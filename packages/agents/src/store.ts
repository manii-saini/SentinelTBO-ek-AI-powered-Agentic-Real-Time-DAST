import Database from 'better-sqlite3';
import { mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import type {
  AgentEvent, ApiParam, ApprovalRequest, AuditRecord, ChangeEvent, Endpoint, Finding,
  HealthSample, KnowledgeEdge, KnowledgeNode, PlannedTest, RunSummary, StageState, Ticket,
} from '@sentinel/shared';

function parse<T>(value: string | null | undefined, fallback: T): T {
  if (!value) return fallback;
  try { return JSON.parse(value) as T; } catch { return fallback; }
}

export class Store {
  readonly db: Database.Database;

  constructor(path = process.env.SENTINEL_DB ?? resolve(process.cwd(), 'data/sentinel.db')) {
    mkdirSync(dirname(path), { recursive: true });
    this.db = new Database(path);
    this.db.pragma('journal_mode = WAL');
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS runs (run_id TEXT PRIMARY KEY, started_at INTEGER, finished_at INTEGER, mode TEXT, change_id TEXT, stages TEXT);
      CREATE TABLE IF NOT EXISTS events (id TEXT PRIMARY KEY, at INTEGER, run_id TEXT, stage TEXT, level TEXT, message TEXT, data TEXT);
      CREATE INDEX IF NOT EXISTS idx_events_at ON events(at DESC);
      CREATE TABLE IF NOT EXISTS changes (id TEXT PRIMARY KEY, at INTEGER, kind TEXT, title TEXT, detail TEXT, source TEXT, endpoints TEXT, status TEXT, change_id TEXT);
      CREATE TABLE IF NOT EXISTS endpoints (id TEXT PRIMARY KEY, method TEXT, path TEXT, host TEXT, source TEXT, status TEXT, roles TEXT, params TEXT, auth_required INTEGER, data_exposed TEXT, business_context TEXT, flow TEXT, last_real_traffic INTEGER, hits30d INTEGER, hits90d INTEGER, vulnerable_to_version TEXT, owner TEXT, recommendation TEXT, discovered_at INTEGER);
      CREATE TABLE IF NOT EXISTS graph_nodes (id TEXT PRIMARY KEY, kind TEXT, label TEXT, data TEXT);
      CREATE TABLE IF NOT EXISTS graph_edges (id TEXT PRIMARY KEY, source TEXT, target TEXT, label TEXT);
      CREATE TABLE IF NOT EXISTS planned_tests (id TEXT PRIMARY KEY, endpoint_id TEXT, method TEXT, path TEXT, test_class TEXT, name TEXT, reasoning TEXT, params TEXT, roles TEXT, risk TEXT, needs_approval INTEGER, executor TEXT, status TEXT, run_id TEXT);
      CREATE TABLE IF NOT EXISTS audit (seq INTEGER PRIMARY KEY, id TEXT, at INTEGER, run_id TEXT, method TEXT, url TEXT, host TEXT, role TEXT, agency TEXT, status INTEGER, timing_ms INTEGER, bytes INTEGER, blocked INTEGER, block_reason TEXT, test_id TEXT, finding_id TEXT, body_hash TEXT, prev_hash TEXT, hash TEXT, replay TEXT);
      CREATE INDEX IF NOT EXISTS idx_audit_at ON audit(at DESC);
      CREATE TABLE IF NOT EXISTS findings (id TEXT PRIMARY KEY, key TEXT, title TEXT, endpoint_id TEXT, endpoint TEXT, test_class TEXT, severity TEXT, score INTEGER, score_explanation TEXT, cwe TEXT, owasp TEXT, owner TEXT, status TEXT, created_at INTEGER, evidence TEXT, impact TEXT, fix TEXT, requests_sent INTEGER, root_cause TEXT, retest TEXT, ticket_id TEXT);
      CREATE TABLE IF NOT EXISTS approvals (id TEXT PRIMARY KEY, kind TEXT, ref_id TEXT, title TEXT, reason TEXT, risk TEXT, created_at INTEGER, status TEXT, modified_plan TEXT);
      CREATE TABLE IF NOT EXISTS tickets (id TEXT PRIMARY KEY, finding_id TEXT, title TEXT, markdown TEXT, created_at INTEGER, destination TEXT, sent INTEGER, sent_at INTEGER);
      CREATE TABLE IF NOT EXISTS health (at INTEGER, host TEXT, latency_ms INTEGER, error_rate REAL, action TEXT);
    `);
  }

  setSetting(key: string, value: unknown) {
    this.db.prepare('INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value').run(key, JSON.stringify(value));
  }
  getSetting<T>(key: string, fallback: T): T {
    const row = this.db.prepare('SELECT value FROM settings WHERE key=?').get(key) as { value: string } | undefined;
    return parse<T>(row?.value, fallback);
  }

  createRun(run: RunSummary) {
    this.db.prepare('INSERT INTO runs(run_id,started_at,mode,change_id,stages) VALUES(?,?,?,?,?)').run(run.runId, run.startedAt, run.mode, run.changeId ?? null, JSON.stringify(run.stages));
  }
  finishRun(runId: string, stages: StageState[]) {
    this.db.prepare('UPDATE runs SET finished_at=?, stages=? WHERE run_id=?').run(Date.now(), JSON.stringify(stages), runId);
  }
  getRun(runId: string): RunSummary | null {
    const r = this.db.prepare('SELECT * FROM runs WHERE run_id=?').get(runId) as Record<string, unknown> | undefined;
    return r ? { runId: r.run_id as string, startedAt: r.started_at as number, finishedAt: (r.finished_at as number) ?? undefined, mode: r.mode as 'full' | 'demo', changeId: (r.change_id as string) ?? undefined, stages: parse(r.stages as string, []) } : null;
  }
  listRuns(): RunSummary[] {
    return (this.db.prepare('SELECT * FROM runs ORDER BY started_at DESC LIMIT 20').all() as Record<string, unknown>[]).map((r) => this.getRun(r.run_id as string)!);
  }

  addEvent(event: AgentEvent) {
    this.db.prepare('INSERT INTO events VALUES(?,?,?,?,?,?,?)').run(event.id, event.at, event.runId, event.stage, event.level, event.message, JSON.stringify(event.data ?? {}));
  }
  listEvents(limit = 200): AgentEvent[] {
    return (this.db.prepare('SELECT * FROM events ORDER BY at DESC, rowid DESC LIMIT ?').all(limit) as Record<string, unknown>[]).map((r) => ({
      id: r.id as string, at: r.at as number, runId: r.run_id as string, stage: r.stage as AgentEvent['stage'],
      level: r.level as AgentEvent['level'], message: r.message as string, data: parse(r.data as string, {}),
    }));
  }

  addChange(change: ChangeEvent) {
    this.db.prepare('INSERT INTO changes VALUES(?,?,?,?,?,?,?,?,?)').run(change.id, change.createdAt, change.kind, change.title, change.detail, change.source, JSON.stringify(change.endpoints), change.status, change.id);
  }
  listChanges(): ChangeEvent[] {
    return (this.db.prepare('SELECT * FROM changes ORDER BY at DESC LIMIT 100').all() as Record<string, unknown>[]).map((r) => ({
      id: r.id as string, kind: r.kind as ChangeEvent['kind'], title: r.title as string, detail: r.detail as string,
      source: r.source as string, createdAt: r.at as number, endpoints: parse(r.endpoints as string, []), status: r.status as ChangeEvent['status'],
    }));
  }
  updateChangeStatus(id: string, status: ChangeEvent['status']) {
    this.db.prepare('UPDATE changes SET status=? WHERE id=?').run(status, id);
  }

  upsertEndpoint(e: Endpoint) {
    this.db.prepare(`INSERT INTO endpoints VALUES(@id,@method,@path,@host,@source,@status,@roles,@params,@auth_required,@data_exposed,@business_context,@flow,@last_real_traffic,@hits30d,@hits90d,@vulnerable_to_version,@owner,@recommendation,@discovered_at)
      ON CONFLICT(id) DO UPDATE SET method=@method,path=@path,status=@status,roles=@roles,params=@params,auth_required=@auth_required,data_exposed=@data_exposed,business_context=@business_context,flow=@flow,last_real_traffic=@last_real_traffic,hits30d=@hits30d,hits90d=@hits90d,vulnerable_to_version=@vulnerable_to_version,owner=@owner,recommendation=@recommendation`)
      .run({
        id: e.id, method: e.method, path: e.path, host: e.host, source: e.source, status: e.status,
        roles: JSON.stringify(e.roles), params: JSON.stringify(e.params), auth_required: e.authRequired ? 1 : 0,
        data_exposed: JSON.stringify(e.dataExposed), business_context: JSON.stringify(e.businessContext), flow: e.flow,
        last_real_traffic: e.lastRealTraffic, hits30d: e.hits30d, hits90d: e.hits90d,
        vulnerable_to_version: e.vulnerableToVersion, owner: e.owner, recommendation: e.recommendation, discovered_at: e.discoveredAt,
      });
  }
  listEndpoints(window: 30 | 90 = 30): Endpoint[] {
    const rows = this.db.prepare('SELECT * FROM endpoints ORDER BY path').all() as Record<string, unknown>[];
    return rows.map((r) => ({
      id: r.id as string, method: r.method as string, path: r.path as string, host: r.host as string,
      source: r.source as Endpoint['source'], status: r.status as Endpoint['status'],
      roles: parse<Endpoint['roles']>(r.roles as string, []), params: parse<ApiParam[]>(r.params as string, []),
      authRequired: Boolean(r.auth_required), dataExposed: parse<string[]>(r.data_exposed as string, []),
      businessContext: parse<string[]>(r.business_context as string, []), flow: r.flow as string,
      lastRealTraffic: (r.last_real_traffic as number) ?? null,
      hits30d: r.hits30d as number,
      hits90d: r.hits90d as number,
      windowHits: window === 30 ? (r.hits30d as number) : (r.hits90d as number),
      vulnerableToVersion: (r.vulnerable_to_version as string) ?? null,
      owner: r.owner as string, recommendation: r.recommendation as Endpoint['recommendation'],
      discoveredAt: r.discovered_at as number,
    }));
  }
  clearDiscovery() {
    this.db.exec('DELETE FROM endpoints; DELETE FROM graph_nodes; DELETE FROM graph_edges; DELETE FROM planned_tests;');
  }

  setGraph(nodes: KnowledgeNode[], edges: KnowledgeEdge[]) {
    const tx = this.db.transaction(() => {
      this.db.exec('DELETE FROM graph_nodes; DELETE FROM graph_edges;');
      const n = this.db.prepare('INSERT INTO graph_nodes VALUES(?,?,?,?)');
      const e = this.db.prepare('INSERT INTO graph_edges VALUES(?,?,?,?)');
      nodes.forEach((node) => n.run(node.id, node.kind, node.label, JSON.stringify(node.data)));
      edges.forEach((edge) => e.run(edge.id, edge.source, edge.target, edge.label));
    });
    tx();
  }
  getGraph(): { nodes: KnowledgeNode[]; edges: KnowledgeEdge[] } {
    return {
      nodes: (this.db.prepare('SELECT * FROM graph_nodes').all() as Record<string, unknown>[]).map((r) => ({ id: r.id as string, kind: r.kind as KnowledgeNode['kind'], label: r.label as string, data: parse(r.data as string, {}) })),
      edges: (this.db.prepare('SELECT * FROM graph_edges').all() as Record<string, unknown>[]).map((r) => ({ id: r.id as string, source: r.source as string, target: r.target as string, label: r.label as string })),
    };
  }

  addPlannedTest(t: PlannedTest, runId?: string) {
    this.db.prepare('INSERT OR REPLACE INTO planned_tests VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)').run(
      t.id, t.endpointId, t.method, t.endpoint, t.testClass, t.name, t.reasoning, JSON.stringify(t.params),
      JSON.stringify(t.roles), t.risk, t.needsApproval ? 1 : 0, t.executor, t.status, runId ?? null,
    );
  }
  listPlannedTests(): PlannedTest[] {
    return (this.db.prepare('SELECT * FROM planned_tests ORDER BY test_class, name').all() as Record<string, unknown>[]).map((r) => ({
      id: r.id as string, endpointId: r.endpoint_id as string, endpoint: r.path as string, method: r.method as string,
      testClass: r.test_class as PlannedTest['testClass'], name: r.name as string, reasoning: r.reasoning as string,
      params: parse(r.params as string, []), roles: parse(r.roles as string, []), risk: r.risk as PlannedTest['risk'],
      needsApproval: Boolean(r.needs_approval), executor: r.executor as string, status: r.status as PlannedTest['status'],
    }));
  }
  updatePlannedTest(id: string, status: PlannedTest['status']) {
    this.db.prepare('UPDATE planned_tests SET status=? WHERE id=?').run(status, id);
  }

  appendAudit(record: AuditRecord) {
    this.db.prepare(`INSERT INTO audit(id,seq,at,run_id,method,url,host,role,agency,status,timing_ms,bytes,blocked,block_reason,test_id,finding_id,body_hash,prev_hash,hash,replay)
      VALUES(@id,@seq,@at,@run_id,@method,@url,@host,@role,@agency,@status,@timing_ms,@bytes,@blocked,@block_reason,@test_id,@finding_id,@body_hash,@prev_hash,@hash,@replay)`)
      .run({
        id: record.id, seq: record.seq, at: record.at, run_id: record.runId, method: record.method, url: record.url,
        host: record.host, role: record.role, agency: record.agency, status: record.status, timing_ms: record.timingMs,
        bytes: record.bytes, blocked: record.blocked ? 1 : 0, block_reason: record.blockReason ?? null,
        test_id: record.testId ?? null, finding_id: record.findingId ?? null, body_hash: record.bodyHash,
        prev_hash: record.prevHash, hash: record.hash, replay: JSON.stringify(record.replay),
      });
  }
  listAudit(opts: { search?: string; blockedOnly?: boolean; limit?: number } = {}): AuditRecord[] {
    const clauses: string[] = [];
    const args: unknown[] = [];
    if (opts.blockedOnly) clauses.push('blocked=1');
    if (opts.search) { clauses.push('(url LIKE ? OR method LIKE ? OR role LIKE ?)'); const q = `%${opts.search}%`; args.push(q, q, q); }
    args.push(opts.limit ?? 300);
    const rows = this.db.prepare(`SELECT * FROM audit ${clauses.length ? 'WHERE ' + clauses.join(' AND ') : ''} ORDER BY seq DESC LIMIT ?`).all(...args) as Record<string, unknown>[];
    return rows.map((r) => ({
      id: r.id as string, seq: r.seq as number, at: r.at as number, runId: r.run_id as string, method: r.method as string,
      url: r.url as string, host: r.host as string, role: r.role as string, agency: r.agency as string,
      status: r.status as number, timingMs: r.timing_ms as number, bytes: r.bytes as number, blocked: Boolean(r.blocked),
      blockReason: (r.block_reason as string) ?? undefined, testId: (r.test_id as string) ?? undefined,
      findingId: (r.finding_id as string) ?? undefined, bodyHash: r.body_hash as string, prevHash: r.prev_hash as string,
      hash: r.hash as string, replay: parse(r.replay as string, { method: 'GET', url: '', headers: {} }),
    }));
  }
  addHealth(sample: HealthSample) {
    this.db.prepare('INSERT INTO health VALUES(?,?,?,?,?)').run(sample.at, sample.host, sample.latencyMs, sample.errorRate, sample.action);
  }
  listHealth(limit = 60): HealthSample[] {
    return (this.db.prepare('SELECT * FROM health ORDER BY at DESC LIMIT ?').all(limit) as Record<string, unknown>[]).map((r) => ({
      at: r.at as number, host: r.host as string, latencyMs: r.latency_ms as number, errorRate: r.error_rate as number, action: r.action as HealthSample['action'],
    })).reverse();
  }

  upsertFinding(f: Finding) {
    this.db.prepare(`INSERT INTO findings VALUES(@id,@key,@title,@endpoint_id,@endpoint,@test_class,@severity,@score,@score_explanation,@cwe,@owasp,@owner,@status,@created_at,@evidence,@impact,@fix,@requests_sent,@root_cause,@retest,@ticket_id)
      ON CONFLICT(id) DO UPDATE SET severity=@severity,score=@score,score_explanation=@score_explanation,status=@status,evidence=@evidence,retest=@retest,ticket_id=@ticket_id,impact=@impact,fix=@fix`)
      .run({
        ...f, test_class: f.testClass, score_explanation: f.scoreExplanation, endpoint_id: f.endpointId, created_at: f.createdAt,
        requests_sent: f.requestsSent, root_cause: f.rootCause, evidence: JSON.stringify(f.evidence),
        retest: f.retest ? JSON.stringify(f.retest) : null, ticket_id: f.ticketId ?? null,
      });
  }
  listFindings(): Finding[] {
    return (this.db.prepare('SELECT * FROM findings ORDER BY score DESC, created_at DESC').all() as Record<string, unknown>[]).map((r) => ({
      id: r.id as string, key: r.key as string, title: r.title as string, endpointId: r.endpoint_id as string,
      endpoint: r.endpoint as string, testClass: r.test_class as Finding['testClass'], severity: r.severity as Finding['severity'],
      score: r.score as number, scoreExplanation: r.score_explanation as string, cwe: r.cwe as string, owasp: r.owasp as string,
      owner: r.owner as string, status: r.status as Finding['status'], createdAt: r.created_at as number,
      evidence: parse(r.evidence as string, []), impact: r.impact as string, fix: r.fix as string,
      requestsSent: r.requests_sent as number, rootCause: r.root_cause as string,
      retest: (r.retest ? parse(r.retest as string, undefined) : undefined) as Retest | undefined,
      ticketId: (r.ticket_id as string) ?? undefined,
    }));
  }
  getFinding(id: string): Finding | null { return this.listFindings().find((f) => f.id === id) ?? null; }
  deleteFindingsForRun(ids: string[]) { ids.forEach((id) => this.db.prepare('DELETE FROM findings WHERE id=?').run(id)); }

  addApproval(a: ApprovalRequest) {
    this.db.prepare('INSERT OR REPLACE INTO approvals VALUES(?,?,?,?,?,?,?,?,?)').run(a.id, a.kind, a.refId, a.title, a.reason, a.risk, a.createdAt, a.status, JSON.stringify(a.modifiedPlan ?? {}));
  }
  listApprovals(): ApprovalRequest[] {
    return (this.db.prepare('SELECT * FROM approvals ORDER BY created_at DESC').all() as Record<string, unknown>[]).map((r) => ({
      id: r.id as string, kind: r.kind as ApprovalRequest['kind'], refId: r.ref_id as string, title: r.title as string,
      reason: r.reason as string, risk: r.risk as ApprovalRequest['risk'], createdAt: r.created_at as number,
      status: r.status as ApprovalRequest['status'], modifiedPlan: parse(r.modified_plan as string, undefined),
    }));
  }
  updateApproval(id: string, status: ApprovalRequest['status'], modifiedPlan?: Partial<PlannedTest>) {
    this.db.prepare('UPDATE approvals SET status=?, modified_plan=? WHERE id=?').run(status, JSON.stringify(modifiedPlan ?? {}), id);
  }
  getApprovalStatus(id: string): ApprovalRequest['status'] | null {
    return (this.db.prepare('SELECT status FROM approvals WHERE id=?').get(id) as { status: ApprovalRequest['status'] } | undefined)?.status ?? null;
  }

  addTicket(t: Ticket) {
    this.db.prepare('INSERT OR REPLACE INTO tickets VALUES(?,?,?,?,?,?,?,?)').run(t.id, t.findingId, t.title, t.markdown, t.createdAt, t.destination, t.sent ? 1 : 0, t.sentAt ?? null);
  }
  listTickets(): Ticket[] {
    return (this.db.prepare('SELECT * FROM tickets ORDER BY created_at DESC').all() as Record<string, unknown>[]).map((r) => ({
      id: r.id as string, findingId: r.finding_id as string, title: r.title as string, markdown: r.markdown as string,
      createdAt: r.created_at as number, destination: r.destination as Ticket['destination'], sent: Boolean(r.sent),
      sentAt: (r.sent_at as number) ?? undefined,
    }));
  }
  updateTicket(id: string, destination: Ticket['destination']) {
    this.db.prepare('UPDATE tickets SET destination=?, sent=1, sent_at=? WHERE id=?').run(destination, Date.now(), id);
  }

  counters(): { endpoints: number; findings: number; confirmed: number; falsePositivesDropped: number; requestsSent: number; blocked: number } {
    const scalar = (sql: string) => (this.db.prepare(sql).get() as { n: number }).n;
    return {
      endpoints: scalar('SELECT COUNT(*) n FROM endpoints'),
      findings: scalar("SELECT COUNT(*) n FROM findings WHERE status NOT IN ('false-positive','closed')"),
      confirmed: scalar("SELECT COUNT(*) n FROM findings WHERE status IN ('open','approved','still-vulnerable')"),
      falsePositivesDropped: scalar("SELECT COUNT(*) n FROM findings WHERE status='false-positive'"),
      requestsSent: scalar('SELECT COUNT(*) n FROM audit WHERE blocked=0'),
      blocked: scalar('SELECT COUNT(*) n FROM audit WHERE blocked=1'),
    };
  }

  resetRunData() {
    this.db.exec(`
      DELETE FROM findings; DELETE FROM approvals; DELETE FROM tickets; DELETE FROM changes;
      DELETE FROM audit; DELETE FROM health; DELETE FROM events; DELETE FROM runs; DELETE FROM planned_tests;
      DELETE FROM endpoints; DELETE FROM graph_nodes; DELETE FROM graph_edges;
      DELETE FROM settings WHERE key IN ('deployToVerifiedMs','lastRunId');
    `);
  }

  close() { this.db.close(); }
}

type Retest = NonNullable<Finding['retest']>;
