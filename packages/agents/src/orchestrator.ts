import type {
  AgentEvent, ApprovalRequest, ChangeEvent, Counters, RunSummary, SafetyConfig, StageId, StageState, TriggerKind,
} from '@sentinel/shared';
import { nowId, STAGE_META, STAGE_ORDER } from '@sentinel/shared';
import type { AgentContext } from './agent.js';
import { approvalForTest, createApproval } from './approvals.js';
import { DISCOVERY_TECHNIQUES, SAFETY_CONFIG, TARGET_BASE_URL } from './config.js';
import { LLM } from './llm.js';
import { SafeHttpClient, SafetyLayer } from './safety.js';
import { Store } from './store.js';
import { ReconAgent } from './agents/recon.js';
import { InventoryAgent } from './agents/inventory.js';
import { PlannerAgent } from './agents/planner.js';
import { executeAll, type Candidate } from './agents/executors.js';
import { VerifierAgent } from './agents/verifier.js';
import { TriageAgent } from './agents/triage.js';
import { ReporterAgent, sendTicket } from './agents/reporter.js';
import { deployFix, RetestAgent } from './agents/retest.js';
import { runOptionalWrappers } from './agents/wrappers.js';

const TRIGGER_ENDPOINTS: Record<TriggerKind, { title: string; detail: string; endpoints: string[] }> = {
  deploy: {
    title: 'CI/CD deploy webhook',
    detail: 'Staging deploy finished; changed booking, payment and search handlers queued for retest.',
    endpoints: ['/api/search', '/api/hold', '/api/book', '/api/pay', '/api/cancel', '/api/bookings/:id', '/api/invoices/:id'],
  },
  'bundle-diff': {
    title: 'New front-end JS bundle diff',
    detail: 'Bundle hash changed; 2 new API routes extracted from route manifest.',
    endpoints: ['/api/book', '/api/pay'],
  },
  subdomain: {
    title: 'New staging subdomain observed',
    detail: 'CT log emitted a certificate for a staging host; hidden-path probe queued.',
    endpoints: ['/internal/debug'],
  },
  'traffic-anomaly': {
    title: 'Gateway traffic-log anomaly',
    detail: 'Unusual request volume on a legacy path with no recent inventory hits.',
    endpoints: ['/v1/bookings'],
  },
};

function initialStages(): StageState[] {
  return STAGE_ORDER.map((id) => ({ id, ...STAGE_META[id], status: 'idle', detail: '' }));
}

export class Orchestrator {
  readonly store: Store;
  readonly safety: SafetyLayer;
  readonly http: SafeHttpClient;
  readonly llm: LLM;
  readonly target = TARGET_BASE_URL;
  private listeners = new Set<(event: AgentEvent) => void>();
  private stages = initialStages();
  private approvalMap = new Map<string, string>();
  private currentRunId = 'idle';
  private deployAt: number | null = null;
  running = false;

  constructor(store?: Store) {
    this.store = store ?? new Store();
    this.safety = new SafetyLayer(this.store.getSetting<SafetyConfig>('safetyConfig', SAFETY_CONFIG));
    this.http = new SafeHttpClient({ safety: this.safety, timeoutMs: 6000 });
    this.llm = new LLM();
    this.safety.onAudit((r) => this.store.appendAudit(r));
    this.safety.onHealth((h) => this.store.addHealth(h));
    this.safety.isApproved((id) => this.store.getApprovalStatus(id) === 'approved');
    this.deployAt = this.store.getSetting<number | null>('deployAt', null);
  }

  onEvent(fn: (event: AgentEvent) => void): () => void {
    this.listeners.add(fn);
    return () => this.listeners.delete(fn);
  }

  emit(stage: StageId | 'system', level: AgentEvent['level'], message: string, data?: Record<string, unknown>): AgentEvent {
    const event: AgentEvent = { id: nowId('evt'), at: Date.now(), runId: this.currentRunId, stage, level, message, data };
    this.store.addEvent(event);
    this.listeners.forEach((fn) => fn(event));
    return event;
  }

  private context(mode: 'full' | 'demo', autoApprove: boolean): AgentContext {
    return {
      store: this.store,
      safety: this.safety,
      http: this.http,
      llm: this.llm,
      target: this.target,
      runId: this.currentRunId,
      mode,
      autoApprove,
      approvalFor: (key) => {
        const id = this.approvalMap.get(key);
        return id && this.store.getApprovalStatus(id) === 'approved' ? id : undefined;
      },
      emit: (stage, level, message, data) => this.emit(stage, level, message, data),
    };
  }

  private stage(id: StageId, status: StageState['status'], detail: string, count?: number) {
    const existing = this.stages.find((s) => s.id === id);
    if (!existing) return;
    existing.status = status;
    existing.detail = detail;
    existing.count = count;
    existing.startedAt = status === 'running' ? Date.now() : existing.startedAt;
    existing.finishedAt = status === 'done' || status === 'error' ? Date.now() : undefined;
    this.emit(id, status === 'error' ? 'error' : status === 'done' ? 'success' : 'info', `${STAGE_META[id].label}: ${detail}`);
  }

  async fireTrigger(kind: TriggerKind, source = 'operator-console'): Promise<ChangeEvent> {
    const meta = TRIGGER_ENDPOINTS[kind];
    const change: ChangeEvent = {
      id: nowId('chg'), kind, title: meta.title, detail: meta.detail, source,
      createdAt: Date.now(), endpoints: meta.endpoints, status: 'queued',
    };
    this.store.addChange(change);
    this.emit('detect', 'success', `Change detected: ${change.title}`, { changeId: change.id, endpoints: change.endpoints });
    return change;
  }

  async deployV21(): Promise<ChangeEvent> {
    const res = await this.http.send({
      method: 'POST',
      url: `${this.target}/__admin/deploy`,
      headers: { 'x-sentinel-synthetic': 'true' },
      body: '{}',
      runId: this.currentRunId,
    });
    this.emit('detect', res.blocked ? 'error' : 'warn', res.blocked ? `Deploy command blocked: ${res.blockReason}` : 'Deploy v2.1 shipped to staging mock', { status: res.status });
    this.deployAt = Date.now();
    this.store.setSetting('deployAt', this.deployAt);
    return this.fireTrigger('deploy', 'ci-cd-pipeline:v2.1');
  }

  async runLoop(options: { mode?: 'full' | 'demo'; autoApprove?: boolean; change?: ChangeEvent; focusPaths?: string[] } = {}): Promise<RunSummary> {
    if (this.running) throw new Error('A security run is already in progress');
    this.running = true;
    const mode = options.mode ?? 'full';
    const autoApprove = options.autoApprove ?? mode === 'demo';
    this.currentRunId = nowId('run');
    this.approvalMap.clear();
    this.stages = initialStages();
    const run: RunSummary = { runId: this.currentRunId, startedAt: Date.now(), mode, changeId: options.change?.id, stages: this.stages };
    this.store.createRun(run);
    this.store.setSetting('lastRunId', this.currentRunId);
    const ctx = this.context(mode, autoApprove);
    this.emit('system', 'info', `SentinelTBO run started (${mode} mode, target ${this.target})`, { runId: this.currentRunId });

    try {
      if (!options.change) await this.fireTrigger('deploy', 'operator-console');
      const changes = options.change ? [options.change] : this.store.listChanges().filter((c) => c.status !== 'tested');
      changes.forEach((c) => this.store.updateChangeStatus(c.id, 'testing'));
      this.stage('detect', 'done', `${changes.length} change event(s) queued`, changes.length);

      this.stage('recon', 'running', 'discovering endpoints via bundle, HAR and probes');
      const endpoints = await new ReconAgent().run({ changes, focusPaths: options.focusPaths }, ctx);
      this.stage('recon', 'done', `${endpoints.length} endpoints discovered`, endpoints.length);

      this.stage('inventory', 'running', 'classifying active / zombie / shadow');
      const inventoried = await new InventoryAgent().run(endpoints, ctx);
      this.stage('inventory', 'done', 'knowledge graph + OpenAPI map updated', inventoried.length);

      this.stage('plan', 'running', 'selecting targeted tests');
      const tests = await new PlannerAgent().run(inventoried, ctx);
      tests.filter((t) => t.needsApproval).forEach((test) => {
        const approval = approvalForTest(test, ctx);
        if (approval) this.approvalMap.set(test.executor, approval.id);
      });
      this.stage('plan', 'done', `${tests.length} tests planned, ${this.approvalMap.size} gated by approval`, tests.length);

      this.stage('execute', 'running', 'safety-layer enforced specialist execution');
      const wrapped = await runOptionalWrappers(ctx);
      const candidates: Candidate[] = await executeAll(tests, ctx);
      const blocked = this.store.listAudit({ blockedOnly: true, limit: 1000 }).filter((a) => a.runId === this.currentRunId).length;
      this.stage('execute', 'done', `${candidates.length} signal(s) from ${tests.length} tests; ${blocked} blocked request(s) logged`, candidates.length);

      this.stage('verify', 'running', 'minimal proof replay 2× against control');
      const verified = await new VerifierAgent().run(candidates, ctx);
      const elapsed = this.deployAt ? Date.now() - this.deployAt : null;
      if (elapsed !== null) this.store.setSetting('deployToVerifiedMs', elapsed);
      this.stage('verify', 'done', `${verified.verified.length} verified, ${verified.dropped.length} dropped`, verified.verified.length);

      this.stage('triage', 'running', 'dedupe, severity scoring, owner mapping');
      const findings = await new TriageAgent().run(verified, ctx);
      findings.forEach((f) => {
        const approval = this.store.listApprovals().find((a) => a.kind === 'finding' && a.refId === f.id);
        if (approval) this.approvalMap.set(f.id, approval.id);
      });
      this.stage('triage', 'done', `${findings.length} finding(s) scored and assigned`, findings.length);

      this.stage('report', 'running', 'drafting Jira-style tickets');
      const tickets = await new ReporterAgent().run(findings, ctx);
      this.stage('report', 'done', `${tickets.length} ticket(s) drafted`, tickets.length);

      changes.forEach((c) => this.store.updateChangeStatus(c.id, 'tested'));
      this.stage('retest', 'done', 'awaiting fix deployment to replay stored proof');
      run.finishedAt = Date.now();
      this.store.finishRun(this.currentRunId, this.stages);
      this.emit('system', 'success', `Run complete: ${findings.length} finding(s), ${verified.dropped.length} false positive(s) dropped in ${Math.round((run.finishedAt - run.startedAt) / 1000)}s`, {
        runId: this.currentRunId, wrappers: wrapped.length,
      });
      return run;
    } catch (error) {
      this.stage('execute', 'error', `Run failed: ${String(error)}`);
      run.finishedAt = Date.now();
      this.store.finishRun(this.currentRunId, this.stages);
      this.emit('system', 'error', `Run failed: ${String(error)}`);
      throw error;
    } finally {
      this.running = false;
    }
  }

  async runDemo(): Promise<RunSummary> {
    await this.reset();
    const change = await this.deployV21();
    return this.runLoop({ mode: 'demo', autoApprove: true, change });
  }

  async reset(): Promise<void> {
    this.store.resetRunData();
    this.stages = initialStages();
    this.approvalMap.clear();
    this.deployAt = null;
    this.emit('system', 'info', 'Workspace reset: mock platform and findings restored to baseline');
    await this.http.send({
      method: 'POST', url: `${this.target}/__admin/reset`,
      headers: { 'x-sentinel-synthetic': 'true' }, runId: 'reset',
    }).catch(() => {});
  }

  approve(id: string, decision: ApprovalRequest['status'], modifiedPlan?: Record<string, unknown>): ApprovalRequest | null {
    const approval = this.store.listApprovals().find((a) => a.id === id);
    if (!approval || !['approved', 'rejected', 'modified'].includes(decision)) return null;
    const status = decision === 'modified' ? 'modified' : decision;
    this.store.updateApproval(id, status, modifiedPlan as never);
    this.emit('system', status === 'approved' ? 'success' : 'warn', `Approval ${id}: ${status}`, { id, status });
    return { ...approval, status };
  }

  async retest(findingId: string, deployFixFirst = true): Promise<ReturnType<RetestAgent['run']> | null> {
    const ctx = this.context('full', false);
    const finding = this.store.getFinding(findingId);
    if (!finding) return null;
    if (deployFixFirst) await deployFix(ctx, findingId);
    return new RetestAgent().run(finding, ctx);
  }

  setSafety(patch: Partial<SafetyConfig>) {
    this.safety.setConfig(patch);
    this.store.setSetting('safetyConfig', this.safety.config);
    this.emit('system', 'warn', `Safety configuration updated: ${Object.keys(patch).join(', ')}`, patch as Record<string, unknown>);
  }

  setWebhook(url: string) {
    this.store.setSetting('webhookConfig', { url });
    this.emit('system', 'info', 'Ticket webhook configuration saved (must still pass allowlist)', { url });
  }

  async sendTicket(ticketId: string, destination: 'mock-jira' | 'mock-teams' | 'webhook') {
    return sendTicket(this.context('full', false), ticketId, destination);
  }

  getState(window: 30 | 90 = 30) {
    const counters = this.store.counters();
    const deployToVerifiedMs = this.store.getSetting<number | null>('deployToVerifiedMs', null);
    return {
      target: this.target,
      mode: this.llm.provider === 'mock' ? 'offline-deterministic' : 'llm-backed',
      llm: { provider: this.llm.provider, model: this.llm.model },
      running: this.running,
      stages: this.stages,
      counters: { ...counters, deployToVerifiedMs } as Counters,
      events: this.store.listEvents(200),
      changes: this.store.listChanges(),
      endpoints: this.store.listEndpoints(window),
      graph: this.store.getGraph(),
      tests: this.store.listPlannedTests(),
      findings: this.store.listFindings(),
      approvals: this.store.listApprovals(),
      tickets: this.store.listTickets(),
      audit: this.store.listAudit({ limit: 400 }),
      health: this.store.listHealth(80),
      runs: this.store.listRuns(),
      safety: this.safety.config,
      healthNow: this.safety.getHealth(new URL(this.target).host),
      techniques: DISCOVERY_TECHNIQUES,
      webhookConfig: this.store.getSetting<{ url?: string }>('webhookConfig', {}),
    };
  }
}

export type SentinelState = ReturnType<Orchestrator['getState']>;
