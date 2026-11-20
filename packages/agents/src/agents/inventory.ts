import type { ChangeEvent, Endpoint, KnowledgeEdge, KnowledgeNode } from '@sentinel/shared';
import type { Agent, AgentContext } from '../agent.js';
import { DISCOVERY_TECHNIQUES, ownerForPath } from '../config.js';

interface TrafficRow { path: string; method: string; at: number }

export function parseTrafficLogs(raw: string): TrafficRow[] {
  const trimmed = raw.trim();
  if (trimmed.startsWith('[') || trimmed.startsWith('{')) {
    const json = JSON.parse(trimmed) as TrafficRow[] | { logs?: TrafficRow[] };
    return Array.isArray(json) ? json : (json.logs ?? []);
  }
  const [header, ...lines] = trimmed.split(/\r?\n/);
  const cols = header.split(',').map((c) => c.trim().toLowerCase());
  return lines.map((line) => {
    const cells = line.split(',');
    const get = (name: string) => cells[cols.indexOf(name)] ?? '';
    return { path: get('path'), method: get('method') || 'GET', at: Number(get('at') || get('timestamp') || 0) };
  }).filter((r) => r.path);
}

export class InventoryAgent implements Agent<Endpoint[], Endpoint[]> {
  readonly id = 'inventory';
  readonly name = 'InventoryAgent';

  async run(endpoints: Endpoint[], ctx: AgentContext): Promise<Endpoint[]> {
    ctx.emit('inventory', 'info', 'Comparing inferred map with 30/90-day gateway traffic', { techniques: DISCOVERY_TECHNIQUES.map((t) => t.name) });
    const now = Date.now();
    const windows: Record<'30' | '90', TrafficRow[]> = { '30': [], '90': [] };
    for (const window of ['30', '90'] as const) {
      try {
        const res = await ctx.http.send({ method: 'GET', url: `${ctx.target}/__admin/traffic?window=${window}`, headers: { 'x-sentinel-synthetic': 'true' }, runId: ctx.runId });
        windows[window] = parseTrafficLogs(res.body);
      } catch {
        windows[window] = [];
      }
    }

    const enriched = endpoints.map((endpoint) => {
      const count = (rows: TrafficRow[]) => rows.filter((r) => r.path === endpoint.path || (endpoint.path.includes(':id') && r.path.startsWith(endpoint.path.split(':id')[0]))).length;
      const hits30d = count(windows['30']);
      const hits90d = count(windows['90']);
      const lastRealTraffic = windows['90'].filter((r) => r.path === endpoint.path).map((r) => r.at).sort((a, b) => b - a)[0] ?? null;
      const undocumented = /^\/(internal|debug|test|beta)(\/|$)/.test(endpoint.path);
      const legacy = /^\/(v1|old|legacy)(\/|$)/.test(endpoint.path);
      const status: Endpoint['status'] = undocumented ? 'shadow' : hits90d === 0 ? 'zombie' : 'active';
      const owner = ownerForPath(endpoint.path);
      const hasKnownIssue = ['/api/bookings/:id', '/api/book', '/api/pay', '/api/cancel', '/api/supplier/webhook', '/internal/debug', '/v1/bookings', '/api/v2/coupons/stack'].includes(endpoint.path);
      const recommendation: Endpoint['recommendation'] = status === 'zombie' ? 'decommission' : status === 'shadow' ? 'restrict' : hasKnownIssue ? 'update' : 'monitor';
      return {
        ...endpoint,
        hits30d,
        hits90d,
        windowHits: hits30d,
        lastRealTraffic,
        status,
        owner: owner.owner,
        vulnerableToVersion: endpoint.path === '/api/v2/coupons/stack' ? 'v2.1 (new)' : hasKnownIssue ? 'v2.0 (known issues)' : null,
        recommendation,
      };
    });

    enriched.forEach((e) => ctx.store.upsertEndpoint(e));

    const nodes: KnowledgeNode[] = [];
    const edges: KnowledgeEdge[] = [];
    const flows = ['search', 'hold', 'book', 'pay', 'cancel'];
    flows.forEach((flow) => nodes.push({ id: `flow:${flow}`, kind: 'flow', label: flow, data: { type: 'business-flow' } }));
    flows.slice(0, -1).forEach((flow, i) => edges.push({ id: `edge:flow:${flow}:${flows[i + 1]}`, source: `flow:${flow}`, target: `flow:${flows[i + 1]}`, label: 'next' }));

    for (const endpoint of enriched) {
      nodes.push({ id: endpoint.id, kind: 'endpoint', label: `${endpoint.method} ${endpoint.path}`, data: { status: endpoint.status, owner: endpoint.owner, hits30d: endpoint.hits30d, hits90d: endpoint.hits90d, source: endpoint.source } });
      const flowKey = `flow:${endpoint.flow}`;
      if (flows.includes(endpoint.flow)) edges.push({ id: `edge:${endpoint.id}:${flowKey}`, source: endpoint.id, target: flowKey, label: 'part of' });
      endpoint.roles.forEach((role) => {
        const id = `role:${role}`;
        if (!nodes.find((n) => n.id === id)) nodes.push({ id, kind: 'role', label: role, data: { type: 'test-account role' } });
        edges.push({ id: `edge:${endpoint.id}:${id}`, source: endpoint.id, target: id, label: 'allows' });
      });
      endpoint.params.forEach((param) => {
        const id = `param:${endpoint.path}:${param.name}`;
        nodes.push({ id, kind: 'param', label: param.name, data: { location: param.location, type: param.type, controllable: Boolean(param.controllable), sensitive: Boolean(param.sensitive) } });
        edges.push({ id: `edge:${endpoint.id}:${id}`, source: endpoint.id, target: id, label: 'accepts' });
      });
    }
    ctx.store.setGraph(nodes, edges);

    const counts = enriched.reduce<Record<string, number>>((acc, e) => { acc[e.status] = (acc[e.status] ?? 0) + 1; return acc; }, {});
    ctx.emit('inventory', 'success', `Inventory built: ${enriched.length} endpoints (${counts.active ?? 0} active, ${counts.zombie ?? 0} zombie, ${counts.shadow ?? 0} shadow)`, { counts, nodes: nodes.length });
    return enriched;
  }
}
