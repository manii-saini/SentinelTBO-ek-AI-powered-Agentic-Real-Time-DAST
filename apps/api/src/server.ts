import Fastify from 'fastify';
import cors from '@fastify/cors';
import { generateOpenAPI, Orchestrator } from '@sentinel/agents';
import type { TriggerKind } from '@sentinel/shared';

const app = Fastify({ logger: false, bodyLimit: 1024 * 1024 });
await app.register(cors, { origin: true });

const orchestrator = new Orchestrator();
const listeners = new Set<() => void>();

app.get('/api/health', async () => ({ ok: true, service: 'sentinel-api', target: orchestrator.target, running: orchestrator.running }));

app.get('/api/state', async (req) => {
  const query = req.query as { window?: string };
  return orchestrator.getState(query.window === '90' ? 90 : 30);
});

app.get('/api/events/stream', async (_req, reply) => {
  reply.raw.writeHead(200, {
    'content-type': 'text/event-stream',
    'cache-control': 'no-cache, no-transform',
    connection: 'keep-alive',
    'access-control-allow-origin': '*',
  });
  reply.raw.write(`event: hello\ndata: ${JSON.stringify({ at: Date.now(), target: orchestrator.target })}\n\n`);
  const off = orchestrator.onEvent((event) => {
    reply.raw.write(`event: agent\ndata: ${JSON.stringify(event)}\n\n`);
  });
  const heartbeat = setInterval(() => reply.raw.write(`: keepalive ${Date.now()}\n\n`), 15_000);
  const cleanup = () => { off(); clearInterval(heartbeat); listeners.delete(cleanup); };
  listeners.add(cleanup);
  reply.raw.on('close', cleanup);
  return reply;
});

function body(req: unknown): Record<string, any> {
  return ((req as { body?: unknown })?.body ?? {}) as Record<string, any>;
}

app.post('/api/triggers/deploy', async (req) => {
  if (orchestrator.running) return { error: 'run in progress' };
  const b = body(req);
  const change = await orchestrator.deployV21();
  if (b.startRun !== false) {
    void orchestrator.runLoop({ mode: b.mode === 'demo' ? 'demo' : 'full', autoApprove: b.autoApprove === true, change })
      .catch((error) => orchestrator.emit('system', 'error', String(error)));
  }
  return { change, started: b.startRun !== false };
});

app.post('/api/triggers/fire', async (req) => {
  const b = body(req);
  const kind = (b.kind ?? 'deploy') as TriggerKind;
  return { change: await orchestrator.fireTrigger(kind, b.source ?? 'operator-console') };
});

app.post('/api/run', async (req) => {
  const b = body(req);
  if (orchestrator.running) return { error: 'run in progress' };
  void orchestrator.runLoop({ mode: b.mode === 'demo' ? 'demo' : 'full', autoApprove: b.autoApprove === true })
    .catch((error) => orchestrator.emit('system', 'error', String(error)));
  return { started: true };
});

app.post('/api/demo', async () => {
  if (orchestrator.running) return { error: 'run in progress' };
  void orchestrator.runDemo().catch((error) => orchestrator.emit('system', 'error', String(error)));
  return { started: true, mode: 'demo' };
});

app.post('/api/reset', async () => {
  await orchestrator.reset();
  return { reset: true };
});

app.post<{ Params: { id: string } }>('/api/approvals/:id', async (req) => {
  const b = body(req);
  return { approval: orchestrator.approve(req.params.id, b.decision ?? 'approved', b.modifiedPlan) };
});

app.post<{ Params: { id: string } }>('/api/tickets/:id/send', async (req) => {
  const ticket = await orchestrator.sendTicket(req.params.id, body(req).destination ?? 'mock-jira');
  return { ticket };
});

app.post<{ Params: { id: string } }>('/api/findings/:id/retest', async (req) => {
  const finding = await orchestrator.retest(req.params.id, body(req).deployFix !== false);
  return { finding };
});

app.put('/api/safety', async (req) => {
  const b = body(req);
  const patch: Record<string, unknown> = {};
  if (typeof b.rateLimit === 'number') patch.rateLimit = b.rateLimit;
  if (typeof b.burst === 'number') patch.burst = b.burst;
  if (Array.isArray(b.allowlist)) patch.allowlist = b.allowlist;
  if (typeof b.killSwitch === 'boolean') patch.killSwitch = b.killSwitch;
  orchestrator.setSafety(patch);
  return { safety: orchestrator.safety.config };
});

app.put('/api/webhook', async (req) => {
  orchestrator.setWebhook(String(body(req).url ?? ''));
  return { ok: true };
});

app.post('/api/audit/query', async (req) => {
  const b = body(req);
  return { audit: orchestrator.store.listAudit({ search: b.search, blockedOnly: Boolean(b.blockedOnly), limit: Number(b.limit ?? 400) }) };
});

app.get('/api/export/openapi', async (_req, reply) => {
  reply.header('content-type', 'application/json');
  reply.header('content-disposition', 'attachment; filename="sentinel-inferred-openapi.json"');
  return generateOpenAPI(orchestrator.store.listEndpoints(90));
});

app.get('/api/export/audit', async (_req, reply) => {
  reply.header('content-type', 'application/jsonl');
  reply.header('content-disposition', 'attachment; filename="sentinel-audit.jsonl"');
  return orchestrator.store.listAudit({ limit: 10000 }).map((r) => JSON.stringify(r)).join('\n');
});

const PORT = Number(process.env.API_PORT ?? 3001);
await app.listen({ host: '127.0.0.1', port: PORT });
console.log(`[sentinel:api] control plane on http://127.0.0.1:${PORT} — SSE at /api/events/stream`);

for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.on(signal, () => {
    listeners.forEach((cleanup) => cleanup());
    void app.close();
    process.exit(0);
  });
}
