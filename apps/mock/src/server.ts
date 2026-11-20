import Fastify from 'fastify';

const app = Fastify({ logger: false, bodyLimit: 256 * 1024 });
const HOST = '127.0.0.1';
const PORT = Number(process.env.MOCK_PORT ?? 4000);

type Role = 'agent' | 'sub-agent' | 'admin';
type Agency = 'A' | 'B';
interface Identity { agency: Agency; role: Role; token: string }
interface Hold { id: string; agency: Agency; fare: number; route: string; pnr: string; cancelled: boolean }
interface Booking { id: string; agency: Agency; holdId: string; fare: number; status: string; pnr: string; passenger: string }
interface Traffic { path: string; method: string; at: number; role: string }

const identities: Identity[] = [
  { agency: 'A', role: 'agent', token: 'test-agent-a' },
  { agency: 'A', role: 'sub-agent', token: 'test-subagent-a' },
  { agency: 'A', role: 'admin', token: 'test-admin-a' },
  { agency: 'B', role: 'agent', token: 'test-agent-b' },
  { agency: 'B', role: 'sub-agent', token: 'test-subagent-b' },
  { agency: 'B', role: 'admin', token: 'test-admin-b' },
];

const holds: Hold[] = [
  { id: 'HOLD-A-1001', agency: 'A', fare: 420, route: 'DEL-BOM', pnr: 'PNRA1001', cancelled: false },
  { id: 'HOLD-B-2001', agency: 'B', fare: 690, route: 'BLR-GOI', pnr: 'PNRB2001', cancelled: false },
];
const bookings: Booking[] = [
  { id: 'BK-A-1001', agency: 'A', holdId: 'HOLD-A-1001', fare: 420, status: 'CONFIRMED', pnr: 'PNRA1001', passenger: 'Synthetic Passenger A' },
  { id: 'BK-B-2001', agency: 'B', holdId: 'HOLD-B-2001', fare: 690, status: 'CONFIRMED', pnr: 'PNRB2001', passenger: 'Synthetic Passenger B' },
];
const refunds = new Map<string, number>();
const couponsUsed = new Map<string, number>();
const patched = new Set<string>();
let v2Deployed = false;
let deployVersion = 'v2.0';
const traffic: Traffic[] = [];
let injectionProbeHits = 0;
const day = 86_400_000;

const seededPaths = [
  ['POST', '/api/search'], ['POST', '/api/hold'], ['POST', '/api/book'], ['POST', '/api/pay'],
  ['POST', '/api/cancel'], ['GET', '/api/bookings/mine'], ['GET', '/api/invoices/BK-A-1001'],
];
for (let d = 0; d < 90; d++) {
  for (const [method, path] of seededPaths) {
    const hits = d < 30 ? (path === '/api/search' ? 7 : 1 + (d % 3)) : 1 + (d % 2);
    for (let i = 0; i < hits; i++) traffic.push({ method, path, at: Date.now() - d * day - i * 60_000, role: 'agent' });
  }
}

function identity(req: { headers: Record<string, unknown> }): Identity | undefined {
  const raw = String(req.headers.authorization ?? '').replace(/^Bearer\s+/i, '');
  return identities.find((i) => i.token === raw);
}

function requireAuth(req: { headers: Record<string, unknown> }, reply: { code: (n: number) => { send: (b: unknown) => unknown } }): Identity | undefined {
  const id = identity(req);
  if (!id) { reply.code(401).send({ error: 'Synthetic test credential required' }); return undefined; }
  return id;
}

function body(req: unknown): Record<string, any> {
  return (req && typeof req === 'object' && 'body' in req ? (req as { body: unknown }).body : {}) as Record<string, any> ?? {};
}

app.addHook('onResponse', async (req) => {
  if (req.url.startsWith('/__admin') || req.url.startsWith('/health')) return;
  if (String(req.headers['x-sentinel-synthetic'] ?? '').toLowerCase() === 'true') return;
  traffic.push({ path: req.url.split('?')[0], method: req.method, at: Date.now(), role: identity(req)?.role ?? 'anonymous' });
  if (traffic.length > 20000) traffic.splice(0, 5000);
});

app.get('/health', async () => ({ ok: true, service: 'mock-travel-platform', version: deployVersion, syntheticOnly: true }));

app.post('/api/search', async (req, rep) => {
  if (!requireAuth(req as never, rep as never)) return;
  const b = body(req);
  if (/or\s+1\s*=\s*1/i.test(String(b.origin ?? '')) && injectionProbeHits++ === 0) {
    return rep.code(500).send({ error: 'SQL syntax artifact in staging query log (flaky fixture)' });
  }
  return {
    results: [
      { flightId: 'F-101', route: `${b.origin ?? 'DEL'}-${b.destination ?? 'BOM'}`, fare: 420, currency: 'INR', serverControlled: true },
      { flightId: 'F-102', route: `${b.origin ?? 'DEL'}-${b.destination ?? 'BOM'}`, fare: 690, currency: 'INR', serverControlled: true },
    ],
    flow: 'search',
  };
});

app.post('/api/hold', async (req, rep) => {
  const id = requireAuth(req as never, rep as never); if (!id) return;
  const b = body(req);
  const hold = holds.find((h) => h.agency === id.agency && h.route.includes(String(b.destination ?? '').slice(0, 3))) ?? holds.find((h) => h.agency === id.agency)!;
  return { holdId: hold.id, fare: hold.fare, pnr: hold.pnr, expiresIn: 600, flow: 'hold' };
});

app.post('/api/book', async (req, rep) => {
  const id = requireAuth(req as never, rep as never); if (!id) return;
  const b = body(req);
  const hold = holds.find((h) => h.id === b.holdId) ?? holds.find((h) => h.agency === id.agency)!;
  const escalated = !patched.has('mass-assignment') && String(b.role ?? '').toLowerCase() === 'admin' && id.role !== 'admin';
  const effectiveRole = escalated ? 'admin' : id.role;
  const tampered = !patched.has('fare-tamper') && b.fare !== undefined && Number(b.fare) !== hold.fare;
  const fareCharged = tampered ? Number(b.fare) : hold.fare;
  let refundIssued = false;
  let doubleRefund = false;
  if (hold.cancelled) {
    const count = (refunds.get(hold.id) ?? 1) + 1;
    refunds.set(hold.id, count);
    refundIssued = true;
    doubleRefund = !patched.has('double-refund') && count >= 2;
  }
  const booking: Booking = {
    id: `BK-${id.agency}-${Date.now().toString(36).toUpperCase()}`, agency: id.agency, holdId: hold.id,
    fare: fareCharged, status: 'CONFIRMED', pnr: hold.pnr, passenger: `Synthetic Passenger ${id.agency}`,
  };
  bookings.push(booking);
  return {
    bookingId: booking.id, flow: 'book', fareCharged, serverFare: hold.fare,
    priceTampered: tampered, effectiveRole, privilegeEscalated: escalated,
    refundIssued, doubleRefund, refundCount: refunds.get(hold.id) ?? 0,
  };
});

app.get('/api/bookings/mine', async (req, rep) => {
  const id = requireAuth(req as never, rep as never); if (!id) return;
  return { bookings: bookings.filter((b) => b.agency === id.agency).slice(0, 5), agency: id.agency, control: true };
});

app.get<{ Params: { id: string } }>('/api/bookings/:id', async (req, rep) => {
  const id = requireAuth(req as never, rep as never); if (!id) return;
  const found = bookings.find((b) => b.id === req.params.id);
  if (!found) return rep.code(404).send({ error: 'booking not found' });
  const crossAgency = found.agency !== id.agency;
  if (crossAgency && patched.has('bola')) return rep.code(403).send({ error: 'Cross-agency access denied (policy enforced)' });
  return {
    ...found,
    crossAgency,
    agencyMatch: !crossAgency,
    authorizationBypassed: crossAgency && !patched.has('bola'),
  };
});

app.post('/api/pay', async (req, rep) => {
  const id = requireAuth(req as never, rep as never); if (!id) return;
  const b = body(req);
  let couponReused = false;
  if (b.coupon) {
    const key = `${id.agency}:${b.coupon}`;
    const used = (couponsUsed.get(key) ?? 0) + 1;
    couponsUsed.set(key, used);
    couponReused = !patched.has('coupon-reuse') && used > 1;
  }
  return { paid: true, amount: Number(b.amount ?? 420), couponReused, discountCount: couponsUsed.get(`${id.agency}:${b.coupon}`) ?? 0, flow: 'pay' };
});

app.post('/api/cancel', async (req, rep) => {
  const id = requireAuth(req as never, rep as never); if (!id) return;
  const b = body(req);
  const hold = holds.find((h) => h.id === b.holdId) ?? holds[0];
  hold.cancelled = true;
  const count = (refunds.get(hold.id) ?? 0) + 1;
  refunds.set(hold.id, count);
  return { cancelled: true, refundIssued: true, refundCount: count, holdId: hold.id, flow: 'cancel' };
});

app.get<{ Params: { id: string } }>('/api/invoices/:id', async (req, rep) => {
  const id = requireAuth(req as never, rep as never); if (!id) return;
  const booking = bookings.find((b) => b.id === req.params.id);
  if (!booking) return rep.code(404).send({ error: 'invoice not found' });
  return { invoiceId: `INV-${booking.id}`, amount: booking.fare, pnr: booking.pnr, agency: booking.agency };
});

app.post('/api/supplier/webhook', async (req, rep) => {
  const id = requireAuth(req as never, rep as never); if (!id) return;
  const target = String(body(req).url ?? '');
  let parsed: URL;
  try { parsed = new URL(target); } catch { return rep.code(400).send({ error: 'invalid url' }); }
  const safeHost = [`127.0.0.1:${PORT}`, `localhost:${PORT}`].includes(parsed.host);
  if (!safeHost || !/^\/(internal|v1)\//.test(parsed.pathname)) {
    return rep.code(400).send({ error: 'Only internal staging URLs are resolved by this demo adapter' });
  }
  if (patched.has('ssrf')) return rep.code(403).send({ error: 'Supplier URL allowlist enforced' });
  let snippet = '';
  try {
    const response = await fetch(target, { headers: { 'x-sentinel-synthetic': 'true', authorization: `Bearer ${id.token}` } });
    snippet = (await response.text()).slice(0, 240);
  } catch { snippet = 'unreachable'; }
  return { fetched: true, target: parsed.pathname, ssrfConfirmed: true, snippet };
});

app.get('/v1/bookings', async (_req, rep) => {
  if (patched.has('zombie')) return rep.code(404).send({ error: 'legacy API decommissioned' });
  return { legacy: true, bookings: bookings.slice(0, 3), exposedAgencies: ['A', 'B'] };
});

app.get('/internal/debug', async (_req, rep) => {
  if (patched.has('shadow')) return rep.code(404).send({ error: 'not found' });
  return {
    passport: 'A1234567', pnr: 'PNRA1001', email: 'synthetic.passenger@travel.test',
    env: 'staging', debug: true, agencies: ['A', 'B'],
  };
});

app.get<{ Querystring: { count?: string } }>('/api/v2/coupons/stack', async (req, rep) => {
  if (!v2Deployed) return rep.code(404).send({ error: 'endpoint not deployed' });
  const count = Number(req.query.count ?? 3);
  const unauthenticated = true;
  return {
    stacked: count, totalDiscount: count * 500, negativeTotal: !patched.has('coupon-stack'),
    unauthenticated, newInVersion: 'v2.1',
  };
});

app.post('/__admin/deploy', async () => {
  v2Deployed = true;
  deployVersion = 'v2.1';
  return { deployed: 'v2.1', version: deployVersion, newRoute: 'GET /api/v2/coupons/stack', note: 'New unauthenticated coupon stacking endpoint' };
});

app.post<{ Body: { keys?: string[] } }>('/__admin/patch', async (req) => {
  (req.body?.keys ?? []).forEach((k) => patched.add(k));
  return { patched: [...patched] };
});
app.post('/__admin/reset', async () => {
  patched.clear();
  v2Deployed = false;
  deployVersion = 'v2.0';
  refunds.clear(); couponsUsed.clear();
  injectionProbeHits = 0;
  holds.forEach((h) => { h.cancelled = false; });
  return { ok: true };
});
app.get('/__admin/state', async () => ({
  version: deployVersion, v2Deployed, patched: [...patched], holds, bookings: bookings.slice(-10),
  refunds: Object.fromEntries(refunds), coupons: Object.fromEntries(couponsUsed),
}));
app.get<{ Querystring: { window?: string } }>('/__admin/traffic', async (req) => {
  const days = Number(req.query.window ?? 30);
  const since = Date.now() - days * day;
  return traffic.filter((t) => t.at >= since).map(({ path, method, at, role }) => ({ path, method, at, role }));
});
app.get('/__admin/bundle', async (_req, rep) => {
  rep.header('content-type', 'application/javascript');
  return `
    const ROUTES = ["/api/search","/api/hold","/api/book","/api/pay","/api/cancel","/api/bookings/mine","/api/invoices/:id","/api/supplier/webhook"];
    ${v2Deployed ? 'ROUTES.push("/api/v2/coupons/stack");' : ''}
    export { ROUTES };
  `;
});

await app.listen({ host: HOST, port: PORT });
console.log(`[sentinel:mock] synthetic travel platform on http://${HOST}:${PORT} (staging only, no real systems)`);
