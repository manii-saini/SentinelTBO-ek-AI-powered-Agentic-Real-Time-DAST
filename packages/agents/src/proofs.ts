import type { ProofExchange, Role, Agency } from '@sentinel/shared';
import { redact } from '@sentinel/shared';
import type { AgentContext } from './agent.js';

export interface ProofMeta {
  rootCause: string;
  businessContext: string[];
  crossAgency?: boolean;
  authBypass?: boolean;
  unauthenticated?: boolean;
  destructive?: boolean;
  dataExposed?: string[];
  impact: string;
  fix: string;
  requests: number;
}

export interface ProofResult {
  reproduced: boolean;
  evidence: ProofExchange[];
  meta: ProofMeta;
}

export interface ProofSpec {
  key: string;
  label: string;
  endpoint: string;
  method: string;
  run(ctx: AgentContext): Promise<ProofResult>;
}

interface SendOpts {
  role?: Role;
  agency?: Agency;
  body?: unknown;
  approvalKey?: string;
  label?: string;
}

async function send(ctx: AgentContext, method: string, path: string, opts: SendOpts = {}): Promise<{ status: number; json: any; exchange: ProofExchange }> {
  const headers: Record<string, string> = { 'x-sentinel-synthetic': 'true', 'content-type': 'application/json' };
  let roleLabel = 'anonymous';
  if (opts.role) {
    const credentialKey = `${opts.role === 'sub-agent' ? 'subagent' : opts.role}-${(opts.agency ?? 'A').toLowerCase()}`;
    const credential = ctx.safety.config.testCredentials[credentialKey];
    if (credential) {
      headers.authorization = `Bearer ${credential.token}`;
      roleLabel = `${credential.role}@agency-${credential.agency}`;
    }
  }
  const approvalId = opts.approvalKey ? ctx.approvalFor(opts.approvalKey) : undefined;
  if (approvalId) headers['x-sentinel-approval'] = approvalId;
  const url = path.startsWith('http') ? path : `${ctx.target}${path}`;
  const body = opts.body === undefined ? undefined : JSON.stringify(opts.body);
  const res = await ctx.http.send({ method, url, headers, body, role: opts.role, agency: opts.agency, runId: ctx.runId });
  let json: any = {};
  try { json = JSON.parse(res.body); } catch { json = { raw: res.body.slice(0, 200) }; }
  const exchange: ProofExchange = {
    label: opts.label ?? `${method} ${path} (${roleLabel})`,
    request: { method, url, headers: { ...headers, authorization: headers.authorization ? '[MASKED TEST TOKEN]' : '(none)' }, body: body ? redact(body) : undefined },
    response: { status: res.status, body: redact(res.body).slice(0, 900), timingMs: res.timingMs },
  };
  return { status: res.status, json, exchange };
}

function result(reproduced: boolean, evidence: ProofExchange[], meta: ProofMeta): ProofResult {
  return { reproduced, evidence, meta: { ...meta, requests: meta.requests + evidence.length } };
}

const P: ProofSpec[] = [
  {
    key: 'bola', label: 'Booking IDOR across agencies', endpoint: '/api/bookings/:id', method: 'GET',
    async run(ctx) {
      const control = await send(ctx, 'GET', '/api/bookings/mine', { role: 'agent', agency: 'A', label: 'Control: own-agency bookings' });
      const attack = await send(ctx, 'GET', '/api/bookings/BK-B-2001', { role: 'agent', agency: 'A', label: 'Proof: agency A reads agency B booking' });
      const reproduced = attack.json?.authorizationBypassed === true && attack.json?.agency === 'B';
      return result(reproduced, [control.exchange, attack.exchange], {
        rootCause: 'booking-idor', businessContext: ['bookings', 'pii'], crossAgency: true, authBypass: true,
        impact: 'Any agency agent can read another agency’s booking, PNR and passenger details, leaking partner data and violating tenancy isolation.',
        fix: 'Enforce tenant-scoped authorization in the booking repository (WHERE agency_id = caller.agency_id) and return 404 for foreign identifiers.', requests: 0,
      });
    },
  },
  {
    key: 'cross-agency-enum', label: 'Cross-agency booking enumeration', endpoint: '/v1/bookings', method: 'GET',
    async run(ctx) {
      const control = await send(ctx, 'GET', '/api/bookings/mine', { role: 'agent', agency: 'A', label: 'Control: scoped booking list' });
      const attack = await send(ctx, 'GET', '/v1/bookings', { role: 'agent', agency: 'A', label: 'Proof: legacy list spans agencies' });
      const reproduced = Array.isArray(attack.json?.exposedAgencies) && attack.json.exposedAgencies.length > 1;
      return result(reproduced, [control.exchange, attack.exchange], {
        rootCause: 'legacy-cross-tenant-list', businessContext: ['bookings', 'pii'], crossAgency: true,
        impact: 'Legacy list aggregates bookings from both agencies, enabling cross-tenant enumeration.',
        fix: 'Decommission /v1 or apply the same tenant policy and response schema as /api/bookings.', requests: 0,
      });
    },
  },
  {
    key: 'unauth-legacy', label: 'Legacy API missing authentication', endpoint: '/v1/bookings', method: 'GET',
    async run(ctx) {
      const control = await send(ctx, 'GET', '/api/bookings/mine', { label: 'Control: protected endpoint without credentials' });
      const attack = await send(ctx, 'GET', '/v1/bookings', { label: 'Proof: unauthenticated legacy read' });
      const reproduced = attack.status === 200 && Array.isArray(attack.json?.bookings) && control.status === 401;
      return result(reproduced, [control.exchange, attack.exchange], {
        rootCause: 'legacy-missing-auth', businessContext: ['bookings'], unauthenticated: true,
        impact: 'Unauthenticated callers can enumerate legacy booking records.',
        fix: 'Remove legacy route from gateway or require the standard synthetic/staging auth policy.', requests: 0,
      });
    },
  },
  {
    key: 'fare-tamper', label: 'Client-controlled fare on booking', endpoint: '/api/book', method: 'POST',
    async run(ctx) {
      const hold = await send(ctx, 'POST', '/api/hold', { role: 'agent', agency: 'A', body: { destination: 'BOM' }, label: 'Control: server-issued fare' });
      const attack = await send(ctx, 'POST', '/api/book', { role: 'agent', agency: 'A', body: { holdId: hold.json?.holdId, fare: 1 }, approvalKey: 'fare-tamper', label: 'Proof: client sets fare to 1' });
      const reproduced = attack.json?.priceTampered === true && attack.json?.fareCharged === 1;
      return result(reproduced, [hold.exchange, attack.exchange], {
        rootCause: 'client-controlled-fare', businessContext: ['bookings', 'payments'], destructive: true,
        impact: 'A caller can book at an arbitrary price, causing direct revenue loss and corrupt fare accounting.',
        fix: 'Recompute fare server-side from holdId and reject requests containing client price fields.', requests: 0,
      });
    },
  },
  {
    key: 'mass-assignment', label: 'Sub-agent privilege escalation via mass assignment', endpoint: '/api/book', method: 'POST',
    async run(ctx) {
      const control = await send(ctx, 'POST', '/api/book', { role: 'sub-agent', agency: 'A', body: {}, approvalKey: 'mass-assignment', label: 'Control: sub-agent baseline role' });
      const attack = await send(ctx, 'POST', '/api/book', { role: 'sub-agent', agency: 'A', body: { role: 'admin' }, approvalKey: 'mass-assignment', label: 'Proof: role field in body' });
      const reproduced = attack.json?.privilegeEscalated === true && attack.json?.effectiveRole === 'admin' && control.json?.effectiveRole !== 'admin';
      return result(reproduced, [control.exchange, attack.exchange], {
        rootCause: 'mass-assignment-role', businessContext: ['bookings', 'supplier-access'], authBypass: true, destructive: true,
        impact: 'Sub-agents can assign themselves admin privileges by adding a role property to the booking payload.',
        fix: 'Use explicit allowlisted DTO fields and derive role exclusively from the authenticated session.', requests: 0,
      });
    },
  },
  {
    key: 'coupon-reuse', label: 'Unlimited coupon reuse', endpoint: '/api/pay', method: 'POST',
    async run(ctx) {
      const control = await send(ctx, 'POST', '/api/pay', { role: 'agent', agency: 'A', body: { amount: 420, coupon: 'SENTINEL50' }, approvalKey: 'coupon-reuse', label: 'Control: first coupon use' });
      const attack = await send(ctx, 'POST', '/api/pay', { role: 'agent', agency: 'A', body: { amount: 420, coupon: 'SENTINEL50' }, approvalKey: 'coupon-reuse', label: 'Proof: coupon replay' });
      const reproduced = attack.json?.couponReused === true;
      return result(reproduced, [control.exchange, attack.exchange], {
        rootCause: 'coupon-replay', businessContext: ['payments', 'coupons', 'credit'], destructive: true,
        impact: 'A single promotional coupon can be replayed indefinitely, creating uncontrolled discounts.',
        fix: 'Make coupon redemption atomic and single-use per booking with a unique redemption record.', requests: 0,
      });
    },
  },
  {
    key: 'double-refund', label: 'Double refund on cancel-rebook', endpoint: '/api/cancel', method: 'POST',
    async run(ctx) {
      const hold = await send(ctx, 'POST', '/api/hold', { role: 'agent', agency: 'A', body: { destination: 'BOM' }, label: 'Control: fresh hold' });
      const cancel = await send(ctx, 'POST', '/api/cancel', { role: 'agent', agency: 'A', body: { holdId: hold.json?.holdId }, approvalKey: 'double-refund', label: 'Proof step 1: cancel and refund' });
      const rebook = await send(ctx, 'POST', '/api/book', { role: 'agent', agency: 'A', body: { holdId: hold.json?.holdId }, approvalKey: 'double-refund', label: 'Proof step 2: rebook same hold' });
      const reproduced = cancel.json?.refundIssued === true && rebook.json?.doubleRefund === true;
      return result(reproduced, [cancel.exchange, rebook.exchange], {
        rootCause: 'cancel-rebook-double-refund', businessContext: ['payments', 'credit', 'bookings'], destructive: true,
        impact: 'Cancelling and rebooking the same hold issues a second refund, enabling cash extraction.',
        fix: 'Bind refunds to immutable payment intents and enforce one refund per successful charge with idempotency keys.', requests: 0,
      });
    },
  },
  {
    key: 'coupon-stack', label: 'Unauthenticated coupon stacking in v2.1', endpoint: '/api/v2/coupons/stack', method: 'GET',
    async run(ctx) {
      const control = await send(ctx, 'GET', '/api/v2/coupons/stack?count=1', { label: 'Control: single coupon' });
      const attack = await send(ctx, 'GET', '/api/v2/coupons/stack?count=6', { label: 'Proof: stacked coupons' });
      const reproduced = attack.status === 200 && attack.json?.negativeTotal === true && attack.json?.unauthenticated === true;
      return result(reproduced, [control.exchange, attack.exchange], {
        rootCause: 'v21-coupon-stack', businessContext: ['payments', 'coupons', 'credit'], unauthenticated: true, destructive: true,
        impact: 'The newly deployed v2.1 route allows unauthenticated coupon stacking that produces negative totals.',
        fix: 'Gate the route behind auth, cap stacking server-side, and clamp totals to zero.', requests: 0,
      });
    },
  },
  {
    key: 'debug-exposure', label: 'Shadow debug endpoint leaks PII', endpoint: '/internal/debug', method: 'GET',
    async run(ctx) {
      const control = await send(ctx, 'GET', '/health', { label: 'Control: public health endpoint' });
      const attack = await send(ctx, 'GET', '/internal/debug', { label: 'Proof: unauthenticated debug data' });
      const reproduced = attack.status === 200 && /passport/i.test(attack.json?.passport ? 'passport' : '');
      return result(reproduced, [control.exchange, attack.exchange], {
        rootCause: 'shadow-debug-pii', businessContext: ['pii'], unauthenticated: true, dataExposed: ['passport', 'pnr', 'email'],
        impact: 'An undocumented internal route exposes passport, PNR and email fields without authentication.',
        fix: 'Remove the debug route from staging, block /internal at the gateway, and rotate any exposed synthetic fixtures.', requests: 0,
      });
    },
  },
  {
    key: 'ssrf-supplier', label: 'SSRF via supplier webhook URL', endpoint: '/api/supplier/webhook', method: 'POST',
    async run(ctx) {
      const control = await send(ctx, 'POST', '/api/supplier/webhook', { role: 'agent', agency: 'A', body: { url: 'https://public.example.test/hook' }, label: 'Control: external URL rejected' });
      const attack = await send(ctx, 'POST', '/api/supplier/webhook', { role: 'agent', agency: 'A', body: { url: `${ctx.target}/internal/debug` }, label: 'Proof: internal URL resolved' });
      const reproduced = attack.json?.ssrfConfirmed === true && control.status >= 400;
      return result(reproduced, [control.exchange, attack.exchange], {
        rootCause: 'supplier-webhook-ssrf', businessContext: ['supplier-access', 'pii'], dataExposed: ['internal.debug', 'passport'],
        impact: 'A supplier-controlled webhook URL can reach internal staging routes and return their contents.',
        fix: 'Allowlist supplier destinations, block RFC1918/loopback/link-local targets, and disable response-body echo.', requests: 0,
      });
    },
  },
  {
    key: 'injection-probe', label: 'SQLi probe on search', endpoint: '/api/search', method: 'POST',
    async run(ctx) {
      const control = await send(ctx, 'POST', '/api/search', { role: 'agent', agency: 'A', body: { origin: 'DEL' }, label: 'Control: normal search' });
      const attack = await send(ctx, 'POST', '/api/search', { role: 'agent', agency: 'A', body: { origin: "' OR 1=1--" }, label: 'Probe: benign SQLi marker' });
      const reproduced = /sql|syntax/i.test(attack.json?.error ?? '');
      return result(reproduced, [control.exchange, attack.exchange], {
        rootCause: 'search-injection-probe', businessContext: ['bookings'],
        impact: 'No injection signal observed with the safe marker; candidate retained only as a dropped false positive.',
        fix: 'No change required based on this probe; keep parameterized queries.', requests: 0,
      });
    },
  },
  {
    key: 'excess-data', label: 'Excess data in invoice response', endpoint: '/api/invoices/:id', method: 'GET',
    async run(ctx) {
      const control = await send(ctx, 'GET', '/health', { label: 'Control: harmless response' });
      const attack = await send(ctx, 'GET', '/api/invoices/BK-A-1001', { role: 'agent', agency: 'A', label: 'Probe: invoice fields' });
      const reproduced = attack.json?.internalScore !== undefined;
      return result(reproduced, [control.exchange, attack.exchange], {
        rootCause: 'invoice-excess-data', businessContext: ['invoices'],
        impact: 'Invoice payload contains only expected fields in this staging build.',
        fix: 'No change required; continue schema-level response filtering.', requests: 0,
      });
    },
  },
  {
    key: 'negative-qty', label: 'Negative quantity on booking', endpoint: '/api/book', method: 'POST',
    async run(ctx) {
      const control = await send(ctx, 'POST', '/api/hold', { role: 'agent', agency: 'A', body: {}, label: 'Control: hold' });
      const attack = await send(ctx, 'POST', '/api/book', { role: 'agent', agency: 'A', body: { holdId: control.json?.holdId, quantity: -1 }, approvalKey: 'negative-qty', label: 'Probe: negative quantity' });
      const reproduced = Number(attack.json?.fareCharged) < 0;
      return result(reproduced, [control.exchange, attack.exchange], {
        rootCause: 'negative-quantity', businessContext: ['bookings'],
        impact: 'No negative charge observed in the staging adapter.',
        fix: 'No change required; validate quantity > 0 as defence in depth.', requests: 0,
      });
    },
  },
  {
    key: 'skip-payment', label: 'Skipped payment step', endpoint: '/api/book', method: 'POST',
    async run(ctx) {
      const control = await send(ctx, 'POST', '/api/hold', { role: 'agent', agency: 'A', body: {}, label: 'Control: hold' });
      const attack = await send(ctx, 'POST', '/api/book', { role: 'agent', agency: 'A', body: { holdId: control.json?.holdId }, approvalKey: 'skip-payment', label: 'Probe: book without payment' });
      const reproduced = attack.json?.paymentSkipped === true;
      return result(reproduced, [control.exchange, attack.exchange], {
        rootCause: 'skipped-payment-step', businessContext: ['payments'],
        impact: 'No skipped-payment state transition observed; booking and payment remain separate staging steps.',
        fix: 'No change required; keep server-side state-machine checks.', requests: 0,
      });
    },
  },
];

export const PROOFS: Record<string, ProofSpec> = Object.fromEntries(P.map((p) => [p.key, p]));
export const ALL_PROOFS = P;
