import type { Endpoint, PlannedTest, Role, TestClass } from '@sentinel/shared';
import { nowId } from '@sentinel/shared';
import type { Agent, AgentContext } from '../agent.js';

interface PlanRule {
  path: string;
  proofKey: string;
  testClass: TestClass;
  name: string;
  risk: 'low' | 'medium' | 'high';
  approval: boolean;
  roles: Role[];
  params: string[];
}

const RULES: PlanRule[] = [
  { path: '/api/bookings/:id', proofKey: 'bola', testClass: 'access-control', name: 'Swap booking ID across agency A → B', risk: 'high', approval: false, roles: ['agent'], params: ['id'] },
  { path: '/v1/bookings', proofKey: 'cross-agency-enum', testClass: 'access-control', name: 'Cross-agency legacy enumeration', risk: 'medium', approval: false, roles: ['agent'], params: [] },
  { path: '/v1/bookings', proofKey: 'unauth-legacy', testClass: 'auth-session', name: 'Unauthenticated legacy read', risk: 'medium', approval: false, roles: [], params: [] },
  { path: '/api/book', proofKey: 'fare-tamper', testClass: 'business-logic', name: 'Client-controlled fare tampering', risk: 'high', approval: true, roles: ['agent'], params: ['holdId', 'fare'] },
  { path: '/api/book', proofKey: 'mass-assignment', testClass: 'api-hygiene', name: 'Sub-agent → admin via mass assignment', risk: 'high', approval: true, roles: ['sub-agent'], params: ['role'] },
  { path: '/api/book', proofKey: 'negative-qty', testClass: 'business-logic', name: 'Negative quantity validation', risk: 'medium', approval: true, roles: ['agent'], params: ['quantity'] },
  { path: '/api/book', proofKey: 'skip-payment', testClass: 'business-logic', name: 'Skipped payment state transition', risk: 'high', approval: true, roles: ['agent'], params: ['holdId'] },
  { path: '/api/pay', proofKey: 'coupon-reuse', testClass: 'business-logic', name: 'Replay coupon twice', risk: 'high', approval: true, roles: ['agent'], params: ['coupon'] },
  { path: '/api/cancel', proofKey: 'double-refund', testClass: 'business-logic', name: 'Cancel → rebook double refund', risk: 'high', approval: true, roles: ['agent'], params: ['holdId'] },
  { path: '/internal/debug', proofKey: 'debug-exposure', testClass: 'data-exposure', name: 'Shadow route PII exposure', risk: 'high', approval: false, roles: [], params: [] },
  { path: '/api/supplier/webhook', proofKey: 'ssrf-supplier', testClass: 'ssrf-open-redirect', name: 'Supplier webhook SSRF to internal route', risk: 'high', approval: false, roles: ['agent'], params: ['url'] },
  { path: '/api/v2/coupons/stack', proofKey: 'coupon-stack', testClass: 'business-logic', name: 'Unauthenticated coupon stacking', risk: 'high', approval: false, roles: [], params: ['count'] },
  { path: '/api/search', proofKey: 'injection-probe', testClass: 'injection', name: 'Benign SQLi marker probe', risk: 'low', approval: false, roles: ['agent'], params: ['origin'] },
  { path: '/api/invoices/:id', proofKey: 'excess-data', testClass: 'data-exposure', name: 'Excess data in invoice response', risk: 'low', approval: false, roles: ['agent'], params: ['id'] },
];

export class PlannerAgent implements Agent<Endpoint[], PlannedTest[]> {
  readonly id = 'plan';
  readonly name = 'PlannerAgent';

  async run(endpoints: Endpoint[], ctx: AgentContext): Promise<PlannedTest[]> {
    ctx.emit('plan', 'info', 'Selecting targeted tests from endpoint parameters, roles and business context');
    const planned: PlannedTest[] = [];
    for (const rule of RULES) {
      const endpoint = endpoints.find((e) => e.path === rule.path);
      if (!endpoint) continue;
      const llm = await ctx.llm.complete({
        system: 'You are a conservative DAST planner. Justify one targeted test, never broad spraying.',
        prompt: `Endpoint: ${endpoint.method} ${endpoint.path}\nRoles: ${endpoint.roles.join(', ')}\nBusiness context: ${endpoint.businessContext.join(', ')}\nTest: ${rule.name}\nParams: ${rule.params.join(', ')}`,
        temperature: 0,
      });
      const test: PlannedTest = {
        id: nowId('test'),
        endpointId: endpoint.id,
        endpoint: endpoint.path,
        method: endpoint.method,
        testClass: rule.testClass,
        name: rule.name,
        reasoning: llm.text,
        params: rule.params,
        roles: rule.roles,
        risk: rule.risk,
        needsApproval: rule.approval,
        executor: rule.proofKey,
        status: 'planned',
      };
      planned.push(test);
      ctx.store.addPlannedTest(test, ctx.runId);
    }
    const groups = [...new Set(planned.map((t) => t.testClass))];
    ctx.emit('plan', 'success', `Planned ${planned.length} targeted tests across ${groups.length} classes (${planned.filter((t) => t.needsApproval).length} require approval)`, {
      classes: groups,
      approvals: planned.filter((t) => t.needsApproval).length,
      llm: ctx.llm.provider,
    });
    return planned;
  }
}
