import type { TestClass } from '@sentinel/shared';
import type { AgentContext } from '../agent.js';
import { PROOFS, type ProofResult } from '../proofs.js';
import type { PlannedTest } from '@sentinel/shared';

export interface Candidate {
  test: PlannedTest;
  proofKey: string;
  result: ProofResult;
}

export interface Executor {
  readonly id: string;
  readonly classes: TestClass[];
  execute(tests: PlannedTest[], ctx: AgentContext): Promise<Candidate[]>;
}

export async function runProofs(tests: PlannedTest[], ctx: AgentContext, executorId: string): Promise<Candidate[]> {
  const candidates: Candidate[] = [];
  for (const test of tests) {
    const proof = PROOFS[test.executor];
    if (!proof) continue;
    ctx.store.updatePlannedTest(test.id, 'running');
    const result = await proof.run(ctx);
    ctx.store.updatePlannedTest(test.id, 'done');
    ctx.emit('execute', result.reproduced ? 'warn' : 'info', `${executorId}: ${test.name} → ${result.reproduced ? 'signal observed' : 'no signal'}`, {
      testId: test.id, proofKey: test.executor, requests: result.meta.requests, endpoint: test.endpoint,
    });
    if (result.reproduced) candidates.push({ test, proofKey: test.executor, result });
  }
  return candidates;
}

class BaseExecutor implements Executor {
  constructor(readonly id: string, readonly classes: TestClass[]) {}
  async execute(tests: PlannedTest[], ctx: AgentContext): Promise<Candidate[]> {
    const mine = tests.filter((t) => this.classes.includes(t.testClass));
    if (!mine.length) return [];
    ctx.emit('execute', 'info', `${this.id} executing ${mine.length} targeted test(s)`, { classes: this.classes });
    return runProofs(mine, ctx, this.id);
  }
}

export class AccessControlExecutor extends BaseExecutor { constructor() { super('AccessControl', ['access-control']); } }
export class BusinessLogicExecutor extends BaseExecutor { constructor() { super('BusinessLogic', ['business-logic']); } }
export class AuthExecutor extends BaseExecutor { constructor() { super('Auth', ['auth-session']); } }
export class InjectionExecutor extends BaseExecutor { constructor() { super('Injection', ['injection']); } }
export class HygieneExecutor extends BaseExecutor { constructor() { super('Hygiene', ['api-hygiene']); } }
export class DataExposureExecutor extends BaseExecutor { constructor() { super('DataExposure', ['data-exposure']); } }
export class SSRFExecutor extends BaseExecutor { constructor() { super('SSRF', ['ssrf-open-redirect']); } }

export const EXECUTORS: Executor[] = [
  new AccessControlExecutor(),
  new BusinessLogicExecutor(),
  new AuthExecutor(),
  new InjectionExecutor(),
  new HygieneExecutor(),
  new DataExposureExecutor(),
  new SSRFExecutor(),
];

export async function executeAll(tests: PlannedTest[], ctx: AgentContext): Promise<Candidate[]> {
  const results = await Promise.all(EXECUTORS.map((executor) => executor.execute(tests, ctx)));
  return results.flat();
}
