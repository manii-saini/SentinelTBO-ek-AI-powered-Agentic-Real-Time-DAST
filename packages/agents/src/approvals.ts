import type { ApprovalRequest, PlannedTest } from '@sentinel/shared';
import { nowId } from '@sentinel/shared';
import type { AgentContext } from './agent.js';

export function createApproval(
  ctx: AgentContext,
  input: { kind: ApprovalRequest['kind']; refId: string; title: string; reason: string; risk: ApprovalRequest['risk'] },
): ApprovalRequest {
  const approval: ApprovalRequest = {
    id: nowId('apr'),
    kind: input.kind,
    refId: input.refId,
    title: input.title,
    reason: input.reason,
    risk: input.risk,
    createdAt: Date.now(),
    status: 'pending',
  };
  ctx.store.addApproval(approval);
  ctx.emit('system', 'warn', `Approval required: ${approval.title}`, { approvalId: approval.id, risk: approval.risk });
  if (ctx.autoApprove) {
    ctx.store.updateApproval(approval.id, 'approved');
    approval.status = 'approved';
    ctx.emit('system', 'info', `Demo policy auto-approved ${approval.id} (synthetic staging target, reversible test)`, { approvalId: approval.id });
  }
  return approval;
}

export function approvalForTest(test: PlannedTest, ctx: AgentContext): ApprovalRequest | null {
  if (!test.needsApproval) return null;
  return createApproval(ctx, {
    kind: 'test',
    refId: test.id,
    title: test.name,
    reason: `Touches payment/refund/booking mutation on staging with synthetic accounts. ${test.reasoning}`,
    risk: test.risk === 'high' ? 'high' : 'medium',
  });
}
