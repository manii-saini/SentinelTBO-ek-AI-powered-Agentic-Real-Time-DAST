import type { Finding } from '@sentinel/shared';
import type { Agent, AgentContext } from '../agent.js';
import { PROOFS } from '../proofs.js';

const FIX_TO_PROOF: Record<string, { patch: string; proof: string }> = {
  'booking-idor': { patch: 'bola', proof: 'bola' },
  'legacy-cross-tenant-list': { patch: 'zombie', proof: 'cross-agency-enum' },
  'legacy-missing-auth': { patch: 'zombie', proof: 'unauth-legacy' },
  'client-controlled-fare': { patch: 'fare-tamper', proof: 'fare-tamper' },
  'mass-assignment-role': { patch: 'mass-assignment', proof: 'mass-assignment' },
  'coupon-replay': { patch: 'coupon-reuse', proof: 'coupon-reuse' },
  'cancel-rebook-double-refund': { patch: 'double-refund', proof: 'double-refund' },
  'v21-coupon-stack': { patch: 'coupon-stack', proof: 'coupon-stack' },
  'shadow-debug-pii': { patch: 'shadow', proof: 'debug-exposure' },
  'supplier-webhook-ssrf': { patch: 'ssrf', proof: 'ssrf-supplier' },
};

export async function deployFix(ctx: AgentContext, findingId: string): Promise<Finding | null> {
  const finding = ctx.store.getFinding(findingId);
  const mapping = finding ? FIX_TO_PROOF[finding.rootCause] : undefined;
  if (!finding || !mapping) return null;
  const res = await ctx.http.send({
    method: 'POST',
    url: `${ctx.target}/__admin/patch`,
    headers: { 'x-sentinel-synthetic': 'true', 'content-type': 'application/json' },
    body: JSON.stringify({ keys: [mapping.patch] }),
    runId: ctx.runId,
  });
  ctx.emit('retest', res.blocked ? 'error' : 'info', `Fix deployed for ${finding.title} (patch: ${mapping.patch})`, { status: res.status, blocked: res.blocked });
  return finding;
}

export class RetestAgent implements Agent<Finding, Finding> {
  readonly id = 'retest';
  readonly name = 'RetestAgent';

  async run(finding: Finding, ctx: AgentContext): Promise<Finding> {
    const mapping = FIX_TO_PROOF[finding.rootCause];
    const proof = mapping ? PROOFS[mapping.proof] : undefined;
    if (!proof) return finding;
    const before = finding.evidence;
    const replay = await proof.run(ctx);
    const result: Finding['retest'] = {
      at: Date.now(),
      result: replay.reproduced ? 'still-vulnerable' : 'closed',
      before,
      after: replay.evidence,
    };
    const updated: Finding = {
      ...finding,
      status: replay.reproduced ? 'still-vulnerable' : 'closed',
      retest: result,
    };
    ctx.store.upsertFinding(updated);
    ctx.emit('retest', replay.reproduced ? 'error' : 'success', `${finding.title}: ${updated.status.toUpperCase()}`, {
      findingId: finding.id, before: before.length, after: replay.evidence.length,
    });
    return updated;
  }
}
