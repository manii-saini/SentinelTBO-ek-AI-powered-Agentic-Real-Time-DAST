import type { Finding } from '@sentinel/shared';
import { CWE_OWASP, scoreSeverity } from '@sentinel/shared';
import type { Agent, AgentContext } from '../agent.js';
import { createApproval } from '../approvals.js';
import { ownerForPath } from '../config.js';
import { deterministicFindingId, droppedFinding, findingKey, type DroppedCandidate, type VerifiedCandidate } from './verifier.js';

export class TriageAgent implements Agent<{ verified: VerifiedCandidate[]; dropped: DroppedCandidate[] }, Finding[]> {
  readonly id = 'triage';
  readonly name = 'TriageAgent';

  async run(input: { verified: VerifiedCandidate[]; dropped: DroppedCandidate[] }, ctx: AgentContext): Promise<Finding[]> {
    ctx.emit('triage', 'info', 'Deduplicating by endpoint + class + root cause and applying business-impact rubric');
    input.dropped.forEach((d) => ctx.store.upsertFinding(droppedFinding(d, ctx)));

    const findings: Finding[] = [];
    for (const item of input.verified) {
      const meta = item.result.meta;
      const scoring = scoreSeverity({
        testClass: item.test.testClass,
        businessContext: meta.businessContext,
        crossAgency: meta.crossAgency,
        authBypass: meta.authBypass,
        unauthenticated: meta.unauthenticated,
        destructive: meta.destructive,
        dataExposed: meta.dataExposed,
        reproducible: true,
      });
      const tags = CWE_OWASP[item.test.testClass];
      const owner = ownerForPath(item.test.endpoint);
      const key = findingKey(item);
      const finding: Finding = {
        id: deterministicFindingId(key),
        key,
        title: item.test.name,
        endpointId: item.test.endpointId,
        endpoint: item.test.endpoint,
        testClass: item.test.testClass,
        severity: scoring.severity,
        score: scoring.score,
        scoreExplanation: scoring.explanation,
        cwe: tags.cwe,
        owasp: tags.owasp,
        owner: owner.owner,
        status: 'open',
        createdAt: Date.now(),
        evidence: item.evidence,
        impact: meta.impact,
        fix: meta.fix,
        requestsSent: item.requestsSent,
        rootCause: meta.rootCause,
      };
      ctx.store.upsertFinding(finding);
      findings.push(finding);

      if (scoring.severity === 'critical' || scoring.severity === 'high') {
        const approval = createApproval(ctx, {
          kind: 'finding',
          refId: finding.id,
          title: `Publish ${finding.severity} finding: ${finding.title}`,
          reason: `Business-impact score ${finding.score}/100 for ${finding.endpoint}. Owner ${finding.owner}.`,
          risk: 'high',
        });
        if (approval.status === 'approved') ctx.store.updateApproval(approval.id, 'approved');
      }
      ctx.emit('triage', 'success', `${finding.severity.toUpperCase()} ${finding.title} → ${finding.owner} (${finding.score}/100)`, {
        findingId: finding.id, cwe: finding.cwe, owasp: finding.owasp,
      });
    }
    ctx.emit('triage', 'info', `Triage complete: ${findings.length} verified finding(s), ${input.dropped.length} false positive(s) dropped`);
    return findings;
  }
}
