import { createHash } from 'node:crypto';
import type { Finding, ProofExchange } from '@sentinel/shared';
import { nowId } from '@sentinel/shared';
import type { Agent, AgentContext } from '../agent.js';
import type { Candidate } from './executors.js';
import { PROOFS } from '../proofs.js';

export interface VerifiedCandidate extends Candidate {
  evidence: ProofExchange[];
  requestsSent: number;
}

export interface DroppedCandidate {
  candidate: Candidate;
  reason: string;
}

export function findingKey(candidate: Candidate): string {
  return [candidate.test.endpoint, candidate.test.testClass, candidate.result.meta.rootCause].join('|');
}

export function deterministicFindingId(key: string): string {
  return `fnd_${createHash('sha1').update(key).digest('hex').slice(0, 12)}`;
}

export class VerifierAgent implements Agent<Candidate[], { verified: VerifiedCandidate[]; dropped: DroppedCandidate[] }> {
  readonly id = 'verify';
  readonly name = 'VerifierAgent';

  async run(candidates: Candidate[], ctx: AgentContext): Promise<{ verified: VerifiedCandidate[]; dropped: DroppedCandidate[] }> {
    ctx.emit('verify', 'info', `Re-running minimal proofs twice with control comparison for ${candidates.length} candidate(s)`);
    const verified: VerifiedCandidate[] = [];
    const dropped: DroppedCandidate[] = [];

    for (const candidate of candidates) {
      const proof = PROOFS[candidate.proofKey];
      if (!proof) continue;
      const first = await proof.run(ctx);
      const second = await proof.run(ctx);
      const stable = first.reproduced && second.reproduced
        && JSON.stringify(first.meta.rootCause) === JSON.stringify(second.meta.rootCause);
      const requestsSent = candidate.result.meta.requests + first.meta.requests + second.meta.requests;

      if (stable) {
        const evidence: ProofExchange[] = [
          candidate.result.evidence[0],
          first.evidence[first.evidence.length - 1],
          second.evidence[second.evidence.length - 1],
        ].filter(Boolean).map((e) => ({ ...e, response: { ...e.response, body: e.response.body.slice(0, 900) } }));
        verified.push({ ...candidate, evidence, requestsSent });
        ctx.emit('verify', 'success', `Verified: ${candidate.test.name} (2/2 replays)`, { testId: candidate.test.id, requests: requestsSent });
      } else {
        const reason = `Dropped: proof reproduced ${Number(first.reproduced) + Number(second.reproduced)}/2 times; control or state comparison unstable`;
        dropped.push({ candidate, reason });
        ctx.emit('verify', 'warn', `False positive dropped: ${candidate.test.name}`, { reason, testId: candidate.test.id });
      }
    }

    const uniqueVerified = [...new Map(verified.map((v) => [findingKey(v), v])).values()];
    if (verified.length !== uniqueVerified.length) ctx.emit('verify', 'info', `Deduplicated ${verified.length - uniqueVerified.length} repeat hit(s)`);
    return { verified: uniqueVerified, dropped };
  }
}

export function droppedFinding(dropped: DroppedCandidate, ctx: AgentContext): Finding {
  const key = findingKey(dropped.candidate);
  return {
    id: deterministicFindingId(key),
    key,
    title: dropped.candidate.test.name,
    endpointId: dropped.candidate.test.endpointId,
    endpoint: dropped.candidate.test.endpoint,
    testClass: dropped.candidate.test.testClass,
    severity: 'info',
    score: 0,
    scoreExplanation: dropped.reason,
    cwe: '-',
    owasp: '-',
    owner: 'VerifierAgent',
    status: 'false-positive',
    createdAt: Date.now(),
    evidence: [dropped.candidate.result.evidence[dropped.candidate.result.evidence.length - 1]].filter(Boolean),
    impact: 'No reproducible business impact; not shown in confirmed findings.',
    fix: 'No action required.',
    requestsSent: dropped.candidate.result.meta.requests,
    rootCause: dropped.candidate.result.meta.rootCause,
  };
}
