import type { Finding, Ticket } from '@sentinel/shared';
import { nowId } from '@sentinel/shared';
import type { Agent, AgentContext } from '../agent.js';

export function ticketMarkdown(finding: Finding): string {
  const evidence = finding.evidence.map((e, i) => [
    `### ${i + 1}. ${e.label}`,
    `**Request:** \`${e.request.method} ${e.request.url}\``,
    e.request.body ? `**Body:** \`${e.request.body}\`` : '',
    `**Response:** ${e.response.status} in ${e.response.timingMs}ms`,
    '```json',
    e.response.body,
    '```',
  ].filter(Boolean).join('\n')).join('\n\n');

  return `# [SEC] ${finding.title}

**Severity:** ${finding.severity.toUpperCase()} (${finding.score}/100)  
**Endpoint:** ${finding.endpoint}  
**Owner:** ${finding.owner}  
**Class:** ${finding.testClass}  
**Tags:** ${finding.cwe} · ${finding.owasp}  
**Finding ID:** ${finding.id} · **Dedupe key:** ${finding.key}

## Impact
${finding.impact}

## Severity rationale
${finding.scoreExplanation}

## Minimal proof (redacted, synthetic accounts only)
${evidence}

## Suggested fix
${finding.fix}

## Verification
Proof replayed 2× against a control request by VerifierAgent; ${finding.requestsSent} synthetic requests total. No production data or real accounts used.
`;
}

export class ReporterAgent implements Agent<Finding[], Ticket[]> {
  readonly id = 'report';
  readonly name = 'ReporterAgent';

  async run(findings: Finding[], ctx: AgentContext): Promise<Ticket[]> {
    const open = findings.filter((f) => f.status === 'open' || f.status === 'approved');
    const tickets: Ticket[] = [];
    for (const finding of open) {
      const ticket: Ticket = {
        id: nowId('SEC'),
        findingId: finding.id,
        title: `[SEC][${finding.severity.toUpperCase()}] ${finding.title}`,
        markdown: ticketMarkdown(finding),
        createdAt: Date.now(),
        destination: 'mock-jira',
        sent: false,
      };
      ctx.store.addTicket(ticket);
      ctx.store.upsertFinding({ ...finding, ticketId: ticket.id });
      tickets.push(ticket);
      ctx.emit('report', 'success', `Ticket ${ticket.id} drafted for ${finding.owner}`, { ticketId: ticket.id, findingId: finding.id });
    }
    ctx.emit('report', 'info', `${tickets.length} ticket(s) generated (not sent automatically)`);
    return tickets;
  }
}

export async function sendTicket(ctx: AgentContext, ticketId: string, destination: Ticket['destination']): Promise<Ticket | null> {
  const ticket = ctx.store.listTickets().find((t) => t.id === ticketId);
  if (!ticket) return null;
  if (destination === 'webhook') {
    const config = ctx.store.getSetting<{ url?: string }>('webhookConfig', {});
    if (config.url) {
      const res = await ctx.http.send({
        method: 'POST',
        url: config.url,
        headers: { 'x-sentinel-synthetic': 'true', 'content-type': 'application/json' },
        body: JSON.stringify({ ticket: ticket.id, title: ticket.title, markdown: ticket.markdown }),
        runId: ctx.runId,
      });
      ctx.emit('report', res.blocked ? 'error' : 'success', `Webhook delivery ${res.blocked ? 'blocked by safety layer' : 'accepted'}`, { reason: res.blockReason, status: res.status });
    }
  }
  ctx.store.updateTicket(ticketId, destination);
  ctx.emit('report', 'success', `${ticketId} delivered via ${destination} adapter`, { destination });
  return ctx.store.listTickets().find((t) => t.id === ticketId) ?? null;
}
