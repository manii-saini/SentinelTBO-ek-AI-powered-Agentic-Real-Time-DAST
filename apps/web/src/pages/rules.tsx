import { Ban, FileCheck2, KeyRound, Lock, ScrollText, ShieldCheck } from 'lucide-react';
import { Badge, Panel } from '../components/ui';

const RULES = [
  { icon: Lock, title: 'Scope', text: 'Targets are restricted to an explicit host:port allowlist. Any request outside scope is stopped before it leaves the process and written to the audit log in red.' },
  { icon: KeyRound, title: 'Synthetic identities', text: 'Only bundled test accounts for agencies A and B (agent, sub-agent, admin). Real credentials are rejected by the safety middleware.' },
  { icon: Ban, title: 'No destructive testing', text: 'POST/PUT/PATCH/DELETE against booking, payment, refund or cancel paths require an approved request id. No DoS, no persistence of access, no bulk extraction.' },
  { icon: FileCheck2, title: 'Minimal, redacted evidence', text: 'The verifier replays a minimal proof twice against a control, stores only the smallest useful request/response pair, and redacts passport, card, email and token fields.' },
  { icon: ScrollText, title: 'Full replayability', text: 'Every request — allowed or blocked — is appended to a hash-chained audit log with method, URL, role, status, timing and a redacted replay payload.' },
  { icon: ShieldCheck, title: 'Staging only', text: 'The bundled mock binds 127.0.0.1:4000 and contains only synthetic passengers, bookings and fares. The system never points at production systems.' },
];

export function Rules() {
  return (
    <div className="space-y-4">
      <div className="panel flex flex-wrap items-center justify-between gap-3 border-emerald-400/20 bg-emerald-400/[0.04] p-4">
        <div className="flex items-center gap-3"><ShieldCheck size={22} className="text-emerald-400" /><div><div className="text-sm font-semibold text-emerald-200">RULES OF ENGAGEMENT — ACTIVE</div><div className="mt-0.5 text-[11px] text-slate-400">Enforced in code by the safety middleware, not just displayed here.</div></div></div>
        <Badge tone="green">staging · synthetic · audited</Badge>
      </div>
      <div className="grid gap-4 lg:grid-cols-3">
        {RULES.map(({ icon: Icon, title, text }) => (
          <Panel key={title} title={title}><Icon size={18} className="mb-2 text-cyan-400" /><p className="text-[11px] leading-relaxed text-slate-400">{text}</p></Panel>
        ))}
      </div>
      <Panel title="Enforcement points" subtitle="where the rules are actually applied">
        <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
          {[
            ['packages/agents/src/safety.ts', 'allowlist, token bucket, approvals, health backoff, hash chain'],
            ['packages/agents/src/proofs.ts', 'synthetic headers, scoped credentials, minimal evidence'],
            ['packages/agents/src/agents/verifier.ts', '2× replay + control, false-positive rejection, redaction'],
            ['apps/mock/src/server.ts', 'loopback-only staging service with synthetic fixtures'],
          ].map(([path, detail]) => <div key={path} className="rounded border border-white/5 bg-ink-950/60 p-3"><div className="font-mono text-[10px] text-cyan-300">{path}</div><div className="mt-1 text-[10px] text-slate-500">{detail}</div></div>)}
        </div>
      </Panel>
    </div>
  );
}
