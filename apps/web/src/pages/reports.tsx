import { Check, Send, Webhook } from 'lucide-react';
import { useState } from 'react';
import type { Sentinel } from '../lib/api';
import { timeAgo } from '../lib/utils';
import { Badge, Button, Code, Input, Panel, SeverityPill } from '../components/ui';

export function Reports({ sentinel }: { sentinel: Sentinel }) {
  const { state, post } = sentinel;
  const [selected, setSelected] = useState<string | null>(null);
  const [url, setUrl] = useState(state?.webhookConfig.url ?? '');
  if (!state) return null;
  const ticket = state.tickets.find((t) => t.id === selected) ?? state.tickets[0];
  const finding = ticket ? state.findings.find((f) => f.id === ticket.findingId) : undefined;

  return (
    <div className="grid gap-4 lg:grid-cols-3">
      <Panel title="Generated tickets" subtitle={`${state.tickets.length} Jira-style drafts awaiting delivery`} className="lg:col-span-1" bodyClass="p-0">
        <div className="max-h-[640px] divide-y divide-white/[0.04] overflow-y-auto">
          {state.tickets.map((t) => (
            <button key={t.id} onClick={() => setSelected(t.id)} className={`block w-full px-3 py-2.5 text-left transition-colors ${ticket?.id === t.id ? 'bg-cyan-400/[0.07]' : 'hover:bg-white/[0.02]'}`}>
              <div className="flex items-center justify-between gap-2"><span className="num text-[10px] text-cyan-300">{t.id}</span>{finding && <SeverityPill severity={finding.severity} />}</div>
              <div className="mt-1 line-clamp-2 text-[10px] text-slate-300">{t.title}</div>
              <div className="mt-1 flex items-center justify-between text-[9px] text-slate-600"><span>{timeAgo(t.createdAt)}</span>{t.sent ? <Badge tone="green"><Check size={9} /> {t.destination}</Badge> : <Badge>draft</Badge>}</div>
            </button>
          ))}
          {!state.tickets.length && <div className="py-12 text-center text-[11px] text-slate-600">No tickets yet — run the loop first.</div>}
        </div>
      </Panel>

      <Panel title={ticket?.title ?? 'No ticket selected'} subtitle={ticket ? `owner ${finding?.owner ?? '—'} · ${finding?.owasp ?? ''}` : ''} className="lg:col-span-2" right={ticket && <div className="flex items-center gap-1.5">
        <Button variant="primary" onClick={() => void post(`/api/tickets/${ticket.id}/send`, { destination: 'mock-jira' })}><Send size={11} /> Jira</Button>
        <Button onClick={() => void post(`/api/tickets/${ticket.id}/send`, { destination: 'mock-teams' })}><Send size={11} /> Teams</Button>
        <Button onClick={() => void post(`/api/tickets/${ticket.id}/send`, { destination: 'webhook' })}><Webhook size={11} /> Webhook</Button>
      </div>}>
        {ticket && <Code className="max-h-[560px] whitespace-pre-wrap">{ticket.markdown}</Code>}
      </Panel>

      <Panel title="Delivery adapters" subtitle="mock by default — webhook must pass the scope allowlist" className="lg:col-span-3">
        <div className="flex flex-wrap items-end gap-3">
          <div className="min-w-[360px] flex-1"><div className="label mb-1.5">Webhook URL (staging allowlist only)</div><Input value={url} onChange={(e) => setUrl(e.target.value)} placeholder="http://127.0.0.1:4000/__admin/..." /></div>
          <Button variant="primary" onClick={() => void post('/api/webhook', { url })}>Save webhook</Button>
          <div className="text-[10px] text-slate-500">Configured: <span className="num text-cyan-300">{state.webhookConfig.url || 'none'}</span> · out-of-scope destinations are blocked and written to the audit log.</div>
        </div>
      </Panel>
    </div>
  );
}
