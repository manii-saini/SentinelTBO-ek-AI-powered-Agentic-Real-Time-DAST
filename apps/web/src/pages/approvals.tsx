import { Check, Clock, Pencil, X } from 'lucide-react';
import { useState } from 'react';
import type { Sentinel } from '../lib/api';
import { timeAgo } from '../lib/utils';
import { Badge, Button, Empty, Input, Panel, Tabs } from '../components/ui';

export function Approvals({ sentinel }: { sentinel: Sentinel }) {
  const { state, post } = sentinel;
  const [tab, setTab] = useState<'pending' | 'all'>('pending');
  const [modifyId, setModifyId] = useState<string | null>(null);
  const [note, setNote] = useState('');
  if (!state) return null;
  const approvals = state.approvals.filter((a) => tab === 'all' || a.status === 'pending');

  async function decide(id: string, decision: string) {
    await post(`/api/approvals/${id}`, { decision, modifiedPlan: note ? { note } : undefined });
    setModifyId(null);
    setNote('');
  }

  return (
    <Panel title="Human approval queue" subtitle="risky payment/refund tests and high-severity findings wait here" right={<Tabs tabs={[{ id: 'pending' as const, label: 'Pending', count: state.approvals.filter((a) => a.status === 'pending').length }, { id: 'all' as const, label: 'All', count: state.approvals.length }]} active={tab} onChange={setTab} />}>
      {!approvals.length ? <Empty title={tab === 'pending' ? 'Queue clear' : 'No approvals yet'} detail="Risky tests and high-severity findings are gated here before execution or publication." /> : (
        <div className="space-y-2">
          {approvals.map((a) => (
            <div key={a.id} className="rounded border border-white/5 bg-ink-950/60 p-3">
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <div className="flex items-center gap-2"><Badge tone={a.kind === 'test' ? 'cyan' : 'violet'}>{a.kind}</Badge><Badge tone={a.risk === 'high' ? 'red' : 'amber'}>{a.risk} risk</Badge><Badge tone={a.status === 'approved' ? 'green' : a.status === 'rejected' ? 'red' : a.status === 'modified' ? 'violet' : 'amber'}>{a.status}</Badge></div>
                  <div className="mt-2 text-xs font-medium text-slate-200">{a.title}</div>
                  <div className="mt-1 text-[10px] leading-relaxed text-slate-500">{a.reason}</div>
                  <div className="mt-1.5 flex items-center gap-1 font-mono text-[9px] text-slate-600"><Clock size={10} /> {a.id} · {a.refId} · {timeAgo(a.createdAt)}</div>
                </div>
                {a.status === 'pending' && <div className="flex shrink-0 gap-1.5">
                  <Button variant="success" onClick={() => void decide(a.id, 'approved')}><Check size={12} /> Approve</Button>
                  <Button variant="danger" onClick={() => void decide(a.id, 'rejected')}><X size={12} /> Reject</Button>
                  <Button onClick={() => setModifyId(modifyId === a.id ? null : a.id)}><Pencil size={12} /> Modify</Button>
                </div>}
              </div>
              {modifyId === a.id && <div className="mt-3 flex gap-2"><Input value={note} onChange={(e) => setNote(e.target.value)} placeholder="Modification note (e.g. narrow scope to agency A only)" /><Button variant="primary" onClick={() => void decide(a.id, 'modified')}>Save & approve</Button></div>}
            </div>
          ))}
        </div>
      )}
    </Panel>
  );
}
