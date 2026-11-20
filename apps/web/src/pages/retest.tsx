import { ArrowRight, CheckCircle2, RotateCcw, XCircle } from 'lucide-react';
import { useState } from 'react';
import { TEST_CLASS_LABEL } from '@sentinel/shared';
import type { TestClass } from '@sentinel/shared';
import type { Sentinel } from '../lib/api';
import { timeAgo } from '../lib/utils';
import { Badge, Button, Code, Empty, Panel, SeverityPill } from '../components/ui';

export function Retest({ sentinel }: { sentinel: Sentinel }) {
  const { state, post } = sentinel;
  const [busy, setBusy] = useState<string | null>(null);
  const [open, setOpen] = useState<string | null>(null);
  if (!state) return null;
  const candidates = state.findings.filter((f) => !['false-positive'].includes(f.status));

  async function run(findingId: string, deployFix: boolean) {
    setBusy(findingId);
    await post(`/api/findings/${findingId}/retest`, { deployFix });
    setBusy(null);
  }

  return (
    <Panel title="Fix verification & retest" subtitle="deploys a patch to the staging mock, then replays the stored minimal proof" right={<Badge tone="cyan"><RotateCcw size={11} /> proof replay</Badge>}>
      {!candidates.length ? <Empty title="No findings to retest" detail="Findings appear after a verification run." /> : <div className="space-y-2">
        {candidates.map((finding) => (
          <div key={finding.id} className="rounded border border-white/5 bg-ink-950/60">
            <div className="flex flex-wrap items-center gap-3 p-3">
              <SeverityPill severity={finding.severity} />
              <div className="min-w-[220px] flex-1">
                <div className="text-xs font-medium text-slate-200">{finding.title}</div>
                <div className="mt-0.5 font-mono text-[10px] text-cyan-300/70">{finding.endpoint} · {TEST_CLASS_LABEL[finding.testClass as TestClass]}</div>
              </div>
              <Badge tone={finding.status === 'closed' ? 'green' : finding.status === 'still-vulnerable' ? 'red' : 'slate'}>{finding.status}</Badge>
              {finding.retest && <span className="num text-[10px] text-slate-500">retested {timeAgo(finding.retest.at)}</span>}
              <div className="flex gap-1.5">
                <Button variant="success" disabled={busy === finding.id} onClick={() => void run(finding.id, true)}><CheckCircle2 size={12} /> Fix deployed → retest</Button>
                <Button disabled={busy === finding.id} onClick={() => void run(finding.id, false)}><RotateCcw size={12} /> Replay proof</Button>
                <Button onClick={() => setOpen(open === finding.id ? null : finding.id)}>Evidence</Button>
              </div>
            </div>
            {open === finding.id && <div className="border-t border-white/5 p-3">
              <div className="grid gap-3 lg:grid-cols-2">
                <div><div className="label mb-1.5">Before — stored proof</div>{finding.evidence.slice(-1).map((e, i) => <Code key={i} className="max-h-40">{e.response.body}</Code>)}</div>
                <div><div className="label mb-1.5">After — latest replay</div>{finding.retest ? <Code className="max-h-40">{finding.retest.after.slice(-1).map((e) => e.response.body).join('\n')}</Code> : <div className="rounded border border-dashed border-white/10 p-4 text-center text-[10px] text-slate-600">Not retested yet</div>}</div>
              </div>
              {finding.retest && <div className={`mt-3 flex items-center gap-2 rounded border p-2 text-[10px] ${finding.retest.result === 'closed' ? 'border-emerald-400/20 bg-emerald-400/[0.05] text-emerald-300' : 'border-rose-400/20 bg-rose-400/[0.05] text-rose-300'}`}>
                {finding.retest.result === 'closed' ? <CheckCircle2 size={13} /> : <XCircle size={13} />}
                {finding.retest.result === 'closed' ? 'Vulnerability closed — proof no longer reproduces against control.' : 'Still vulnerable — proof reproduced after patch deployment.'}
                <ArrowRight size={12} /> {finding.retest.before.length} before exchanges · {finding.retest.after.length} after exchanges
              </div>}
            </div>}
          </div>
        ))}
      </div>}
    </Panel>
  );
}
