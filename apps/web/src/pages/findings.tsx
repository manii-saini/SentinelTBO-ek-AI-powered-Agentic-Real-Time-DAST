import { ChevronDown, ExternalLink, Fingerprint, ShieldCheck } from 'lucide-react';
import { useState } from 'react';
import { TEST_CLASS_LABEL } from '@sentinel/shared';
import type { TestClass } from '@sentinel/shared';
import type { Sentinel } from '../lib/api';
import { timeAgo } from '../lib/utils';
import { Badge, Code, Empty, Panel, SeverityPill, Tabs } from '../components/ui';

export function Findings({ sentinel }: { sentinel: Sentinel }) {
  const { state } = sentinel;
  const [tab, setTab] = useState<'confirmed' | 'dropped' | 'closed'>('confirmed');
  const [open, setOpen] = useState<string | null>(null);
  if (!state) return null;
  const list = state.findings.filter((f) => tab === 'dropped' ? f.status === 'false-positive' : tab === 'closed' ? f.status === 'closed' || f.status === 'still-vulnerable' : !['false-positive', 'closed', 'still-vulnerable'].includes(f.status));

  return (
    <Panel title="Verified findings" subtitle="minimal redacted proof · deduped by endpoint + class + root cause" right={<Tabs tabs={[
      { id: 'confirmed' as const, label: 'Confirmed', count: state.findings.filter((f) => !['false-positive', 'closed', 'still-vulnerable'].includes(f.status)).length },
      { id: 'dropped' as const, label: 'False positives dropped', count: state.findings.filter((f) => f.status === 'false-positive').length },
      { id: 'closed' as const, label: 'Retested', count: state.findings.filter((f) => f.status === 'closed' || f.status === 'still-vulnerable').length },
    ]} active={tab} onChange={setTab} />}>
      {!list.length ? <Empty title="Nothing here yet" detail="Findings appear after verification and triage complete." /> : <div className="space-y-2">
        {list.map((finding) => (
          <div key={finding.id} className="rounded border border-white/5 bg-ink-950/60">
            <button onClick={() => setOpen(open === finding.id ? null : finding.id)} className="flex w-full items-start gap-3 p-3 text-left hover:bg-white/[0.02]">
              <div className="mt-0.5"><SeverityPill severity={finding.severity} /></div>
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-2"><span className="text-xs font-medium text-slate-200">{finding.title}</span><Badge tone="slate">{TEST_CLASS_LABEL[finding.testClass as TestClass]}</Badge><Badge tone={finding.status === 'closed' ? 'green' : finding.status === 'still-vulnerable' ? 'red' : 'slate'}>{finding.status}</Badge></div>
                <div className="mt-1 font-mono text-[10px] text-cyan-300/80">{finding.endpoint}</div>
                <div className="mt-1 text-[10px] text-slate-500">{finding.impact}</div>
              </div>
              <div className="shrink-0 text-right"><div className="num text-lg font-semibold text-amber-300">{finding.score}</div><div className="text-[9px] text-slate-600">score /100</div><div className="mt-1 text-[9px] text-slate-500">owner: {finding.owner}</div></div>
              <ChevronDown size={14} className={`mt-1 shrink-0 text-slate-600 transition-transform ${open === finding.id ? 'rotate-180' : ''}`} />
            </button>
            {open === finding.id && <div className="border-t border-white/5 p-3">
              <div className="grid gap-3 lg:grid-cols-3">
                <div className="space-y-2">
                  <div className="label">Classification</div>
                  <div className="text-[10px] text-slate-400">{finding.cwe}</div><div className="text-[10px] text-slate-400">{finding.owasp}</div>
                  <div className="num text-[9px] text-slate-600">{finding.id} · {timeAgo(finding.createdAt)}</div>
                  <div className="flex items-center gap-1 text-[10px] text-slate-500"><Fingerprint size={11} /> {finding.requestsSent} synthetic requests</div>
                </div>
                <div className="space-y-2 lg:col-span-2">
                  <div className="label">Severity rationale</div>
                  <p className="text-[10px] leading-relaxed text-slate-400">{finding.scoreExplanation}</p>
                  <div className="label pt-1">Suggested fix</div>
                  <p className="text-[10px] leading-relaxed text-emerald-200/80">{finding.fix}</p>
                </div>
              </div>
              <div className="mt-3 space-y-2">
                <div className="label flex items-center gap-1"><ShieldCheck size={11} /> Minimal proof — control + two independent replays, PII redacted</div>
                {finding.evidence.map((e, i) => (
                  <div key={i} className="rounded border border-white/5 bg-ink-950 p-2">
                    <div className="mb-1.5 flex items-center justify-between gap-2"><span className="text-[10px] font-medium text-slate-300">{i + 1}. {e.label}</span><span className="num text-[9px] text-slate-600">{e.response.status} · {e.response.timingMs}ms</span></div>
                    <div className="mb-1 font-mono text-[9px] text-cyan-300/70">{e.request.method} {e.request.url}</div>
                    {e.request.body && <Code className="mb-1 max-h-24">{e.request.body}</Code>}
                    <Code className="max-h-36">{e.response.body}</Code>
                  </div>
                ))}
                {finding.retest && <div className="mt-2 rounded border border-cyan-400/15 bg-cyan-400/[0.04] p-2 text-[10px] text-cyan-200"><ExternalLink size={10} className="mr-1 inline" /> Retest {timeAgo(finding.retest.at)}: {finding.retest.result} · {finding.retest.after.length} after-evidence exchanges</div>}
              </div>
            </div>}
          </div>
        ))}
      </div>}
    </Panel>
  );
}
