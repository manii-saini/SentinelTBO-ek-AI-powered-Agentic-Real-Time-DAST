import { Activity, GitCommitHorizontal, Globe2, Radio, Sparkles, TrendingUp } from 'lucide-react';
import type { Sentinel } from '../lib/api';
import { timeAgo } from '../lib/utils';
import { Badge, Button, Code, Panel } from '../components/ui';

const TRIGGERS = [
  { kind: 'deploy', label: 'CI/CD deploy webhook', detail: 'POST /api/triggers/deploy — stage build, changed handlers', icon: GitCommitHorizontal, tone: 'cyan' as const },
  { kind: 'bundle-diff', label: 'Front-end JS bundle diff', detail: 'New route literals extracted from shipped bundle', icon: Sparkles, tone: 'violet' as const },
  { kind: 'subdomain', label: 'New subdomain / CT log', detail: 'Certificate transparency emitted a staging host', icon: Globe2, tone: 'amber' as const },
  { kind: 'traffic-anomaly', label: 'Traffic-log anomaly', detail: 'Gateway detects unusual legacy path activity', icon: TrendingUp, tone: 'red' as const },
];

export function ChangeDetection({ sentinel }: { sentinel: Sentinel }) {
  const { state, post } = sentinel;
  if (!state) return null;
  return (
    <div className="grid gap-4 lg:grid-cols-5">
      <Panel title="Fire simulated trigger" subtitle="each trigger queues endpoints and emits a change event" className="lg:col-span-2">
        <div className="space-y-2">
          {TRIGGERS.map(({ kind, label, detail, icon: Icon, tone }) => (
            <button key={kind} onClick={() => void post('/api/triggers/fire', { kind })} className="group flex w-full items-start gap-3 rounded border border-white/5 bg-ink-950/60 p-3 text-left transition-colors hover:border-cyan-400/30 hover:bg-cyan-400/[0.04]">
              <span className="mt-0.5 rounded border border-white/10 bg-white/[0.03] p-1.5 text-slate-400 group-hover:text-cyan-300"><Icon size={15} /></span>
              <span className="min-w-0 flex-1"><span className="block text-xs font-medium text-slate-200">{label}</span><span className="mt-0.5 block text-[10px] text-slate-500">{detail}</span></span>
              <Badge tone={tone}>fire</Badge>
            </button>
          ))}
          <div className="flex gap-2 pt-2">
            <Button variant="primary" className="flex-1" onClick={() => void post('/api/triggers/deploy', { mode: 'demo', autoApprove: true })} disabled={state.running}><Radio size={12} /> Deploy + run full loop</Button>
          </div>
        </div>
        <div className="mt-4">
          <div className="label mb-1.5">Real webhook</div>
          <Code>{`curl -X POST http://127.0.0.1:3001/api/triggers/deploy \\\n  -H 'content-type: application/json' \\\n  -d '{"startRun":true,"mode":"demo"}'`}</Code>
        </div>
      </Panel>

      <Panel title="Change events" subtitle="detected → testing → tested" className="lg:col-span-3" bodyClass="p-0">
        <div className="divide-y divide-white/[0.04]">
          {state.changes.map((change) => (
            <div key={change.id} className="px-4 py-3">
              <div className="flex items-start justify-between gap-3">
                <div className="flex items-center gap-2">
                  <Activity size={13} className="text-cyan-400" />
                  <div><div className="text-xs font-medium text-slate-200">{change.title}</div><div className="mt-0.5 text-[10px] text-slate-500">{change.detail}</div></div>
                </div>
                <Badge tone={change.status === 'tested' ? 'green' : change.status === 'testing' ? 'cyan' : 'amber'}>{change.status}</Badge>
              </div>
              <div className="mt-2 flex flex-wrap items-center gap-1.5 pl-5">
                <span className="text-[9px] uppercase tracking-wide text-slate-600">queued for testing</span>
                {change.endpoints.map((path) => <code key={path} className="rounded bg-white/[0.04] px-1.5 py-0.5 font-mono text-[9px] text-cyan-200/80">{path}</code>)}
              </div>
              <div className="mt-2 pl-5 font-mono text-[9px] text-slate-600">{change.id} · {change.source} · {timeAgo(change.createdAt)}</div>
            </div>
          ))}
          {!state.changes.length && <div className="py-12 text-center text-[11px] text-slate-600">No changes detected yet.</div>}
        </div>
      </Panel>
    </div>
  );
}
