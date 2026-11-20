import { Activity, AlertTriangle, ArrowRight, Check, Clock, Rocket, ShieldCheck, Zap } from 'lucide-react';
import { Area, AreaChart, ResponsiveContainer, Tooltip } from 'recharts';
import type { StageState } from '../lib/types';
import type { Sentinel } from '../lib/api';
import { duration, timeAgo } from '../lib/utils';
import { Badge, Button, Dot, Panel, Stat } from '../components/ui';

const toneFor = (status: StageState['status']) => status === 'done' ? 'green' : status === 'running' ? 'cyan' : status === 'error' ? 'red' : status === 'blocked' ? 'amber' : 'slate';

export function MissionControl({ sentinel }: { sentinel: Sentinel }) {
  const { state, events, post } = sentinel;
  if (!state) return null;
  const health = state.health;
  const running = state.stages.find((s) => s.status === 'running');
  const healthy = (state.healthNow?.errorRate ?? 0) < 0.25 && !state.safety.killSwitch;

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-6">
        <Stat label="Endpoints mapped" value={state.counters.endpoints} hint="inferred + probed" />
        <Stat label="Findings" value={state.counters.findings} hint="deduplicated" tone="amber" />
        <Stat label="Confirmed" value={state.counters.confirmed} hint="verified 2× + control" tone="red" />
        <Stat label="False positives dropped" value={state.counters.falsePositivesDropped} hint="verifier rejections" tone="green" />
        <Stat label="Requests sent" value={state.counters.requestsSent} hint={`${state.counters.blocked} blocked & logged`} />
        <div className="panel relative overflow-hidden px-4 py-3">
          <div className="flex items-center justify-between"><span className="label">Deploy → verified</span><Clock size={13} className="text-cyan-400" /></div>
          <div className="num mt-1.5 text-2xl font-semibold text-cyan-300">{duration(state.counters.deployToVerifiedMs)}</div>
          <div className="mt-1 text-[10px] text-slate-500">last deploy-triggered run</div>
          {state.running && <div className="absolute inset-x-0 bottom-0 h-0.5 overflow-hidden bg-cyan-400/10"><div className="h-full w-1/3 animate-scan bg-cyan-400" /></div>}
        </div>
      </div>

      <Panel title="Autonomous agent loop" subtitle={running ? `${running.label} in progress — ${running.detail}` : 'idle — fire a change or press Demo to start'} right={<div className="flex gap-2">
        <Button variant="danger" onClick={() => void post('/api/reset')}>Reset</Button>
        <Button variant="primary" onClick={() => void post('/api/triggers/deploy', { mode: 'demo', autoApprove: true })} disabled={state.running}><Rocket size={12} /> Deploy v2.1</Button>
      </div>} bodyClass="p-3">
        <div className="flex flex-wrap items-stretch gap-1.5">
          {state.stages.map((stage, i) => (
            <div key={stage.id} className="flex flex-1 items-center gap-1.5">
              <div className="min-w-[104px] flex-1 rounded border border-white/5 bg-ink-950/60 px-2.5 py-2">
                <div className="flex items-center gap-1.5">
                  <Dot tone={toneFor(stage.status)} pulse={stage.status === 'running'} />
                  <span className="truncate text-[10px] font-semibold text-slate-300">{stage.label}</span>
                </div>
                <div className="mt-1 truncate font-mono text-[9px] text-slate-600">{stage.agent}</div>
                <div className="mt-1.5 flex items-center gap-1 text-[9px] text-slate-500">
                  {stage.status === 'done' ? <Check size={10} className="text-emerald-400" /> : stage.status === 'running' ? <Zap size={10} className="text-cyan-400" /> : null}
                  <span className="truncate">{stage.status === 'idle' ? 'waiting' : stage.detail}</span>
                </div>
              </div>
              {i < state.stages.length - 1 && <ArrowRight size={12} className="shrink-0 text-slate-700" />}
            </div>
          ))}
        </div>
      </Panel>

      <div className="grid gap-4 lg:grid-cols-3">
        <Panel title="Live event feed" subtitle="SSE stream from every agent" className="lg:col-span-2" bodyClass="p-0">
          <div className="max-h-[420px] overflow-y-auto">
            {events.slice(0, 80).map((event) => (
              <div key={event.id} className="flex items-start gap-3 border-b border-white/[0.03] px-4 py-2 hover:bg-white/[0.02]">
                <span className="num w-16 shrink-0 pt-0.5 text-[10px] text-slate-600">{new Date(event.at).toLocaleTimeString('en-GB', { hour12: false })}</span>
                <Badge tone={event.level === 'error' ? 'red' : event.level === 'warn' ? 'amber' : event.level === 'success' ? 'green' : 'slate'} className="w-16 shrink-0 justify-center">{event.stage}</Badge>
                <span className={event.level === 'error' ? 'text-rose-300' : event.level === 'warn' ? 'text-amber-200' : 'text-slate-300'}>{event.message}</span>
              </div>
            ))}
          </div>
        </Panel>

        <div className="space-y-4">
          <Panel title="Safety layer health" right={<Badge tone={healthy ? 'green' : 'red'}><ShieldCheck size={11} /> {healthy ? 'OPERATIONAL' : state.safety.killSwitch ? 'KILLED' : 'DEGRADED'}</Badge>}>
            <div className="space-y-2 text-[11px]">
              <Row label="Target host" value={state.safety.allowlist.join(', ')} />
              <Row label="Rate limit" value={`${state.safety.rateLimit} req/s · burst ${state.safety.burst}`} />
              <Row label="Avg latency" value={`${Math.round(state.healthNow?.latencyMs ?? 0)} ms`} />
              <Row label="Error rate" value={`${((state.healthNow?.errorRate ?? 0) * 100).toFixed(1)}%`} />
              <Row label="Approval gate" value={state.safety.requireApprovalForDestructive ? 'enforced' : 'disabled'} />
              <Row label="Last request" value={timeAgo(state.audit[0]?.at)} />
            </div>
            <div className="mt-3 h-16">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={health.map((h) => ({ t: h.at, l: h.latencyMs }))}>
                  <defs><linearGradient id="latency" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#22d3ee" stopOpacity={0.4} /><stop offset="100%" stopColor="#22d3ee" stopOpacity={0} /></linearGradient></defs>
                  <Tooltip contentStyle={{ background: '#0b1118', border: '1px solid #1d2a37', fontSize: 10 }} labelFormatter={(v) => timeAgo(Number(v))} />
                  <Area type="monotone" dataKey="l" stroke="#22d3ee" fill="url(#latency)" strokeWidth={1.5} isAnimationActive={false} />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </Panel>

          <Panel title="Latest run">
            {state.runs[0] ? <div className="space-y-2">
              <Row label="Run id" value={<span className="num">{state.runs[0].runId}</span>} />
              <Row label="Mode" value={state.runs[0].mode} />
              <Row label="Started" value={timeAgo(state.runs[0].startedAt)} />
              <Row label="Duration" value={duration(state.runs[0].finishedAt ? state.runs[0].finishedAt - state.runs[0].startedAt : null)} />
              <Row label="Stages done" value={`${state.runs[0].stages.filter((s) => s.status === 'done').length}/9`} />
            </div> : <div className="py-6 text-center text-[11px] text-slate-600">No runs yet — press Demo</div>}
          </Panel>

          <div className="flex gap-2 rounded-lg border border-amber-400/15 bg-amber-400/[0.04] p-3 text-[10px] text-amber-200/80">
            <AlertTriangle size={14} className="mt-0.5 shrink-0" />
            <span>All traffic targets the bundled staging mock. Synthetic accounts only; every request is audited and replayable.</span>
          </div>
        </div>
      </div>
    </div>
  );
}

function Row({ label, value }: { label: string; value: React.ReactNode }) {
  return <div className="flex items-center justify-between gap-3"><span className="text-slate-500">{label}</span><span className="truncate text-right num text-slate-300">{value}</span></div>;
}
