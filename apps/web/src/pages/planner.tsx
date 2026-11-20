import { Crosshair, LockKeyhole, Sparkles } from 'lucide-react';
import { TEST_CLASS_LABEL } from '@sentinel/shared';
import type { TestClass } from '@sentinel/shared';
import type { Sentinel } from '../lib/api';
import { Badge, Empty, Panel } from '../components/ui';

export function AttackPlanner({ sentinel }: { sentinel: Sentinel }) {
  const { state } = sentinel;
  if (!state) return null;
  const classes = [...new Set(state.tests.map((t) => t.testClass))];
  return (
    <div className="space-y-4">
      <Panel title="Targeted attack plan" subtitle={`${state.tests.length} tests selected from parameters, roles and business context — no broad spraying`} right={<Badge tone="cyan"><Sparkles size={11} /> reasoning: {state.llm.provider}</Badge>}>
        {!state.tests.length ? <Empty title="No tests planned yet" detail="Run the agent loop to generate a targeted plan." /> : (
          <div className="grid gap-4 xl:grid-cols-2">
            {classes.map((testClass) => (
              <div key={testClass}>
                <div className="mb-2 flex items-center gap-2">
                  <Crosshair size={13} className="text-cyan-400" />
                  <span className="text-[11px] font-semibold uppercase tracking-wide text-slate-300">{TEST_CLASS_LABEL[testClass as TestClass]}</span>
                  <Badge>{state.tests.filter((t) => t.testClass === testClass).length}</Badge>
                </div>
                <div className="space-y-2">
                  {state.tests.filter((t) => t.testClass === testClass).map((test) => (
                    <div key={test.id} className="rounded border border-white/5 bg-ink-950/60 p-3">
                      <div className="flex items-start justify-between gap-2">
                        <div className="min-w-0"><div className="text-xs font-medium text-slate-200">{test.name}</div><div className="mt-0.5 font-mono text-[10px] text-cyan-300/80">{test.method} {test.endpoint}</div></div>
                        <div className="flex shrink-0 gap-1"><Badge tone={test.risk === 'high' ? 'red' : test.risk === 'medium' ? 'amber' : 'slate'}>{test.risk}</Badge><Badge tone={test.status === 'done' ? 'green' : test.needsApproval ? 'amber' : 'slate'}>{test.status}</Badge></div>
                      </div>
                      <p className="mt-2 text-[10px] leading-relaxed text-slate-400">{test.reasoning}</p>
                      <div className="mt-2 flex flex-wrap items-center gap-1.5 text-[9px] text-slate-500">
                        <span className="label mr-1">params</span>
                        {test.params.length ? test.params.map((p) => <code key={p} className="rounded bg-white/[0.04] px-1.5 py-0.5 text-cyan-200/70">{p}</code>) : <span>none</span>}
                        <span className="label ml-2">roles</span>
                        {test.roles.length ? test.roles.map((r) => <code key={r} className="rounded bg-white/[0.04] px-1.5 py-0.5 text-violet-200/70">{r}</code>) : <span>anonymous</span>}
                        {test.needsApproval && <span className="ml-auto flex items-center gap-1 text-amber-400"><LockKeyhole size={10} /> approval gate</span>}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        )}
      </Panel>
    </div>
  );
}
