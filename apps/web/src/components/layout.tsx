import type { ReactNode } from 'react';
import {
  Activity, ClipboardCheck, Crosshair, FileWarning, GitBranch, Play,
  Radio, RotateCcw, ScrollText, ShieldCheck, Siren, Table2,
} from 'lucide-react';
import type { Sentinel } from '../lib/api';
import { cn } from '../lib/utils';
import { Badge, Button, Dot } from './ui';

export const NAV = [
  { id: 'mission', label: 'Mission Control', icon: Activity, group: 'OPERATE' },
  { id: 'changes', label: 'Change Detection', icon: Radio, group: 'OPERATE' },
  { id: 'graph', label: 'Knowledge Graph', icon: GitBranch, group: 'UNDERSTAND' },
  { id: 'inventory', label: 'API Inventory', icon: Table2, group: 'UNDERSTAND' },
  { id: 'planner', label: 'Attack Planner', icon: Crosshair, group: 'TEST' },
  { id: 'execution', label: 'Execution & Safety', icon: Siren, group: 'TEST' },
  { id: 'approvals', label: 'Approval Queue', icon: ClipboardCheck, group: 'TEST' },
  { id: 'findings', label: 'Findings', icon: FileWarning, group: 'DECIDE' },
  { id: 'reports', label: 'Reports & Tickets', icon: ScrollText, group: 'DECIDE' },
  { id: 'retest', label: 'Retest', icon: RotateCcw, group: 'DECIDE' },
  { id: 'rules', label: 'Rules of Engagement', icon: ShieldCheck, group: 'GOVERN' },
] as const;

export type PageId = typeof NAV[number]['id'];

export function Layout({ page, setPage, sentinel, children }: {
  page: PageId; setPage: (p: PageId) => void; sentinel: Sentinel; children: ReactNode;
}) {
  const { state, connected, post } = sentinel;
  const kill = state?.safety.killSwitch ?? false;
  const groups = [...new Set(NAV.map((n) => n.group))];
  const title = NAV.find((n) => n.id === page)?.label ?? 'Mission Control';

  return (
    <div className="flex h-full min-h-screen bg-ink-950 grid-bg">
      <aside className="flex w-[224px] shrink-0 flex-col border-r border-white/5 bg-ink-900/90 backdrop-blur">
        <div className="flex h-16 items-center gap-2.5 border-b border-white/5 px-4">
          <div className="relative flex h-8 w-8 items-center justify-center rounded bg-cyan-400/10 text-cyan-300 ring-1 ring-cyan-400/30">
            <ShieldCheck size={17} />
            <span className="absolute -right-0.5 -top-0.5 h-1.5 w-1.5 rounded-full bg-emerald-400" />
          </div>
          <div>
            <div className="text-sm font-bold tracking-tight text-slate-100">SENTINEL<span className="text-cyan-400">TBO</span></div>
            <div className="text-[9px] uppercase tracking-[0.18em] text-slate-500">agentic dast control plane</div>
          </div>
        </div>
        <nav className="flex-1 overflow-y-auto py-3">
          {groups.map((group) => (
            <div key={group} className="mb-3">
              <div className="label px-4 pb-1.5">{group}</div>
              {NAV.filter((n) => n.group === group).map(({ id, label, icon: Icon }) => (
                <button key={id} onClick={() => setPage(id)} className={cn('group flex w-full items-center gap-2.5 border-l-2 px-4 py-2 text-left text-[11.5px] transition-colors', page === id ? 'border-cyan-400 bg-cyan-400/[0.07] text-cyan-200' : 'border-transparent text-slate-400 hover:bg-white/[0.03] hover:text-slate-200')}>
                  <Icon size={14} className={page === id ? 'text-cyan-300' : 'text-slate-500 group-hover:text-slate-400'} />
                  <span className="truncate">{label}</span>
                  {id === 'approvals' && !!state?.approvals.filter((a) => a.status === 'pending').length && (
                    <span className="ml-auto rounded bg-amber-400/15 px-1 num text-[9px] text-amber-300">{state.approvals.filter((a) => a.status === 'pending').length}</span>
                  )}
                </button>
              ))}
            </div>
          ))}
        </nav>
        <button onClick={() => setPage('rules')} className="m-3 flex items-center gap-2 rounded border border-emerald-400/20 bg-emerald-400/[0.06] px-2.5 py-2 text-left">
          <ShieldCheck size={14} className="shrink-0 text-emerald-400" />
          <div><div className="text-[10px] font-semibold text-emerald-300">RULES OF ENGAGEMENT</div><div className="text-[9px] text-slate-500">staging only · enforced in code</div></div>
        </button>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex h-16 shrink-0 items-center justify-between border-b border-white/5 bg-ink-950/80 px-6 backdrop-blur">
          <div>
            <h1 className="text-base font-semibold tracking-tight text-slate-100">{title}</h1>
            <div className="mt-0.5 flex items-center gap-2 text-[10px] text-slate-500">
              <span className="num">{state?.target ?? 'connecting…'}</span>
              <span>·</span><span>{state?.mode ?? '—'}</span>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Badge tone={connected ? 'green' : 'red'}><Dot tone={connected ? 'green' : 'red'} pulse={!connected} /> {connected ? 'SSE LIVE' : 'OFFLINE'}</Badge>
            <Button onClick={() => void post('/api/run', { mode: 'full' })} disabled={state?.running}><Play size={12} /> Run loop</Button>
            <Button variant="primary" onClick={() => void post('/api/demo')} disabled={state?.running}>Demo</Button>
            <Button variant={kill ? 'danger' : 'ghost'} onClick={() => void post('/api/safety', { killSwitch: !kill }, 'PUT')}><Siren size={12} /> {kill ? 'KILL SWITCH ON' : 'Kill switch'}</Button>
          </div>
        </header>
        <main className="min-h-0 flex-1 overflow-y-auto p-5">{children}</main>
      </div>
    </div>
  );
}
