import { Download, Layers, Search } from 'lucide-react';
import { useState } from 'react';
import type { Sentinel } from '../lib/api';
import { timeAgo } from '../lib/utils';
import { Badge, Button, Input, Panel, Table, Tabs } from '../components/ui';

export function Inventory({ sentinel }: { sentinel: Sentinel }) {
  const { state, window, setWindow, api } = sentinel;
  const [filter, setFilter] = useState('');
  const [tab, setTab] = useState<'all' | 'active' | 'zombie' | 'shadow'>('all');
  if (!state) return null;
  const endpoints = state.endpoints.filter((e) => (tab === 'all' || e.status === tab) && (e.path.toLowerCase().includes(filter.toLowerCase()) || e.owner.toLowerCase().includes(filter.toLowerCase())));

  return (
    <div className="space-y-4">
      <Panel title="Inferred API inventory" subtitle="knowledge graph diffed against gateway traffic logs" right={<div className="flex items-center gap-2">
        <div className="flex overflow-hidden rounded border border-white/10">
          {([30, 90] as const).map((d) => <button key={d} onClick={() => setWindow(d)} className={`px-2.5 py-1 text-[10px] ${window === d ? 'bg-cyan-500/20 text-cyan-200' : 'text-slate-500 hover:text-slate-300'}`}>{d}d window</button>)}
        </div>
        <a href={`${api}/api/export/openapi`} download><Button variant="primary"><Download size={12} /> Export OpenAPI 3</Button></a>
      </div>}>
        <div className="mb-3 flex items-center gap-3">
          <div className="relative w-64"><Search size={12} className="absolute left-2 top-2.5 text-slate-600" /><Input value={filter} onChange={(e) => setFilter(e.target.value)} placeholder="Filter path or owner…" className="pl-7" /></div>
          <Tabs tabs={[
            { id: 'all' as const, label: 'All', count: state.endpoints.length },
            { id: 'active' as const, label: 'Active', count: state.endpoints.filter((e) => e.status === 'active').length },
            { id: 'zombie' as const, label: 'Zombie', count: state.endpoints.filter((e) => e.status === 'zombie').length },
            { id: 'shadow' as const, label: 'Shadow', count: state.endpoints.filter((e) => e.status === 'shadow').length },
          ]} active={tab} onChange={setTab} />
        </div>
        <Table headers={['Endpoint', 'State', 'Last real traffic', 'Auth', 'Data exposed', 'Vulns vs version', 'Likely owner', 'Recommendation']} dense>
          {endpoints.map((e) => (
            <tr key={e.id} className="hover:bg-white/[0.02]">
              <td className="px-3 py-2"><div className="font-mono text-[10px] text-slate-200"><span className="text-cyan-400">{e.method}</span> {e.path}</div><div className="text-[9px] text-slate-600">{e.source} · {e.windowHits ?? e.hits30d} hits/{window}d</div></td>
              <td className="px-3 py-2"><Badge tone={e.status === 'active' ? 'green' : e.status === 'zombie' ? 'amber' : 'red'}>{e.status}</Badge></td>
              <td className="num px-3 py-2 text-[10px] text-slate-400">{timeAgo(e.lastRealTraffic)}</td>
              <td className="px-3 py-2 text-[10px] text-slate-400">{e.authRequired ? e.roles.join('/') : 'none'}</td>
              <td className="px-3 py-2 text-[10px] text-slate-400">{e.dataExposed.join(', ') || '—'}</td>
              <td className="px-3 py-2 text-[10px] text-amber-300/80">{e.vulnerableToVersion ?? '—'}</td>
              <td className="px-3 py-2 text-[10px] text-slate-400">{e.owner}</td>
              <td className="px-3 py-2"><Badge tone={e.recommendation === 'decommission' ? 'red' : e.recommendation === 'restrict' ? 'amber' : e.recommendation === 'update' ? 'violet' : 'slate'}>{e.recommendation}</Badge></td>
            </tr>
          ))}
        </Table>
      </Panel>

      <Panel title="Discovery techniques" subtitle="how the inferred map is assembled and compared to real traffic" right={<Badge tone="cyan"><Layers size={11} /> {state.techniques.length} sources</Badge>}>
        <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
          {state.techniques.map((t) => <div key={t.name} className="rounded border border-white/5 bg-ink-950/60 p-3"><div className="text-[11px] font-medium text-slate-200">{t.name}</div><div className="mt-1 text-[10px] leading-relaxed text-slate-500">{t.detail}</div></div>)}
          <div className="rounded border border-cyan-400/15 bg-cyan-400/[0.04] p-3"><div className="text-[11px] font-medium text-cyan-200">Inference rule</div><div className="mt-1 text-[10px] leading-relaxed text-slate-400">No 90-day traffic → zombie. Undocumented live route → shadow. Traffic present → active.</div></div>
        </div>
      </Panel>
    </div>
  );
}
