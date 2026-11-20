import { Ban, Download, Search, ShieldAlert, ShieldCheck } from 'lucide-react';
import { useMemo, useState } from 'react';
import { CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import type { Sentinel } from '../lib/api';
import { download, timeAgo } from '../lib/utils';
import { Badge, Button, Code, Input, Panel, Slider, Table, Tabs } from '../components/ui';

export function ExecutionConsole({ sentinel }: { sentinel: Sentinel }) {
  const { state, post, api } = sentinel;
  const [allowlist, setAllowlist] = useState('');
  const [rate, setRate] = useState<number | null>(null);
  const [search, setSearch] = useState('');
  const [tab, setTab] = useState<'all' | 'blocked'>('all');
  const [expanded, setExpanded] = useState<string | null>(null);

  const chart = useMemo(() => state?.health.map((h, i) => ({ i, latency: h.latencyMs, error: Math.round(h.errorRate * 100) })) ?? [], [state]);
  if (!state) return null;
  const rps = rate ?? state.safety.rateLimit;
  const hosts = allowlist || state.safety.allowlist.join('\n');
  const audit = state.audit.filter((a) => (tab === 'all' || a.blocked) && (!search || `${a.url} ${a.method} ${a.role}`.toLowerCase().includes(search.toLowerCase())));

  async function applySafety(patch: Record<string, unknown>) { await post('/api/safety', patch, 'PUT'); }

  return (
    <div className="space-y-4">
      <div className="grid gap-4 lg:grid-cols-3">
        <Panel title="Scope allowlist" subtitle="every outbound request is checked against this list" right={<Badge tone="green"><ShieldCheck size={11} /> enforced</Badge>}>
          <textarea value={hosts} onChange={(e) => setAllowlist(e.target.value)} spellCheck={false} className="h-24 w-full resize-none rounded border border-white/10 bg-ink-950 p-2 font-mono text-[10px] text-cyan-200 outline-none focus:border-cyan-400/50" />
          <div className="mt-2 flex items-center justify-between text-[10px] text-slate-500"><span>one host:port per line · no wildcards</span><Button variant="primary" onClick={() => void applySafety({ allowlist: hosts.split(/[\n,]/).map((s) => s.trim()).filter(Boolean) })}>Save scope</Button></div>
        </Panel>

        <Panel title="Rate limit & health response" subtitle="token bucket per host, auto-throttle on degradation">
          <div className="flex items-center justify-between"><span className="label">Requests / second</span><span className="num text-sm text-cyan-300">{rps}</span></div>
          <div className="mt-2"><Slider value={rps} min={1} max={60} onChange={(n) => setRate(n)} /></div>
          <div className="mt-3 flex gap-2"><Button onClick={() => void applySafety({ rateLimit: rps })}>Apply rate</Button><Button variant="danger" onClick={() => void applySafety({ killSwitch: !state.safety.killSwitch })}><Ban size={12} /> {state.safety.killSwitch ? 'Resume traffic' : 'Kill all traffic'}</Button></div>
          <div className="mt-3 space-y-1.5 text-[10px] text-slate-500">
            <div className="flex justify-between"><span>Health backoff threshold</span><span className="num text-amber-300">{(state.safety.healthBackoffThreshold * 100).toFixed(0)}% errors</span></div>
            <div className="flex justify-between"><span>Health pause threshold</span><span className="num text-rose-300">{(state.safety.healthPauseThreshold * 100).toFixed(0)}% errors</span></div>
            <div className="flex justify-between"><span>Current action</span><Badge tone={state.healthNow?.action === 'pause' ? 'red' : state.healthNow?.action === 'backoff' ? 'amber' : 'green'}>{state.healthNow?.action ?? 'normal'}</Badge></div>
          </div>
        </Panel>

        <Panel title="Test credential vault" subtitle="masked · two agencies × three roles" right={<Badge tone="cyan">synthetic only</Badge>}>
          <Table headers={['Account', 'Agency', 'Role', 'Token']} dense>
            {Object.entries(state.safety.testCredentials).map(([key, cred]) => (
              <tr key={key}><td className="px-3 py-1.5 font-mono text-[10px] text-slate-300">{key}</td><td className="px-3 py-1.5 text-[10px] text-slate-400">{cred.agency}</td><td className="px-3 py-1.5 text-[10px] text-slate-400">{cred.role}</td><td className="num px-3 py-1.5 text-[10px] text-slate-600">test-•••••{cred.token.slice(-3)}</td></tr>
            ))}
          </Table>
        </Panel>
      </div>

      <Panel title="Health monitor" subtitle="latency and error rate observed by the safety layer" className="lg:col-span-2" right={<Badge tone={state.healthNow && state.healthNow.latencyMs > 450 ? 'amber' : 'green'}>{Math.round(state.healthNow?.latencyMs ?? 0)} ms p-avg</Badge>}>
        <div className="h-48">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={chart}>
              <CartesianGrid stroke="#16222e" strokeDasharray="3 3" />
              <XAxis dataKey="i" hide /><YAxis yAxisId="left" stroke="#475569" fontSize={9} width={30} /><YAxis yAxisId="right" orientation="right" stroke="#475569" fontSize={9} width={28} />
              <Tooltip contentStyle={{ background: '#0b1118', border: '1px solid #1d2a37', fontSize: 10 }} />
              <Line yAxisId="left" type="monotone" dataKey="latency" stroke="#22d3ee" dot={false} strokeWidth={1.5} isAnimationActive={false} />
              <Line yAxisId="right" type="monotone" dataKey="error" stroke="#fb7185" dot={false} strokeWidth={1.5} isAnimationActive={false} />
            </LineChart>
          </ResponsiveContainer>
        </div>
        <div className="mt-1 flex gap-4 text-[9px] text-slate-500"><span className="text-cyan-300">— latency (ms)</span><span className="text-rose-300">— error rate (%)</span></div>
      </Panel>

      <Panel title="Replayable audit log" subtitle="append-only, hash-chained, every request including blocks" right={<div className="flex items-center gap-2">
        <a href={`${api}/api/export/audit`} download><Button><Download size={12} /> Export JSONL</Button></a>
      </div>}>
        <div className="mb-3 flex items-center gap-3">
          <div className="relative w-64"><Search size={12} className="absolute left-2 top-2.5 text-slate-600" /><Input className="pl-7" value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search URL, method, role…" /></div>
          <Tabs tabs={[{ id: 'all' as const, label: 'All requests' }, { id: 'blocked' as const, label: 'Blocked', count: state.counters.blocked }]} active={tab} onChange={setTab} />
          <span className="ml-auto text-[10px] text-slate-500">showing {audit.length} of {state.audit.length}</span>
        </div>
        <Table headers={['Seq', 'Time', 'Method / URL', 'Role', 'Status', 'Timing', 'Result', 'Replay']} dense>
          {audit.map((a) => (
            <tr key={a.id} className={a.blocked ? 'bg-rose-500/[0.06]' : 'hover:bg-white/[0.02]'}>
              <td className="num px-3 py-1.5 text-[10px] text-slate-600">{a.seq}</td>
              <td className="num px-3 py-1.5 text-[10px] text-slate-500">{timeAgo(a.at)}</td>
              <td className="px-3 py-1.5 font-mono text-[10px]"><span className="text-cyan-400">{a.method}</span> <span className={a.blocked ? 'text-rose-300' : 'text-slate-300'}>{a.url}</span></td>
              <td className="px-3 py-1.5 text-[10px] text-slate-400">{a.role}</td>
              <td className="num px-3 py-1.5 text-[10px] text-slate-400">{a.status || '—'}</td>
              <td className="num px-3 py-1.5 text-[10px] text-slate-500">{a.timingMs}ms</td>
              <td className="px-3 py-1.5">{a.blocked ? <Badge tone="red"><ShieldAlert size={10} /> BLOCKED</Badge> : <Badge tone="green">allowed</Badge>}</td>
              <td className="px-3 py-1.5"><Button onClick={() => setExpanded(expanded === a.id ? null : a.id)}>{expanded === a.id ? 'hide' : 'view'}</Button></td>
            </tr>
          ))}
        </Table>
        {expanded && (() => {
          const record = state.audit.find((a) => a.id === expanded);
          return record ? <div className="mt-3 space-y-2 rounded border border-white/5 bg-ink-950 p-3">
            <div className="flex gap-4 text-[10px] text-slate-500"><span>hash <span className="num text-cyan-300">{record.hash}</span></span><span>prev <span className="num text-slate-400">{record.prevHash}</span></span><span>{record.blockReason ?? 'allowed by safety layer'}</span></div>
            <Code>{JSON.stringify(record.replay, null, 2)}</Code>
          </div> : null;
        })()}
        <div className="mt-2 text-[9px] text-slate-600">Requests are stored with redacted bodies and a SHA-256 hash chain.</div>
      </Panel>
    </div>
  );
}
