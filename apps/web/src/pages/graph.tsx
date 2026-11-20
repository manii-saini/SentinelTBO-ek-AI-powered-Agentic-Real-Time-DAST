import { useMemo, useState } from 'react';
import { Handle, Position, ReactFlow, Background, Controls, type Node, type Edge, type NodeProps } from '@xyflow/react';
import { GitBranch, Info } from 'lucide-react';
import type { Sentinel } from '../lib/api';
import type { KnowledgeNode } from '../lib/types';
import { Badge, Panel, Table } from '../components/ui';

const kindColor: Record<string, string> = {
  endpoint: 'border-cyan-400/40 bg-cyan-500/10 text-cyan-200',
  param: 'border-amber-400/30 bg-amber-500/10 text-amber-200',
  role: 'border-violet-400/30 bg-violet-500/10 text-violet-200',
  flow: 'border-emerald-400/40 bg-emerald-500/10 text-emerald-200',
  asset: 'border-slate-500/30 bg-slate-500/10 text-slate-300',
};

function GraphNode({ data }: NodeProps) {
  const node = data as unknown as KnowledgeNode;
  return (
    <div className={`min-w-[110px] rounded border px-2 py-1.5 font-mono text-[10px] shadow-lg ${kindColor[node.kind] ?? kindColor.asset}`}>
      <Handle type="target" position={Position.Left} className="!h-1.5 !w-1.5 !border-0 !bg-slate-500" />
      <div className="text-[8px] uppercase tracking-wider opacity-60">{node.kind}</div>
      <div className="max-w-[180px] truncate">{node.label}</div>
      <Handle type="source" position={Position.Right} className="!h-1.5 !w-1.5 !border-0 !bg-slate-500" />
    </div>
  );
}
const nodeTypes = { sentinel: GraphNode };

export function KnowledgeGraph({ sentinel }: { sentinel: Sentinel }) {
  const { state } = sentinel;
  const [selected, setSelected] = useState<string | null>(null);
  const { nodes, edges } = useMemo(() => {
    if (!state) return { nodes: [] as Node[], edges: [] as Edge[] };
    const counts: Record<string, number> = {};
    const layout: Record<string, number> = { flow: 0, endpoint: 1, role: 2, param: 3, asset: 4 };
    const nodes: Node[] = state.graph.nodes.map((node) => {
      const col = layout[node.kind] ?? 4;
      const row = counts[node.kind] ?? 0;
      counts[node.kind] = row + 1;
      return {
        id: node.id,
        type: 'sentinel',
        position: { x: col * 300 + 40, y: row * 72 + 40 },
        data: node as unknown as Record<string, unknown>,
      };
    });
    const edges: Edge[] = state.graph.edges.map((edge) => ({
      id: edge.id, source: edge.source, target: edge.target, label: edge.label,
      animated: true, style: { stroke: '#2b4356', strokeWidth: 1 },
      labelStyle: { fill: '#64748b', fontSize: 9 }, labelBgStyle: { fill: '#0b1118' },
    }));
    return { nodes, edges };
  }, [state]);

  if (!state) return null;
  const node = state.graph.nodes.find((n) => n.id === selected);
  const endpoint = state.endpoints.find((e) => e.id === selected);

  return (
    <div className="grid gap-4 lg:grid-cols-4">
      <Panel title="App knowledge graph" subtitle="endpoints · params · roles · business flows" className="lg:col-span-3" bodyClass="p-0" right={<Badge tone="cyan"><GitBranch size={11} /> {state.graph.nodes.length} nodes / {state.graph.edges.length} edges</Badge>}>
        <div className="h-[620px] bg-ink-950">
          <ReactFlow nodes={nodes} edges={edges} nodeTypes={nodeTypes} onNodeClick={(_, n) => setSelected(n.id)} fitView fitViewOptions={{ padding: 0.15 }} minZoom={0.25} proOptions={{ hideAttribution: true }}>
            <Background color="#1d2a37" gap={24} size={1} />
            <Controls showInteractive={false} />
          </ReactFlow>
        </div>
      </Panel>
      <Panel title="Node inspector" subtitle={selected ?? 'click a node to inspect'}>
        {!node ? <div className="flex flex-col items-center gap-2 py-16 text-center text-[11px] text-slate-600"><Info size={20} /> Select a node to see params, roles and traffic.</div> : (
          <div className="space-y-4">
            <div><div className="label">Node</div><div className="mt-1 break-all font-mono text-xs text-cyan-200">{node.label}</div><Badge className="mt-2" tone={node.kind === 'endpoint' ? 'cyan' : node.kind === 'flow' ? 'green' : 'amber'}>{node.kind}</Badge></div>
            <div><div className="label">Metadata</div><pre className="mt-1 overflow-auto rounded bg-ink-950 p-2 font-mono text-[10px] text-slate-400">{JSON.stringify(node.data, null, 2)}</pre></div>
            {endpoint && <>
              <div><div className="label">Parameters</div><div className="mt-1 space-y-1">
                {endpoint.params.length ? endpoint.params.map((p) => <div key={p.name} className="flex items-center justify-between rounded bg-white/[0.03] px-2 py-1 text-[10px]"><span className="font-mono text-slate-300">{p.name}</span><span className="text-slate-500">{p.location} · {p.type}{p.controllable ? ' · controllable' : ''}</span></div>) : <div className="text-[10px] text-slate-600">none</div>}
              </div></div>
              <div><div className="label">Roles & traffic</div><div className="mt-1 text-[10px] text-slate-400">{endpoint.roles.join(', ') || 'unauthenticated'} · {endpoint.hits30d} hits/30d · last {endpoint.lastRealTraffic ? new Date(endpoint.lastRealTraffic).toLocaleDateString() : 'never'}</div></div>
            </>}
            {!endpoint && <Table headers={['Relation', 'Target']}>{state.graph.edges.filter((e) => e.source === node.id || e.target === node.id).slice(0, 8).map((edge) => <tr key={edge.id} className="text-[10px]"><td className="px-3 py-1.5 text-slate-500">{edge.label}</td><td className="px-3 py-1.5 font-mono text-slate-300">{edge.source === node.id ? edge.target : edge.source}</td></tr>)}</Table>}
          </div>
        )}
      </Panel>
    </div>
  );
}
