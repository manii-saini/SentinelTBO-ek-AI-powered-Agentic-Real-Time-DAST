import { useEffect, useState } from 'react';
import { Layout, NAV, type PageId } from './components/layout';
import { useSentinel } from './lib/api';
import { MissionControl } from './pages/mission';
import { ChangeDetection } from './pages/changes';
import { KnowledgeGraph } from './pages/graph';
import { Inventory } from './pages/inventory';
import { AttackPlanner } from './pages/planner';
import { ExecutionConsole } from './pages/execution';
import { Approvals } from './pages/approvals';
import { Findings } from './pages/findings';
import { Reports } from './pages/reports';
import { Retest } from './pages/retest';
import { Rules } from './pages/rules';

function fromHash(): PageId {
  const hash = window.location.hash.replace('#', '') as PageId;
  return NAV.some((n) => n.id === hash) ? hash : 'mission';
}

export default function App() {
  const sentinel = useSentinel();
  const [page, setPageState] = useState<PageId>(fromHash);
  const setPage = (next: PageId) => { window.location.hash = next; setPageState(next); };

  useEffect(() => {
    const handler = () => setPageState(fromHash());
    window.addEventListener('hashchange', handler);
    return () => window.removeEventListener('hashchange', handler);
  }, []);

  const pages: Record<PageId, React.ReactNode> = {
    mission: <MissionControl sentinel={sentinel} />,
    changes: <ChangeDetection sentinel={sentinel} />,
    graph: <KnowledgeGraph sentinel={sentinel} />,
    inventory: <Inventory sentinel={sentinel} />,
    planner: <AttackPlanner sentinel={sentinel} />,
    execution: <ExecutionConsole sentinel={sentinel} />,
    approvals: <Approvals sentinel={sentinel} />,
    findings: <Findings sentinel={sentinel} />,
    reports: <Reports sentinel={sentinel} />,
    retest: <Retest sentinel={sentinel} />,
    rules: <Rules />,
  };

  return (
    <Layout page={page} setPage={setPage} sentinel={sentinel}>
      {!sentinel.state && <div className="panel p-8 text-center text-xs text-slate-500">Connecting to control plane… {sentinel.error && <span className="text-rose-400">({sentinel.error})</span>}</div>}
      {sentinel.state && pages[page]}
    </Layout>
  );
}
