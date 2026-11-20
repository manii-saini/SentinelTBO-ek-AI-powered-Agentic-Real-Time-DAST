import type {
  AgentEvent, ApprovalRequest, AuditRecord, ChangeEvent, Counters, Endpoint, Finding,
  HealthSample, KnowledgeEdge, KnowledgeNode, PlannedTest, RunSummary, SafetyConfig, StageState, Ticket,
} from '@sentinel/shared';

export interface SentinelState {
  target: string;
  mode: string;
  llm: { provider: string; model: string };
  running: boolean;
  stages: StageState[];
  counters: Counters;
  events: AgentEvent[];
  changes: ChangeEvent[];
  endpoints: Endpoint[];
  graph: { nodes: KnowledgeNode[]; edges: KnowledgeEdge[] };
  tests: PlannedTest[];
  findings: Finding[];
  approvals: ApprovalRequest[];
  tickets: Ticket[];
  audit: AuditRecord[];
  health: HealthSample[];
  runs: RunSummary[];
  safety: SafetyConfig;
  healthNow: HealthSample | null;
  techniques: { name: string; detail: string }[];
  webhookConfig: { url?: string };
}

export type { AgentEvent, ApprovalRequest, AuditRecord, ChangeEvent, Endpoint, Finding, HealthSample, KnowledgeEdge, KnowledgeNode, PlannedTest, RunSummary, StageState, Ticket };
