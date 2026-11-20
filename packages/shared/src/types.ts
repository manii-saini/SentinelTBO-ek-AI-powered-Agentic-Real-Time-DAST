export type Agency = 'A' | 'B';
export type Role = 'agent' | 'sub-agent' | 'admin';

export type StageId =
  | 'detect'
  | 'recon'
  | 'inventory'
  | 'plan'
  | 'execute'
  | 'verify'
  | 'triage'
  | 'report'
  | 'retest';

export type StageStatus = 'idle' | 'running' | 'done' | 'blocked' | 'error';

export interface StageState {
  id: StageId;
  label: string;
  agent: string;
  status: StageStatus;
  detail: string;
  startedAt?: number;
  finishedAt?: number;
  count?: number;
}

export type TriggerKind =
  | 'deploy'
  | 'bundle-diff'
  | 'subdomain'
  | 'traffic-anomaly';

export interface ChangeEvent {
  id: string;
  kind: TriggerKind;
  title: string;
  detail: string;
  source: string;
  createdAt: number;
  endpoints: string[];
  status: 'queued' | 'testing' | 'tested';
}

export type InventoryStatus = 'active' | 'zombie' | 'shadow';

export interface ApiParam {
  name: string;
  location: 'path' | 'query' | 'body' | 'header';
  type: string;
  sensitive?: boolean;
  controllable?: boolean;
}

export interface Endpoint {
  id: string;
  method: string;
  path: string;
  host: string;
  source: 'crawl' | 'har' | 'bundle' | 'gateway' | 'hidden-probe' | 'ct-log' | 'ci';
  status: InventoryStatus;
  roles: Role[];
  params: ApiParam[];
  authRequired: boolean;
  dataExposed: string[];
  businessContext: string[];
  flow: string;
  lastRealTraffic: number | null;
  hits30d: number;
  hits90d: number;
  windowHits?: number;
  vulnerableToVersion: string | null;
  owner: string;
  recommendation: 'decommission' | 'restrict' | 'update' | 'monitor';
  discoveredAt: number;
}

export interface KnowledgeNode {
  id: string;
  kind: 'endpoint' | 'param' | 'role' | 'flow' | 'asset';
  label: string;
  data: Record<string, unknown>;
}

export interface KnowledgeEdge {
  id: string;
  source: string;
  target: string;
  label: string;
}

export interface KnowledgeGraph {
  nodes: KnowledgeNode[];
  edges: KnowledgeEdge[];
}

export type TestClass =
  | 'access-control'
  | 'business-logic'
  | 'auth-session'
  | 'injection'
  | 'api-hygiene'
  | 'data-exposure'
  | 'ssrf-open-redirect';

export interface PlannedTest {
  id: string;
  endpointId: string;
  endpoint: string;
  method: string;
  testClass: TestClass;
  name: string;
  reasoning: string;
  params: string[];
  roles: Role[];
  risk: 'low' | 'medium' | 'high';
  needsApproval: boolean;
  executor: string;
  status: 'planned' | 'approved' | 'running' | 'done' | 'rejected' | 'skipped';
}

export interface ProofExchange {
  label: string;
  request: {
    method: string;
    url: string;
    headers: Record<string, string>;
    body?: string;
  };
  response: {
    status: number;
    body: string;
    timingMs: number;
  };
}

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface Finding {
  id: string;
  key: string;
  title: string;
  endpointId: string;
  endpoint: string;
  testClass: TestClass;
  severity: Severity;
  score: number;
  scoreExplanation: string;
  cwe: string;
  owasp: string;
  owner: string;
  status: 'open' | 'approved' | 'still-vulnerable' | 'closed' | 'false-positive';
  createdAt: number;
  evidence: ProofExchange[];
  impact: string;
  fix: string;
  requestsSent: number;
  rootCause: string;
  retest?: RetestRecord;
  ticketId?: string;
}

export interface RetestRecord {
  at: number;
  result: 'closed' | 'still-vulnerable';
  before: ProofExchange[];
  after: ProofExchange[];
}

export interface ApprovalRequest {
  id: string;
  kind: 'test' | 'finding';
  refId: string;
  title: string;
  reason: string;
  risk: 'medium' | 'high';
  createdAt: number;
  status: 'pending' | 'approved' | 'rejected' | 'modified';
  modifiedPlan?: Partial<PlannedTest>;
}

export interface AuditRecord {
  id: string;
  seq: number;
  at: number;
  runId: string;
  method: string;
  url: string;
  host: string;
  role: string;
  agency: string;
  status: number;
  timingMs: number;
  bytes: number;
  blocked: boolean;
  blockReason?: string;
  testId?: string;
  findingId?: string;
  bodyHash: string;
  prevHash: string;
  hash: string;
  replay: {
    method: string;
    url: string;
    headers: Record<string, string>;
    body?: string;
  };
}

export interface Ticket {
  id: string;
  findingId: string;
  title: string;
  markdown: string;
  createdAt: number;
  destination: 'mock-jira' | 'mock-teams' | 'webhook';
  sent: boolean;
  sentAt?: number;
}

export interface HealthSample {
  at: number;
  host: string;
  latencyMs: number;
  errorRate: number;
  action: 'normal' | 'backoff' | 'pause';
}

export type EventLevel = 'info' | 'success' | 'warn' | 'error';

export interface AgentEvent {
  id: string;
  at: number;
  runId: string;
  stage: StageId | 'system';
  level: EventLevel;
  message: string;
  data?: Record<string, unknown>;
}

export interface Counters {
  endpoints: number;
  findings: number;
  confirmed: number;
  falsePositivesDropped: number;
  requestsSent: number;
  blocked: number;
  deployToVerifiedMs: number | null;
}

export interface SafetyConfig {
  allowlist: string[];
  rateLimit: number;
  burst: number;
  healthPauseThreshold: number;
  healthBackoffThreshold: number;
  killSwitch: boolean;
  requireApprovalForDestructive: boolean;
  testCredentials: Record<string, { agency: Agency; role: Role; token: string }>;
}

export interface OwnershipEntry {
  pathPrefix: string;
  owner: string;
  team: string;
  slack: string;
}

export interface RunSummary {
  runId: string;
  startedAt: number;
  finishedAt?: number;
  mode: 'full' | 'demo';
  changeId?: string;
  stages: StageState[];
}
