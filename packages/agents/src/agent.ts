import type { AgentEvent, StageId } from '@sentinel/shared';
import type { LLM } from './llm.js';
import type { SafeHttpClient, SafetyLayer } from './safety.js';
import type { Store } from './store.js';

export interface AgentContext {
  store: Store;
  safety: SafetyLayer;
  http: SafeHttpClient;
  llm: LLM;
  target: string;
  runId: string;
  mode: 'full' | 'demo';
  autoApprove: boolean;
  approvalFor: (key: string) => string | undefined;
  emit: (stage: StageId | 'system', level: AgentEvent['level'], message: string, data?: Record<string, unknown>) => void;
}

export interface Agent<I, O> {
  readonly id: string;
  readonly name: string;
  run(input: I, ctx: AgentContext): Promise<O>;
}
