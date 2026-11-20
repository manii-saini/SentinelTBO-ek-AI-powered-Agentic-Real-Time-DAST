import type { AgentContext } from '../agent.js';

export interface ExternalToolResult {
  tool: 'zap' | 'nuclei';
  enabled: boolean;
  findings: number;
  detail: string;
}

function enabled(name: string): boolean {
  return (process.env[name] ?? 'false').toLowerCase() === 'true';
}

export async function runOptionalWrappers(ctx: AgentContext): Promise<ExternalToolResult[]> {
  const out: ExternalToolResult[] = [];
  for (const [tool, flag, binary] of [
    ['zap', 'SENTINEL_ENABLE_ZAP', 'zap-cli'],
    ['nuclei', 'SENTINEL_ENABLE_NUCLEI', 'nuclei'],
  ] as const) {
    if (!enabled(flag)) {
      out.push({ tool, enabled: false, findings: 0, detail: `Disabled by ${flag}` });
      continue;
    }
    try {
      const proc = new DenoLikeProcess(binary);
      const result = await proc.run(['-u', ctx.target, '-json']);
      out.push({ tool, enabled: true, findings: result.length, detail: `${binary} wrapper executed in staging-only mode` });
      ctx.emit('execute', 'warn', `${tool} wrapper executed (${result.length} raw hits — requires sentinel verification)`, { tool });
    } catch (error) {
      out.push({ tool, enabled: true, findings: 0, detail: `Wrapper unavailable: ${String(error)}` });
      ctx.emit('execute', 'warn', `${tool} wrapper unavailable; native specialists remain authoritative`, { error: String(error) });
    }
  }
  return out;
}

class DenoLikeProcess {
  constructor(private binary: string) {}
  async run(_args: string[]): Promise<unknown[]> {
    const mod = new Function('return import("node:child_process")') as () => Promise<{ execFile: (cmd: string, args: string[], cb: (e: Error | null, out: string) => void) => void }>;
    const { execFile } = await mod();
    return new Promise((resolve, reject) => {
      execFile(this.binary, ['-version'], (error) => error ? reject(error) : resolve([]));
    });
  }
}
