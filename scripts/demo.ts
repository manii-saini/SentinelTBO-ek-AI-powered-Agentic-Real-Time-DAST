import { spawn, type ChildProcess } from 'node:child_process';
import { resolve } from 'node:path';

const tsx = resolve(process.cwd(), 'node_modules/.bin/tsx');
const children: ChildProcess[] = [];
const keep = process.argv.includes('--keep');

async function up(url: string): Promise<boolean> {
  try {
    const res = await fetch(url, { signal: AbortSignal.timeout(1200) });
    return res.ok;
  } catch { return false; }
}

async function waitFor(url: string, label: string, timeoutMs = 15000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    if (await up(url)) { console.log(`  ✓ ${label} ready`); return; }
    await new Promise((r) => setTimeout(r, 300));
  }
  throw new Error(`${label} did not start in time`);
}

function launch(script: string, label: string, env: Record<string, string>) {
  const child = spawn(tsx, [script], { env: { ...process.env, ...env }, stdio: ['ignore', 'pipe', 'pipe'] });
  child.stderr?.on('data', (d: Buffer) => process.stderr.write(`[${label}] ${d}`));
  children.push(child);
}

async function main() {
  console.log('SentinelTBO scripted demo — synthetic staging target only');
  if (!(await up('http://127.0.0.1:4000/health'))) launch(resolve(process.cwd(), 'apps/mock/src/server.ts'), 'mock', {});
  if (!(await up('http://127.0.0.1:3001/api/health'))) launch(resolve(process.cwd(), 'apps/api/src/server.ts'), 'api', {});
  await waitFor('http://127.0.0.1:4000/health', 'mock platform');
  await waitFor('http://127.0.0.1:3001/api/health', 'control plane');

  const started = Date.now();
  const stream = await fetch('http://127.0.0.1:3001/api/events/stream');
  const reader = stream.body?.getReader();
  if (!reader) throw new Error('SSE stream unavailable');
  const response = await fetch('http://127.0.0.1:3001/api/demo', { method: 'POST' });
  if (!response.ok) throw new Error(`demo start failed: ${await response.text()}`);
  const decoder = new TextDecoder();
  let buffer = '';
  let done = false;

  while (!done) {
    const { value, done: closed } = await reader.read();
    if (closed) break;
    buffer += decoder.decode(value, { stream: true });
    const chunks = buffer.split('\n\n');
    buffer = chunks.pop() ?? '';
    for (const chunk of chunks) {
      const line = chunk.split('\n').find((l) => l.startsWith('data: '));
      if (!line) continue;
      const event = JSON.parse(line.slice(6)) as { level: string; stage: string; message?: string };
      if (!event.message) continue;
      const icon = event.level === 'error' ? '×' : event.level === 'warn' ? '!' : event.level === 'success' ? '✓' : '·';
      console.log(`${icon} [${event.stage}] ${event.message}`);
      if (event.message.startsWith('Run complete')) done = true;
    }
  }

  const state = await (await fetch('http://127.0.0.1:3001/api/state')).json() as {
    counters: { confirmed: number; falsePositivesDropped: number; requestsSent: number; deployToVerifiedMs: number | null };
  };
  console.log(`\nDone in ${((Date.now() - started) / 1000).toFixed(1)}s — ${state.counters.confirmed} confirmed findings, ${state.counters.falsePositivesDropped} false positives dropped, ${state.counters.requestsSent} logged requests.`);
  console.log(`Deploy → verified: ${((state.counters.deployToVerifiedMs ?? 0) / 1000).toFixed(1)}s`);
  if (keep) console.log('Servers left running. Open http://127.0.0.1:5173 for the UI.');
  else { children.forEach((c) => c.kill('SIGTERM')); console.log('Demo servers stopped. Run `npm run dev` for the full UI.'); }
}

main().catch((error) => { console.error(error); children.forEach((c) => c.kill('SIGTERM')); process.exitCode = 1; });
