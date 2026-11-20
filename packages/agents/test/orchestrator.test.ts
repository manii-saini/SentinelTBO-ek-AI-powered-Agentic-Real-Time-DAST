import assert from 'node:assert/strict';
import { spawn, type ChildProcess } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';

const PORT = 4100;
const dir = mkdtempSync(join(tmpdir(), 'sentinel-e2e-'));
process.env.MOCK_PORT = String(PORT);
process.env.SENTINEL_TARGET = `http://127.0.0.1:${PORT}`;
process.env.SENTINEL_ALLOWLIST = `127.0.0.1:${PORT}`;
process.env.SENTINEL_DB = join(dir, 'e2e.db');
process.env.SENTINEL_LLM_PROVIDER = 'mock';

const { Orchestrator } = await import('../src/orchestrator.js');

async function waitForMock() {
  for (let i = 0; i < 60; i++) {
    try {
      const res = await fetch(`http://127.0.0.1:${PORT}/health`, { signal: AbortSignal.timeout(1000) });
      if (res.ok) return;
    } catch { /* retry */ }
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error('mock platform did not start');
}

test('full agent loop discovers, verifies, triages and retests planted vulnerabilities', { timeout: 180_000 }, async () => {
  const mock: ChildProcess = spawn(resolve(process.cwd(), 'node_modules/.bin/tsx'), [resolve(process.cwd(), 'apps/mock/src/server.ts')], {
    env: { ...process.env, MOCK_PORT: String(PORT) }, stdio: 'ignore',
  });
  const orchestrator = new Orchestrator();
  try {
    await waitForMock();
    const run = await orchestrator.runDemo();
    const state = orchestrator.getState();

    assert.equal(run.mode, 'demo');
    assert.equal(run.stages.length, 9);
    assert.ok(run.stages.every((s) => s.status === 'done'));
    assert.ok(state.endpoints.length >= 12, `expected discovered endpoints, got ${state.endpoints.length}`);
    assert.ok(state.endpoints.some((e) => e.path === '/v1/bookings' && e.status === 'zombie'));
    assert.ok(state.endpoints.some((e) => e.path === '/internal/debug' && e.status === 'shadow'));

    const confirmed = state.findings.filter((f) => f.status !== 'false-positive' && f.status !== 'closed');
    const roots = confirmed.map((f) => f.rootCause);
    for (const expected of [
      'booking-idor', 'client-controlled-fare', 'mass-assignment-role', 'cancel-rebook-double-refund',
      'coupon-replay', 'shadow-debug-pii', 'supplier-webhook-ssrf', 'v21-coupon-stack',
    ]) {
      assert.ok(roots.includes(expected), `missing planted vulnerability: ${expected}`);
    }
    assert.ok(state.findings.some((f) => f.status === 'false-positive'), 'expected dropped false positives');
    assert.equal(state.tickets.length, confirmed.length);
    assert.ok(state.approvals.length > 0);
    assert.ok(state.counters.requestsSent > 60);
    assert.ok(state.counters.deployToVerifiedMs !== null);
    assert.ok(state.audit.every((a) => a.hash && a.prevHash));
    assert.ok(state.graph.nodes.length > 20);

    const blocked = await orchestrator.http.send({
      method: 'GET', url: 'https://production.travel.example/api/bookings',
      headers: { 'x-sentinel-synthetic': 'true', authorization: 'Bearer test-agent-a' },
    });
    assert.equal(blocked.blocked, true);
    assert.equal(orchestrator.store.listAudit({ blockedOnly: true })[0].blockReason?.includes('Out of scope'), true);

    const idor = confirmed.find((f) => f.rootCause === 'booking-idor')!;
    const retested = await orchestrator.retest(idor.id);
    assert.equal(retested?.status, 'closed');
    assert.equal(retested?.retest?.result, 'closed');
  } finally {
    orchestrator.store.close();
    mock.kill('SIGTERM');
    await new Promise((r) => setTimeout(r, 150));
    rmSync(dir, { recursive: true, force: true });
  }
});
