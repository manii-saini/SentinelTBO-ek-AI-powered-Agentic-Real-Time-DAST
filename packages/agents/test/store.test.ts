import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { Store } from '../src/store.js';

function fresh() {
  const dir = mkdtempSync(join(tmpdir(), 'sentinel-store-'));
  const store = new Store(join(dir, 'test.db'));
  return { store, cleanup: () => { store.close(); rmSync(dir, { recursive: true, force: true }); } };
}

test('store persists settings, runs, events and stages', () => {
  const { store, cleanup } = fresh();
  store.setSetting('scope', { allowlist: ['127.0.0.1:4000'] });
  assert.deepEqual(store.getSetting('scope', {}), { allowlist: ['127.0.0.1:4000'] });
  store.createRun({ runId: 'run_1', startedAt: 1, mode: 'demo', stages: [] });
  store.finishRun('run_1', [{ id: 'detect', label: 'Detect', agent: 'x', status: 'done', detail: '' }]);
  const run = store.getRun('run_1');
  assert.equal(run?.mode, 'demo');
  assert.equal(run?.stages[0].status, 'done');
  assert.ok(run?.finishedAt);
  store.addEvent({ id: 'e1', at: 2, runId: 'run_1', stage: 'detect', level: 'info', message: 'hello', data: { a: 1 } });
  assert.equal(store.listEvents()[0].message, 'hello');
  cleanup();
});

test('store computes counters and searches append-only audit log', () => {
  const { store, cleanup } = fresh();
  store.appendAudit({
    id: 'a1', seq: 1, at: 1, runId: 'r', method: 'GET', url: 'http://127.0.0.1:4000/api/search', host: '127.0.0.1:4000',
    role: 'agent', agency: 'A', status: 200, timingMs: 3, bytes: 10, blocked: false, bodyHash: 'x', prevHash: '0', hash: 'h',
    replay: { method: 'GET', url: 'http://127.0.0.1:4000/api/search', headers: {} },
  });
  store.appendAudit({
    id: 'a2', seq: 2, at: 2, runId: 'r', method: 'POST', url: 'https://evil.example/x', host: 'evil.example',
    role: 'agent', agency: 'A', status: 0, timingMs: 0, bytes: 0, blocked: true, blockReason: 'Out of scope',
    bodyHash: 'x', prevHash: 'h', hash: 'h2', replay: { method: 'POST', url: 'https://evil.example/x', headers: {} },
  });
  assert.equal(store.counters().requestsSent, 1);
  assert.equal(store.counters().blocked, 1);
  assert.equal(store.listAudit({ blockedOnly: true }).length, 1);
  assert.equal(store.listAudit({ search: 'evil.example' })[0].blockReason, 'Out of scope');
  cleanup();
});
