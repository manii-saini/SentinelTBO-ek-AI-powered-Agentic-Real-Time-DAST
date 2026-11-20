import assert from 'node:assert/strict';
import test from 'node:test';
import { SafeHttpClient, SafetyLayer } from '../src/safety.js';

const baseHeaders = { 'x-sentinel-synthetic': 'true', authorization: 'Bearer test-agent-a' };

function client(safety: SafetyLayer, fetchImpl?: typeof fetch) {
  return new SafeHttpClient({
    safety,
    timeoutMs: 500,
    fetchImpl: fetchImpl ?? (async () => new Response('{"ok":true}', { status: 200 }) as Response),
  });
}

test('out-of-scope host is blocked and written to append-only audit', async () => {
  const safety = new SafetyLayer({ allowlist: ['127.0.0.1:4000'] });
  const audits: { url: string; blocked: boolean; blockReason?: string }[] = [];
  safety.onAudit((r) => audits.push(r));
  const res = await client(safety).send({ method: 'GET', url: 'https://production.travel.example/api/bookings', headers: baseHeaders });
  assert.equal(res.blocked, true);
  assert.equal(res.status, 0);
  assert.match(res.blockReason ?? '', /Out of scope/);
  assert.equal(audits.length, 1);
  assert.equal(audits[0].blocked, true);
  assert.match(audits[0].blockReason ?? '', /allowlist/);
});

test('missing synthetic marker or non-test credential is blocked', async () => {
  const safety = new SafetyLayer();
  const badMarker = await client(safety).send({ method: 'GET', url: 'http://127.0.0.1:4000/api/search', headers: { authorization: 'Bearer test-agent-a' } });
  assert.match(badMarker.blockReason ?? '', /synthetic-traffic marker/);
  const badToken = await client(safety).send({ method: 'GET', url: 'http://127.0.0.1:4000/api/search', headers: { ...baseHeaders, authorization: 'Bearer real-production-token' } });
  assert.match(badToken.blockReason ?? '', /approved synthetic test account/);
  assert.ok(safety.getHealth('127.0.0.1:4000'));
});

test('destructive methods require an approved request id', async () => {
  const safety = new SafetyLayer();
  let approved = false;
  safety.isApproved((id) => approved && id === 'apr_safe_1');
  const http = client(safety);
  const url = 'http://127.0.0.1:4000/api/refund';
  const blocked = await http.send({ method: 'POST', url, headers: { ...baseHeaders, 'x-sentinel-approval': 'apr_safe_1' }, body: '{}' });
  assert.match(blocked.blockReason ?? '', /approved request/);
  approved = true;
  const allowed = await http.send({ method: 'POST', url, headers: { ...baseHeaders, 'x-sentinel-approval': 'apr_safe_1' }, body: '{}' });
  assert.equal(allowed.blocked, false);
  assert.equal(allowed.status, 200);
});

test('non-destructive read on a refund path is allowed without approval', async () => {
  const safety = new SafetyLayer();
  const res = await client(safety).send({ method: 'GET', url: 'http://127.0.0.1:4000/api/refund/status', headers: baseHeaders });
  assert.equal(res.blocked, false);
});

test('per-host token bucket and kill switch enforce rate and hard stop', async () => {
  const safety = new SafetyLayer({ rateLimit: 1, burst: 1 });
  const first = safety.authorize({ method: 'GET', url: 'http://127.0.0.1:4000/api/search', headers: baseHeaders });
  const second = safety.authorize({ method: 'GET', url: 'http://127.0.0.1:4000/api/search', headers: baseHeaders });
  assert.equal(first.allowed, true);
  assert.ok(second.waitMs! > 0);
  const other = safety.authorize({ method: 'GET', url: 'http://localhost:4000/api/search', headers: baseHeaders });
  assert.equal(other.allowed, true);
  safety.setConfig({ killSwitch: true });
  const stopped = safety.authorize({ method: 'GET', url: 'http://127.0.0.1:4000/api/search', headers: baseHeaders });
  assert.match(stopped.reason ?? '', /KILL SWITCH/);
});

test('health monitor pauses a host after sustained 5xx responses', async () => {
  const safety = new SafetyLayer({ healthPauseThreshold: 0.3 });
  const http = new SafeHttpClient({ safety, fetchImpl: (async () => new Response('down', { status: 500 }) as Response) });
  for (let i = 0; i < 4; i++) await http.send({ method: 'GET', url: 'http://127.0.0.1:4000/api/search', headers: baseHeaders });
  const next = safety.authorize({ method: 'GET', url: 'http://127.0.0.1:4000/api/search', headers: baseHeaders });
  assert.equal(next.allowed, false);
  assert.match(next.reason ?? '', /Health monitor paused/);
});

test('audit records are hash-chained and PII is redacted from replay', () => {
  const safety = new SafetyLayer();
  const seen: { prevHash: string; hash: string; replay: { body?: string } }[] = [];
  safety.onAudit((r) => seen.push(r));
  safety.recordResponse({ method: 'POST', url: 'http://127.0.0.1:4000/api/book', headers: baseHeaders, body: '{"passport":"A1234567","email":"a@b.com"}' }, 200, 12);
  safety.recordResponse({ method: 'GET', url: 'http://127.0.0.1:4000/api/search', headers: baseHeaders }, 200, 8);
  assert.equal(seen[1].prevHash, seen[0].hash);
  assert.notEqual(seen[0].hash, seen[1].hash);
  assert.doesNotMatch(seen[0].replay.body ?? '', /A1234567|a@b\.com/);
  assert.match(seen[0].replay.body ?? '', /REDACTED/);
});
