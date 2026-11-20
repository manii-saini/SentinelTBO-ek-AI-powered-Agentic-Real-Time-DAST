import { createHash, randomUUID } from 'node:crypto';
import type { Agency, AuditRecord, HealthSample, Role, SafetyConfig } from '@sentinel/shared';
import { redact } from '@sentinel/shared';

export interface OutboundRequest {
  method: string;
  url: string;
  headers: Record<string, string>;
  body?: string;
  role?: Role;
  agency?: Agency;
  testId?: string;
  findingId?: string;
  runId?: string;
}

export interface AuthorizationResult {
  allowed: boolean;
  reason?: string;
  waitMs?: number;
  approvalId?: string;
}

const DESTRUCTIVE_PATH = /\/(pay|payment|charge|cancel|refund|book|booking|checkout|transfer)(\/|\?|$)/i;
const DESTRUCTIVE_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

export const DEFAULT_SAFETY_CONFIG: SafetyConfig = {
  allowlist: ['127.0.0.1:4000', 'localhost:4000', 'staging.travel.internal'],
  rateLimit: 12,
  burst: 20,
  healthPauseThreshold: 0.5,
  healthBackoffThreshold: 0.25,
  killSwitch: false,
  requireApprovalForDestructive: true,
  testCredentials: {
    'agent-a': { agency: 'A', role: 'agent', token: 'test-agent-a' },
    'subagent-a': { agency: 'A', role: 'sub-agent', token: 'test-subagent-a' },
    'admin-a': { agency: 'A', role: 'admin', token: 'test-admin-a' },
    'agent-b': { agency: 'B', role: 'agent', token: 'test-agent-b' },
    'subagent-b': { agency: 'B', role: 'sub-agent', token: 'test-subagent-b' },
    'admin-b': { agency: 'B', role: 'admin', token: 'test-admin-b' },
  },
};

interface Bucket {
  tokens: number;
  updated: number;
}

interface HostHealth {
  samples: number[];
  errors: number;
  pausedUntil: number;
}

function hostOf(url: string): string {
  const u = new URL(url);
  return `${u.hostname}${u.port ? `:${u.port}` : ''}`;
}

function tokenOf(headers: Record<string, string>): string | undefined {
  const auth = headers.authorization ?? headers.Authorization ?? '';
  return auth.replace(/^Bearer\s+/i, '').trim() || undefined;
}

function hashChain(prev: string, payload: string): string {
  return createHash('sha256').update(prev + payload).digest('hex').slice(0, 32);
}

export class SafetyLayer {
  config: SafetyConfig;
  private buckets = new Map<string, Bucket>();
  private health = new Map<string, HostHealth>();
  private seq = 0;
  private lastHash = '0'.repeat(32);
  private auditSink: (record: AuditRecord) => void = () => {};
  private healthSink: (sample: HealthSample) => void = () => {};
  private approvalChecker: (id: string) => boolean = () => false;

  constructor(config: Partial<SafetyConfig> = {}) {
    this.config = { ...DEFAULT_SAFETY_CONFIG, ...config };
  }

  onAudit(fn: (record: AuditRecord) => void) { this.auditSink = fn; return this; }
  onHealth(fn: (sample: HealthSample) => void) { this.healthSink = fn; return this; }
  isApproved(fn: (id: string) => boolean) { this.approvalChecker = fn; return this; }

  setConfig(patch: Partial<SafetyConfig>) {
    this.config = { ...this.config, ...patch };
  }

  authorize(req: OutboundRequest): AuthorizationResult {
    if (this.config.killSwitch) return { allowed: false, reason: 'KILL SWITCH ACTIVE — all outbound traffic stopped' };

    let u: URL;
    try {
      u = new URL(req.url);
    } catch {
      return { allowed: false, reason: 'Malformed URL' };
    }
    if (!['http:', 'https:'].includes(u.protocol)) return { allowed: false, reason: `Protocol ${u.protocol} not allowed` };

    const host = hostOf(req.url);
    if (!this.config.allowlist.some((h) => h.toLowerCase() === host.toLowerCase())) {
      return { allowed: false, reason: `Out of scope: ${host} is not in the scope allowlist` };
    }

    if ((req.headers['x-sentinel-synthetic'] ?? '').toLowerCase() !== 'true') {
      return { allowed: false, reason: 'Missing synthetic-traffic marker (x-sentinel-synthetic: true)' };
    }

    const token = tokenOf(req.headers);
    const knownTokens = new Set(Object.values(this.config.testCredentials).map((c) => c.token));
    if (token && !knownTokens.has(token)) {
      return { allowed: false, reason: 'Credential is not an approved synthetic test account' };
    }

    if (this.config.requireApprovalForDestructive && DESTRUCTIVE_METHODS.has(req.method.toUpperCase()) && DESTRUCTIVE_PATH.test(u.pathname)) {
      const approvalId = req.headers['x-sentinel-approval'];
      if (!approvalId || !this.approvalChecker(approvalId)) {
        return { allowed: false, reason: `Destructive test requires an approved request (${req.method} ${u.pathname})`, approvalId };
      }
      return { allowed: true, approvalId };
    }

    const h = this.health.get(host);
    if (h && Date.now() < h.pausedUntil) {
      return { allowed: false, reason: `Health monitor paused ${host} after elevated error rate` };
    }

    const waitMs = this.takeToken(host);
    if (waitMs > 0) return { allowed: true, waitMs };

    return { allowed: true };
  }

  private takeToken(host: string): number {
    const now = Date.now();
    const bucket = this.buckets.get(host) ?? { tokens: this.config.burst, updated: now };
    const refill = ((now - bucket.updated) / 1000) * this.config.rateLimit;
    bucket.tokens = Math.min(this.config.burst, bucket.tokens + refill);
    bucket.updated = now;
    let wait = 0;
    if (bucket.tokens < 1) {
      wait = Math.ceil(((1 - bucket.tokens) / this.config.rateLimit) * 1000);
    } else {
      bucket.tokens -= 1;
    }
    this.buckets.set(host, bucket);
    return wait;
  }

  recordResponse(req: OutboundRequest, status: number, timingMs: number, bytes = 0, blocked = false, blockReason?: string): AuditRecord {
    const host = (() => { try { return hostOf(req.url); } catch { return 'invalid'; } })();
    const h = this.health.get(host) ?? { samples: [], errors: 0, pausedUntil: 0 };
    h.samples.push(timingMs);
    if (h.samples.length > 30) h.samples.shift();
    if (status >= 500 || status === 0) h.errors += 1;
    const errorRate = h.errors / Math.max(1, h.samples.length);
    let action: HealthSample['action'] = 'normal';
    if (errorRate >= this.config.healthPauseThreshold) {
      h.pausedUntil = Date.now() + 4000;
      action = 'pause';
      h.errors = 0;
    } else if (errorRate >= this.config.healthBackoffThreshold) {
      action = 'backoff';
    }
    this.health.set(host, h);
    this.healthSink({ at: Date.now(), host, latencyMs: timingMs, errorRate, action });

    const seq = ++this.seq;
    const replay = {
      method: req.method,
      url: req.url,
      headers: Object.fromEntries(Object.entries(req.headers).map(([k, v]) => [k, /authorization|token/i.test(k) ? '[REDACTED]' : v])),
      body: req.body ? redact(req.body) : undefined,
    };
    const payload = JSON.stringify({ seq, at: Date.now(), method: req.method, url: req.url, status, role: req.role, timingMs, blocked });
    const hash = hashChain(this.lastHash, payload);
    const record: AuditRecord = {
      id: randomUUID(),
      seq,
      at: Date.now(),
      runId: req.runId ?? 'manual',
      method: req.method,
      url: req.url,
      host,
      role: req.role ?? 'unknown',
      agency: req.agency ?? '-',
      status,
      timingMs,
      bytes,
      blocked,
      blockReason,
      testId: req.testId,
      findingId: req.findingId,
      bodyHash: createHash('sha256').update(req.body ?? '').digest('hex').slice(0, 16),
      prevHash: this.lastHash,
      hash,
      replay,
    };
    this.lastHash = hash;
    this.auditSink(record);
    return record;
  }

  getHealth(host: string): HealthSample | null {
    const h = this.health.get(host);
    if (!h) return null;
    const latency = h.samples.reduce((a, b) => a + b, 0) / Math.max(1, h.samples.length);
    return {
      at: Date.now(),
      host,
      latencyMs: Math.round(latency),
      errorRate: h.errors / Math.max(1, h.samples.length),
      action: Date.now() < h.pausedUntil ? 'pause' : latency > 450 || h.errors > 3 ? 'backoff' : 'normal',
    };
  }
}

export interface SafeHttpClientOptions {
  safety: SafetyLayer;
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
}

export class SafeHttpClient {
  constructor(private options: SafeHttpClientOptions) {}

  async send(req: OutboundRequest): Promise<{ ok: boolean; status: number; body: string; timingMs: number; blocked: boolean; blockReason?: string; approvalId?: string }> {
    const { safety } = this.options;
    const auth = safety.authorize(req);
    if (!auth.allowed) {
      const rec = safety.recordResponse(req, 0, 0, 0, true, auth.reason);
      return { ok: false, status: 0, body: JSON.stringify({ blocked: true, reason: auth.reason, auditId: rec.id }), timingMs: 0, blocked: true, blockReason: auth.reason };
    }
    if (auth.waitMs) await new Promise((r) => setTimeout(r, Math.min(auth.waitMs!, 1500)));

    const started = performance.now();
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.options.timeoutMs ?? 5000);
    try {
      const fetchFn = this.options.fetchImpl ?? fetch;
      const response = await fetchFn(req.url, {
        method: req.method,
        headers: req.headers,
        body: req.body,
        signal: controller.signal,
      });
      const text = await response.text();
      const timingMs = Math.round(performance.now() - started);
      safety.recordResponse(req, response.status, timingMs, text.length, false);
      return { ok: response.ok, status: response.status, body: text, timingMs, blocked: false, approvalId: auth.approvalId };
    } catch (error) {
      const timingMs = Math.round(performance.now() - started);
      const message = error instanceof Error ? error.message : String(error);
      safety.recordResponse(req, 0, timingMs, 0, true, message);
      return { ok: false, status: 0, body: JSON.stringify({ error: message }), timingMs, blocked: true, blockReason: message };
    } finally {
      clearTimeout(timer);
    }
  }
}
