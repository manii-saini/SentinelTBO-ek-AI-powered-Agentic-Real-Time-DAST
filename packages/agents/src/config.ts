import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import type { OwnershipEntry, SafetyConfig } from '@sentinel/shared';
import { DEFAULT_SAFETY_CONFIG } from './safety.js';

export const TARGET_BASE_URL = process.env.SENTINEL_TARGET ?? 'http://127.0.0.1:4000';

export const SAFETY_CONFIG: SafetyConfig = {
  ...DEFAULT_SAFETY_CONFIG,
  allowlist: (process.env.SENTINEL_ALLOWLIST ?? DEFAULT_SAFETY_CONFIG.allowlist.join(',')).split(',').map((s) => s.trim()).filter(Boolean),
  rateLimit: Number(process.env.SENTINEL_RATE_LIMIT ?? DEFAULT_SAFETY_CONFIG.rateLimit),
  burst: Number(process.env.SENTINEL_BURST ?? DEFAULT_SAFETY_CONFIG.burst),
};

export const DISCOVERY_TECHNIQUES = [
  { name: 'JS bundle route extraction', detail: 'Parse quoted route literals from production front-end bundles' },
  { name: 'HAR ingestion', detail: 'Import recorded browser sessions from QA and staging' },
  { name: 'Hidden path guessing', detail: 'Probe /v1 /old /internal /test /beta /debug prefixes' },
  { name: 'Gateway log diff', detail: 'Compare inferred map against 30/90-day gateway traffic' },
  { name: 'CT-log subdomains', detail: 'Correlate certificate transparency entries with staging hosts' },
  { name: 'Playwright role crawl', detail: 'Optional authenticated crawl with synthetic accounts behind SENTINEL_USE_PLAYWRIGHT' },
];

export function loadOwnership(): OwnershipEntry[] {
  try {
    const file = resolve(process.cwd(), 'packages/shared/assets.json');
    return JSON.parse(readFileSync(file, 'utf8')) as OwnershipEntry[];
  } catch {
    return [{ pathPrefix: '/', owner: 'Unassigned', team: 'Triage', slack: '#security-triage' }];
  }
}

export function ownerForPath(path: string): OwnershipEntry {
  const entries = loadOwnership();
  return entries.find((e) => path.startsWith(e.pathPrefix)) ?? entries[entries.length - 1];
}

export const ENDPOINT_META: Record<string, { roles: string[]; params: { name: string; location: 'path' | 'query' | 'body' | 'header'; type: string; sensitive?: boolean; controllable?: boolean }[]; data: string[]; context: string[]; flow: string }> = {
  '/api/search': { roles: ['agent', 'sub-agent'], params: [{ name: 'origin', location: 'body', type: 'string' }, { name: 'destination', location: 'body', type: 'string' }], data: ['fares'], context: ['bookings'], flow: 'search' },
  '/api/hold': { roles: ['agent', 'sub-agent'], params: [{ name: 'holdId', location: 'body', type: 'string' }], data: ['pnr', 'fares'], context: ['bookings'], flow: 'hold' },
  '/api/book': { roles: ['agent', 'sub-agent', 'admin'], params: [{ name: 'holdId', location: 'body', type: 'string' }, { name: 'fare', location: 'body', type: 'number', controllable: true }, { name: 'role', location: 'body', type: 'string', controllable: true, sensitive: true }, { name: 'quantity', location: 'body', type: 'number', controllable: true }], data: ['pnr', 'passenger'], context: ['bookings', 'payments'], flow: 'book' },
  '/api/bookings/mine': { roles: ['agent', 'sub-agent', 'admin'], params: [], data: ['pnr', 'bookings'], context: ['bookings'], flow: 'book' },
  '/api/bookings/:id': { roles: ['agent', 'sub-agent', 'admin'], params: [{ name: 'id', location: 'path', type: 'string', controllable: true }], data: ['pnr', 'passenger', 'bookings'], context: ['bookings', 'pii'], flow: 'book' },
  '/api/pay': { roles: ['agent', 'admin'], params: [{ name: 'amount', location: 'body', type: 'number', controllable: true }, { name: 'coupon', location: 'body', type: 'string', controllable: true }], data: ['payments'], context: ['payments', 'coupons'], flow: 'pay' },
  '/api/cancel': { roles: ['agent', 'admin'], params: [{ name: 'holdId', location: 'body', type: 'string', controllable: true }], data: ['payments'], context: ['payments', 'credit'], flow: 'cancel' },
  '/api/invoices/:id': { roles: ['agent', 'admin'], params: [{ name: 'id', location: 'path', type: 'string' }], data: ['pnr', 'invoices'], context: ['invoices'], flow: 'pay' },
  '/api/supplier/webhook': { roles: ['agent', 'admin'], params: [{ name: 'url', location: 'body', type: 'url', controllable: true, sensitive: true }], data: ['supplier config'], context: ['supplier-access'], flow: 'cancel' },
  '/v1/bookings': { roles: ['agent', 'admin'], params: [], data: ['bookings', 'passenger'], context: ['bookings', 'pii'], flow: 'legacy' },
  '/internal/debug': { roles: [], params: [], data: ['passport', 'pnr', 'email'], context: ['pii', 'supplier-access'], flow: 'internal' },
  '/api/v2/coupons/stack': { roles: [], params: [{ name: 'count', location: 'query', type: 'number', controllable: true }], data: ['coupons', 'payments'], context: ['payments', 'coupons', 'credit'], flow: 'pay' },
};

export function metaForPath(path: string) {
  return ENDPOINT_META[path] ?? {
    roles: ['agent'],
    params: [] as { name: string; location: 'path' | 'query' | 'body' | 'header'; type: string; controllable?: boolean }[],
    data: ['unknown'],
    context: ['bookings'],
    flow: 'unknown',
  };
}
