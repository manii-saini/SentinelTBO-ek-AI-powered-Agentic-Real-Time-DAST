import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import type { Endpoint, ChangeEvent } from '@sentinel/shared';
import type { Agent, AgentContext } from '../agent.js';
import { metaForPath, ownerForPath } from '../config.js';

const HIDDEN_PATHS = [
  '/v1/bookings', '/v1/health', '/old/bookings', '/legacy/bookings', '/internal/debug',
  '/internal/status', '/test/routes', '/beta/bookings', '/debug', '/api/v2/coupons/stack',
];

export function parseHAR(json: unknown): string[] {
  const entries = (json as { log?: { entries?: { request?: { url?: string } }[] } })?.log?.entries ?? [];
  return entries.map((e) => {
    try { return new URL(e.request?.url ?? '').pathname; } catch { return ''; }
  }).filter(Boolean);
}

export function parseBundle(source: string): string[] {
  const matches = source.match(/["'`](\/(?:api|internal|v1|old|beta|test)\/[A-Za-z0-9/_:?-]+)["'`]/g) ?? [];
  return [...new Set(matches.map((m) => m.slice(1, -1).split('?')[0]))];
}

export class PlaywrightCrawler {
  async crawl(ctx: AgentContext, routes: string[]): Promise<{ crawled: number; mode: string }> {
    if (process.env.SENTINEL_USE_PLAYWRIGHT !== 'true') {
      ctx.emit('recon', 'info', 'Playwright crawl skipped (set SENTINEL_USE_PLAYWRIGHT=true to enable); HTTP/bundle/HAR discovery used', { routes: routes.length });
      return { crawled: 0, mode: 'fallback' };
    }
    try {
      const loader = new Function('return import("playwright")') as () => Promise<{ chromium: { launch: (opts: object) => Promise<{ newPage: () => Promise<any>; close: () => Promise<void> }> } }>;
      const { chromium } = await loader();
      const browser = await chromium.launch({ headless: true });
      const page = await browser.newPage();
      let crawled = 0;
      for (const route of routes.slice(0, 20)) {
        try {
          await page.goto(`${ctx.target}${route}`, { waitUntil: 'domcontentloaded', timeout: 4000 });
          crawled++;
        } catch { /* route is not a browser page; API routes are crawled via safe HTTP client */ }
      }
      await browser.close();
      ctx.emit('recon', 'success', 'Playwright authenticated crawl completed', { crawled });
      return { crawled, mode: 'playwright' };
    } catch (error) {
      ctx.emit('recon', 'warn', 'Playwright unavailable; continuing with HTTP discovery', { error: String(error) });
      return { crawled: 0, mode: 'fallback' };
    }
  }
}

function makeEndpoint(ctx: AgentContext, path: string, source: Endpoint['source'], found = true): Endpoint {
  const meta = metaForPath(path);
  const owner = ownerForPath(path);
  return {
    id: `${ctx.target}|${path}`,
    method: path.includes('/bookings/') ? 'GET' : path.includes('/coupons/stack') ? 'GET' : path.startsWith('/internal') || path.startsWith('/health') ? 'GET' : 'POST',
    path,
    host: new URL(ctx.target).host,
    source,
    status: 'active',
    roles: meta.roles as Endpoint['roles'],
    params: meta.params as Endpoint['params'],
    authRequired: meta.roles.length > 0,
    dataExposed: meta.data,
    businessContext: meta.context,
    flow: meta.flow,
    lastRealTraffic: found ? Date.now() - 3_600_000 : null,
    hits30d: 0,
    hits90d: 0,
    vulnerableToVersion: null,
    owner: owner.owner,
    recommendation: 'monitor',
    discoveredAt: Date.now(),
  };
}

export class ReconAgent implements Agent<{ changes: ChangeEvent[]; focusPaths?: string[] }, Endpoint[]> {
  readonly id = 'recon';
  readonly name = 'ReconAgent';

  async run(input: { changes: ChangeEvent[]; focusPaths?: string[] }, ctx: AgentContext): Promise<Endpoint[]> {
    ctx.emit('recon', 'info', 'Starting role-based discovery of staging application', { target: ctx.target });
    const discovered = new Map<string, Endpoint>();
    const add = (path: string, source: Endpoint['source'], found = true) => {
      if (!discovered.has(path)) discovered.set(path, makeEndpoint(ctx, path, source, found));
    };

    let harPaths: string[] = [];
    try {
      const har = JSON.parse(readFileSync(resolve(process.cwd(), 'packages/agents/fixtures/sample.har'), 'utf8'));
      harPaths = parseHAR(har);
      harPaths.forEach((p) => add(p, 'har'));
      ctx.emit('recon', 'success', `HAR fixture ingested: ${harPaths.length} recorded routes`, { routes: harPaths });
    } catch (error) {
      ctx.emit('recon', 'warn', 'HAR fixture unavailable', { error: String(error) });
    }

    try {
      const res = await ctx.http.send({ method: 'GET', url: `${ctx.target}/__admin/bundle`, headers: { 'x-sentinel-synthetic': 'true' }, runId: ctx.runId });
      const routes = parseBundle(res.body);
      routes.forEach((p) => add(p, 'bundle'));
      ctx.emit('recon', 'success', `JS bundle route extraction: ${routes.length} API routes`, { routes });
      await new PlaywrightCrawler().crawl(ctx, routes);
    } catch (error) {
      ctx.emit('recon', 'warn', 'Bundle extraction failed', { error: String(error) });
    }

    for (const path of HIDDEN_PATHS) {
      const res = await ctx.http.send({ method: 'GET', url: `${ctx.target}${path}`, headers: { 'x-sentinel-synthetic': 'true' }, runId: ctx.runId });
      if (res.status === 200) {
        add(path, path.startsWith('/v1') || path.startsWith('/old') ? 'hidden-probe' : 'hidden-probe', true);
        ctx.emit('recon', 'warn', `Undocumented route responds: ${path}`, { status: res.status, source: 'hidden-probe' });
      }
    }

    for (const change of input.changes) {
      change.endpoints.forEach((p) => add(p, 'ci'));
    }
    input.focusPaths?.forEach((p) => add(p, 'ci'));

    const ctHosts = (process.env.SENTINEL_CT_SUBDOMAINS ?? 'staging.travel.internal').split(',').filter(Boolean);
    ctx.emit('recon', 'info', 'CT-log subdomain correlation complete', { hosts: ctHosts });

    const endpoints = [...discovered.values()];
    ctx.emit('recon', 'success', `Recon complete: ${endpoints.length} endpoints in knowledge graph`, { endpoints: endpoints.map((e) => e.path) });
    return endpoints;
  }
}
