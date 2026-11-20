import type { Endpoint } from '@sentinel/shared';

export function generateOpenAPI(endpoints: Endpoint[]): Record<string, unknown> {
  const paths: Record<string, Record<string, unknown>> = {};
  for (const e of endpoints) {
    const key = e.path.replace(/:([A-Za-z0-9_]+)/g, '{$1}');
    paths[key] ??= {};
    const params = [
      ...e.params.filter((p) => p.location === 'path').map((p) => ({ name: p.name, in: 'path', required: true, schema: { type: p.type === 'number' ? 'number' : 'string' } })),
      ...e.params.filter((p) => p.location === 'query').map((p) => ({ name: p.name, in: 'query', required: false, schema: { type: p.type === 'number' ? 'number' : 'string' } })),
    ];
    paths[key][e.method.toLowerCase()] = {
      operationId: `${e.method.toLowerCase()}_${key.replace(/[^a-zA-Z0-9]/g, '_')}`,
      summary: `${e.flow} flow · ${e.status} endpoint${e.vulnerableToVersion ? ` · ${e.vulnerableToVersion}` : ''}`,
      tags: [e.flow, e.status],
      security: e.authRequired ? [{ syntheticBearer: [] }] : [],
      ...(params.length ? { parameters: params } : {}),
      ...(e.params.some((p) => p.location === 'body') ? {
        requestBody: {
          content: {
            'application/json': {
              schema: {
                type: 'object',
                properties: Object.fromEntries(e.params.filter((p) => p.location === 'body').map((p) => [p.name, { type: p.type === 'number' ? 'number' : 'string' }])),
              },
            },
          },
        },
      } : {}),
      responses: { 200: { description: 'Synthetic staging response' } },
    };
  }
  return {
    openapi: '3.0.3',
    info: {
      title: 'SentinelTBO inferred staging API',
      version: '1.0.0-inferred',
      description: 'Generated from recon evidence (JS bundles, HAR, hidden probes, gateway logs). Synthetic staging only.',
    },
    servers: [{ url: 'http://127.0.0.1:4000', description: 'bundled mock travel platform' }],
    components: { securitySchemes: { syntheticBearer: { type: 'http', scheme: 'bearer', description: 'Test-account tokens only' } } },
    paths,
  };
}
