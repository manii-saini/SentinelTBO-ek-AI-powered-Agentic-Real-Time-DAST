export * from './types.js';
export * from './severity.js';

export const STAGE_ORDER = [
  'detect',
  'recon',
  'inventory',
  'plan',
  'execute',
  'verify',
  'triage',
  'report',
  'retest',
] as const;

export const STAGE_META: Record<string, { label: string; agent: string }> = {
  detect: { label: 'Detect change', agent: 'ChangeWatcher' },
  recon: { label: 'Learn app', agent: 'ReconAgent' },
  inventory: { label: 'Build inventory', agent: 'InventoryAgent' },
  plan: { label: 'Plan attacks', agent: 'PlannerAgent' },
  execute: { label: 'Execute safely', agent: 'SpecialistExecutors' },
  verify: { label: 'Verify', agent: 'VerifierAgent' },
  triage: { label: 'Triage', agent: 'TriageAgent' },
  report: { label: 'Report', agent: 'ReporterAgent' },
  retest: { label: 'Retest', agent: 'RetestAgent' },
};

export const TEST_CLASSES = [
  'access-control',
  'business-logic',
  'auth-session',
  'injection',
  'api-hygiene',
  'data-exposure',
  'ssrf-open-redirect',
] as const;

export function nowId(prefix: string): string {
  return `${prefix}_${Date.now().toString(36)}${Math.random().toString(36).slice(2, 7)}`;
}

export function redact(value: string): string {
  return value
    .replace(/([A-Z]{1,2}\d{6,8})/g, '[PASSPORT_REDACTED]')
    .replace(/\b(\d{4}[ -]?){3}\d{4}\b/g, '[CARD_REDACTED]')
    .replace(/\b[\w.+-]+@[\w-]+\.[\w.]+\b/g, '[EMAIL_REDACTED]')
    .replace(/"(token|authorization|api[_-]?key)"\s*:\s*"[^"]*"/gi, '"$1":"[REDACTED]"');
}
