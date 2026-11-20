import type { Finding, TestClass } from './types.js';

export const BUSINESS_CONTEXT_WEIGHT: Record<string, number> = {
  bookings: 8,
  payments: 10,
  credit: 12,
  pii: 10,
  'supplier-access': 8,
  coupons: 4,
  invoices: 4,
};

export const TEST_CLASS_LABEL: Record<TestClass, string> = {
  'access-control': 'Access control',
  'business-logic': 'Business logic',
  'auth-session': 'Auth / session',
  injection: 'Injection',
  'api-hygiene': 'API hygiene',
  'data-exposure': 'Data exposure',
  'ssrf-open-redirect': 'SSRF / open redirect',
};

export interface SeverityInput {
  testClass: TestClass;
  businessContext: string[];
  crossAgency?: boolean;
  authBypass?: boolean;
  unauthenticated?: boolean;
  destructive?: boolean;
  bulkExtraction?: boolean;
  reproducible?: boolean;
  dataExposed?: string[];
}

export interface SeverityResult {
  score: number;
  severity: Finding['severity'];
  explanation: string;
}

export function scoreSeverity(input: SeverityInput): SeverityResult {
  const reasons: string[] = [];
  let score = 18;

  for (const context of input.businessContext) {
    const weight = BUSINESS_CONTEXT_WEIGHT[context] ?? 1;
    score += weight;
    reasons.push(`${context} +${weight}`);
  }
  const add = (condition: boolean | undefined, points: number, label: string) => {
    if (condition) {
      score += points;
      reasons.push(`${label} +${points}`);
    }
  };
  add(input.crossAgency, 22, 'cross-agency boundary crossed');
  add(input.authBypass, 20, 'authorization bypass');
  add(input.unauthenticated, 18, 'no authentication required');
  add(input.destructive, 12, 'financial state mutation');
  add(input.bulkExtraction, 8, 'bulk data exposure');
  add(input.testClass === 'ssrf-open-redirect', 15, 'server-side request forgery primitive');
  add(input.testClass === 'data-exposure', 8, 'direct sensitive-data disclosure');
  add(input.reproducible === false, -25, 'not reproducible');
  if (input.reproducible !== false) reasons.push('verified twice +5');
  if (input.reproducible !== false) score += 5;

  if (input.dataExposed?.some((d) => /passport|pnr|card|email/i.test(d))) {
    score += 8;
    reasons.push('sensitive PNR/PII fields +8');
  }

  score = Math.max(0, Math.min(100, score));
  const severity: Finding['severity'] =
    score >= 80 ? 'critical' : score >= 62 ? 'high' : score >= 42 ? 'medium' : score >= 22 ? 'low' : 'info';

  return {
    score,
    severity,
    explanation: `Business impact rubric: ${reasons.join(', ') || 'baseline'} = ${score}/100 (${severity}).`,
  };
}

export const CWE_OWASP: Record<TestClass, { cwe: string; owasp: string }> = {
  'access-control': { cwe: 'CWE-639: Insecure Direct Object Reference', owasp: 'API1:2023 BOLA / API5:2023 BFLA' },
  'business-logic': { cwe: 'CWE-840: Business Logic Errors', owasp: 'API6:2023 Unrestricted Access to Sensitive Business Flows' },
  'auth-session': { cwe: 'CWE-287: Improper Authentication', owasp: 'API2:2023 Broken Authentication' },
  injection: { cwe: 'CWE-89: Injection', owasp: 'API8:2023 Security Misconfiguration' },
  'api-hygiene': { cwe: 'CWE-915: Improperly Controlled Modification of Object Properties', owasp: 'API3:2023 Broken Object Property Level Authorization' },
  'data-exposure': { cwe: 'CWE-200: Exposure of Sensitive Information', owasp: 'API3:2023 Broken Object Property Level Authorization' },
  'ssrf-open-redirect': { cwe: 'CWE-918: Server-Side Request Forgery', owasp: 'API7:2023 Server Side Request Forgery' },
};
