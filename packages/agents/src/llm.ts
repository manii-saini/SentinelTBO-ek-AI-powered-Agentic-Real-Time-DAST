import { createHash } from 'node:crypto';

export type LLMProvider = 'mock' | 'openai' | 'anthropic';

export interface LLMOptions {
  system: string;
  prompt: string;
  temperature?: number;
  maxTokens?: number;
}

export interface LLMResult {
  provider: LLMProvider;
  text: string;
  latencyMs: number;
}

export class LLM {
  readonly provider: LLMProvider;
  readonly model: string;

  constructor(provider = (process.env.SENTINEL_LLM_PROVIDER ?? 'mock') as LLMProvider) {
    this.provider = provider;
    this.model = process.env.SENTINEL_LLM_MODEL ?? 'sentinel-deterministic-1';
  }

  async complete(options: LLMOptions): Promise<LLMResult> {
    const started = performance.now();
    if (this.provider === 'mock') {
      return { provider: 'mock', text: this.mockComplete(options), latencyMs: Math.round(performance.now() - started) };
    }
    const key = process.env.SENTINEL_LLM_API_KEY;
    if (!key) throw new Error(`SENTINEL_LLM_API_KEY is required for provider ${this.provider}`);
    if (this.provider === 'openai') {
      const response = await fetch('https://api.openai.com/v1/chat/completions', {
        method: 'POST',
        headers: { 'content-type': 'application/json', authorization: `Bearer ${key}` },
        body: JSON.stringify({ model: this.model, messages: [{ role: 'system', content: options.system }, { role: 'user', content: options.prompt }], temperature: options.temperature ?? 0 }),
      });
      const json = await response.json() as { choices?: { message?: { content?: string } }[] };
      return { provider: this.provider, text: json.choices?.[0]?.message?.content ?? '', latencyMs: Math.round(performance.now() - started) };
    }
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-api-key': key, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify({ model: this.model, max_tokens: options.maxTokens ?? 512, messages: [{ role: 'user', content: `${options.system}\n\n${options.prompt}` }] }),
    });
    const json = await response.json() as { content?: { text?: string }[] };
    return { provider: this.provider, text: json.content?.map((c) => c.text ?? '').join('') ?? '', latencyMs: Math.round(performance.now() - started) };
  }

  private mockComplete(options: LLMOptions): string {
    const digest = createHash('sha256').update(options.prompt).digest('hex');
    const topic = options.prompt.match(/Endpoint:\s*(\S+)/)?.[1] ?? 'this endpoint';
    const test = options.prompt.match(/Test:\s*([^\n]+)/)?.[1] ?? 'the selected test';
    const variants = [
      `Targeted because ${topic} exposes a state-changing parameter and the selected control (${test}) isolates a single authorization or trust boundary; deterministic seed ${digest.slice(0, 6)}.`,
      `Chosen over broad fuzzing: ${topic} is used in the search-to-payment flow, so ${test} exercises the business impact path with one synthetic account pair and minimal requests.`,
      `Reasoning: observed parameters and role requirements on ${topic} make ${test} the highest-signal, lowest-noise check; mock reasoning seed ${digest.slice(0, 6)}.`,
    ];
    return variants[Number.parseInt(digest.slice(0, 2), 16) % variants.length];
  }
}
