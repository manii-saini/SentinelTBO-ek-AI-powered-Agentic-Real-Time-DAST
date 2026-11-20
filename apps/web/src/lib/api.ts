import { useCallback, useEffect, useRef, useState } from 'react';
import type { AgentEvent, SentinelState } from './types';

const API = (import.meta.env.VITE_API_URL as string | undefined) ?? 'http://127.0.0.1:3001';

export function useSentinel() {
  const [state, setState] = useState<SentinelState | null>(null);
  const [events, setEvents] = useState<AgentEvent[]>([]);
  const [connected, setConnected] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [windowDays, setWindowDays] = useState<30 | 90>(30);
  const timer = useRef<number | null>(null);

  const refresh = useCallback(async (days?: 30 | 90) => {
    try {
      const res = await fetch(`${API}/api/state?window=${days ?? windowDays}`);
      if (!res.ok) throw new Error(`API ${res.status}`);
      const json = await res.json() as SentinelState;
      setState(json);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, [windowDays]);

  useEffect(() => { void refresh(windowDays); }, [refresh, windowDays]);

  useEffect(() => {
    const source = new EventSource(`${API}/api/events/stream`);
    source.addEventListener('hello', () => setConnected(true));
    source.addEventListener('agent', (message) => {
      const event = JSON.parse((message as MessageEvent).data) as AgentEvent;
      setEvents((prev) => [event, ...prev].slice(0, 400));
      if (timer.current) window.clearTimeout(timer.current);
      timer.current = window.setTimeout(() => { void refresh(); }, 350);
    });
    source.onerror = () => setConnected(false);
    source.onopen = () => setConnected(true);
    return () => { source.close(); if (timer.current) window.clearTimeout(timer.current); };
  }, [refresh]);

  const post = useCallback(async (path: string, body: unknown = {}, method = 'POST') => {
    const res = await fetch(`${API}${path}`, {
      method,
      headers: body === undefined ? undefined : { 'content-type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const json = await res.json().catch(() => ({}));
    await refresh();
    return json;
  }, [refresh]);

  return { state, events: events.length ? events : (state?.events ?? []), connected, error, refresh, post, window: windowDays, setWindow: setWindowDays, api: API };
}

export type Sentinel = ReturnType<typeof useSentinel>;
