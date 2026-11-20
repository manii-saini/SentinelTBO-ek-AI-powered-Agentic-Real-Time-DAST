import { cva, type VariantProps } from 'class-variance-authority';
import type { ButtonHTMLAttributes, InputHTMLAttributes, ReactNode } from 'react';
import type { Severity } from '@sentinel/shared';
import { cn } from '../lib/utils';

const button = cva('inline-flex items-center justify-center gap-1.5 rounded border font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-40', {
  variants: {
    variant: {
      primary: 'border-cyan-400/30 bg-cyan-500/15 text-cyan-200 hover:bg-cyan-500/25',
      ghost: 'border-white/5 bg-white/[0.03] text-slate-300 hover:bg-white/[0.07]',
      danger: 'border-rose-400/30 bg-rose-500/10 text-rose-300 hover:bg-rose-500/20',
      success: 'border-emerald-400/30 bg-emerald-500/10 text-emerald-300 hover:bg-emerald-500/20',
    },
    size: { sm: 'h-7 px-2 text-[11px]', md: 'h-9 px-3 text-xs', lg: 'h-10 px-4 text-sm' },
  },
  defaultVariants: { variant: 'ghost', size: 'sm' },
});

export function Button({ className, variant, size, ...props }: ButtonHTMLAttributes<HTMLButtonElement> & VariantProps<typeof button>) {
  return <button className={cn(button({ variant, size }), className)} {...props} />;
}

export function Panel({ title, subtitle, right, children, className, bodyClass }: {
  title?: string; subtitle?: string; right?: ReactNode; children: ReactNode; className?: string; bodyClass?: string;
}) {
  return (
    <section className={cn('panel min-w-0', className)}>
      {(title || right) && (
        <header className="panel-head">
          <div className="min-w-0">
            {title && <h2 className="truncate text-xs font-semibold uppercase tracking-[0.12em] text-slate-300">{title}</h2>}
            {subtitle && <p className="mt-0.5 truncate text-[11px] text-slate-500">{subtitle}</p>}
          </div>
          {right}
        </header>
      )}
      <div className={cn('p-4', bodyClass)}>{children}</div>
    </section>
  );
}

export function Badge({ children, tone = 'slate', className }: { children: ReactNode; tone?: 'slate' | 'cyan' | 'amber' | 'red' | 'green' | 'violet'; className?: string }) {
  const tones = {
    slate: 'border-white/10 bg-white/5 text-slate-400',
    cyan: 'border-cyan-400/25 bg-cyan-400/10 text-cyan-300',
    amber: 'border-amber-400/25 bg-amber-400/10 text-amber-300',
    red: 'border-rose-400/25 bg-rose-400/10 text-rose-300',
    green: 'border-emerald-400/25 bg-emerald-400/10 text-emerald-300',
    violet: 'border-violet-400/25 bg-violet-400/10 text-violet-300',
  };
  return <span className={cn('inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide', tones[tone], className)}>{children}</span>;
}

export function SeverityPill({ severity }: { severity: Severity }) {
  return <Badge tone={severity === 'critical' ? 'red' : severity === 'high' ? 'amber' : severity === 'medium' ? 'violet' : severity === 'low' ? 'cyan' : 'slate'}>{severity}</Badge>;
}

export function Dot({ tone = 'cyan', pulse = false }: { tone?: 'cyan' | 'green' | 'amber' | 'red' | 'slate'; pulse?: boolean }) {
  const colors = { cyan: 'bg-cyan-400', green: 'bg-emerald-400', amber: 'bg-amber-400', red: 'bg-rose-400', slate: 'bg-slate-500' };
  return <span className={cn('inline-block h-1.5 w-1.5 rounded-full', colors[tone], pulse && 'animate-blink')} />;
}

export function Stat({ label, value, hint, tone = 'cyan' }: { label: string; value: string | number; hint?: string; tone?: 'cyan' | 'green' | 'amber' | 'red' }) {
  const accent = { cyan: 'text-cyan-300', green: 'text-emerald-300', amber: 'text-amber-300', red: 'text-rose-300' }[tone];
  return (
    <div className="panel px-4 py-3">
      <div className="label">{label}</div>
      <div className={cn('num mt-1.5 text-2xl font-semibold tracking-tight', accent)}>{value}</div>
      {hint && <div className="mt-1 text-[10px] text-slate-500">{hint}</div>}
    </div>
  );
}

export function Tabs<T extends string>({ tabs, active, onChange }: { tabs: { id: T; label: string; count?: number }[]; active: T; onChange: (id: T) => void }) {
  return (
    <div className="flex items-center gap-1 border-b border-white/5">
      {tabs.map((tab) => (
        <button key={tab.id} onClick={() => onChange(tab.id)} className={cn('relative px-3 py-2 text-[11px] font-medium uppercase tracking-wide transition-colors', active === tab.id ? 'text-cyan-300' : 'text-slate-500 hover:text-slate-300')}>
          {tab.label}
          {tab.count !== undefined && <span className="ml-1.5 num text-[10px] text-slate-500">{tab.count}</span>}
          {active === tab.id && <span className="absolute inset-x-2 -bottom-px h-px bg-cyan-400" />}
        </button>
      ))}
    </div>
  );
}

export function Table({ headers, children, dense = false }: { headers: string[]; children: ReactNode; dense?: boolean }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[640px] border-collapse text-left">
        <thead><tr className="border-b border-white/5">{headers.map((h) => <th key={h} className={cn('label whitespace-nowrap px-3 font-semibold', dense ? 'py-2' : 'py-3')}>{h}</th>)}</tr></thead>
        <tbody className="divide-y divide-white/[0.04]">{children}</tbody>
      </table>
    </div>
  );
}

export function Input({ className, ...props }: InputHTMLAttributes<HTMLInputElement>) {
  return <input className={cn('h-8 w-full rounded border border-white/10 bg-ink-950 px-2.5 text-xs text-slate-200 outline-none placeholder:text-slate-600 focus:border-cyan-400/50', className)} {...props} />;
}

export function Slider({ value, min = 0, max = 60, step = 1, onChange }: { value: number; min?: number; max?: number; step?: number; onChange: (n: number) => void }) {
  return <input type="range" min={min} max={max} step={step} value={value} onChange={(e) => onChange(Number(e.target.value))} className="h-1.5 w-full cursor-pointer appearance-none rounded-full bg-ink-700 accent-cyan-400" />;
}

export function Empty({ title, detail }: { title: string; detail?: string }) {
  return <div className="flex flex-col items-center justify-center gap-1 py-12 text-center"><div className="text-xs font-medium text-slate-400">{title}</div>{detail && <div className="max-w-sm text-[11px] text-slate-600">{detail}</div>}</div>;
}

export function Code({ children, className }: { children: ReactNode; className?: string }) {
  return <pre className={cn('max-h-60 overflow-auto whitespace-pre-wrap break-all rounded border border-white/5 bg-ink-950 p-3 font-mono text-[10px] leading-relaxed text-slate-400', className)}>{children}</pre>;
}
