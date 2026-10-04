import { animate, motion, useMotionValue, useTransform } from 'motion/react';
import { useEffect, type CSSProperties, type ReactNode } from 'react';
import type { EmailProtocol, Severity } from '../engine/types.ts';
import { SpotlightCard } from './bits.tsx';

// Standard, slightly desaturated severity scale (no neon)
export const SEV: Record<Severity, { color: string; bg: string; label: string }> = {
  critical: { color: '#f05252', bg: 'rgb(240 82 82 / 0.10)', label: 'Critical' },
  high: { color: '#f08c3e', bg: 'rgb(240 140 62 / 0.10)', label: 'High' },
  medium: { color: '#d9a92b', bg: 'rgb(217 169 43 / 0.10)', label: 'Medium' },
  low: { color: '#5b8def', bg: 'rgb(91 141 239 / 0.10)', label: 'Low' },
  info: { color: '#8b8b94', bg: 'rgb(139 139 148 / 0.10)', label: 'Info' },
};
export const SEV_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

export const PROTO_COLOR: Record<EmailProtocol, string> = { SMTP: '#7ea6f2', IMAP: '#a99be8', POP3: '#d99ab8', UNKNOWN: '#71717a' };

export const scoreColor = (s: number) => (s >= 85 ? '#3fb27f' : s >= 70 ? '#8cb247' : s >= 55 ? '#d9a92b' : s >= 35 ? '#f08c3e' : '#f05252');

export function SevBadge({ sev, className = '' }: { sev: Severity; className?: string }) {
  const s = SEV[sev];
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-xs font-bold ${className}`}
      style={{ color: s.color, background: s.bg, borderColor: `${s.color}33` }}>
      <span className="h-1.5 w-1.5 rounded-full" style={{ background: s.color }} />
      {s.label}
    </span>
  );
}

export function ProtoBadge({ p }: { p: EmailProtocol }) {
  return <span className="rounded border border-white/10 bg-white/[0.03] px-1.5 py-px font-mono text-[10.5px] font-bold" style={{ color: PROTO_COLOR[p] }}>{p}</span>;
}

export function Card({ children, className = '', title, icon, action, delay = 0 }: { children: ReactNode; className?: string; title?: ReactNode; icon?: ReactNode; action?: ReactNode; delay?: number }) {
  return (
    <motion.section initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.45, delay, ease: [0.16, 1, 0.3, 1] }} className="min-w-0">
      <SpotlightCard className={`h-full p-5 ${className}`}>
        {title && (
          <header className="relative mb-4 flex items-center justify-between gap-3">
            <h3 className="flex items-center gap-2 text-[15px] font-bold text-zinc-100">
              {icon && <span className="text-zinc-500">{icon}</span>}{title}
            </h3>
            {action}
          </header>
        )}
        <div className="relative">{children}</div>
      </SpotlightCard>
    </motion.section>
  );
}

export function Counter({ value, decimals = 0, className = '', style }: { value: number; decimals?: number; className?: string; style?: CSSProperties }) {
  const mv = useMotionValue(0);
  const text = useTransform(mv, (v) => v.toLocaleString(undefined, { minimumFractionDigits: decimals, maximumFractionDigits: decimals }));
  useEffect(() => { const c = animate(mv, value, { duration: 1.1, ease: [0.16, 1, 0.3, 1] }); return c.stop; }, [value, mv]);
  return <motion.span className={`tabular-nums ${className}`} style={style}>{text}</motion.span>;
}

export function ScoreRing({ score, size = 200, stroke = 10, label, sub }: { score: number; size?: number; stroke?: number; label?: string; sub?: string }) {
  const r = (size - stroke) / 2;
  const c = 2 * Math.PI * r;
  const color = scoreColor(score);
  return (
    <div className="relative shrink-0" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="#202024" strokeWidth={stroke} />
        <motion.circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke={color} strokeWidth={stroke} strokeLinecap="round"
          strokeDasharray={c} initial={{ strokeDashoffset: c }} animate={{ strokeDashoffset: c * (1 - score / 100) }}
          transition={{ duration: 1.3, ease: [0.16, 1, 0.3, 1] }} />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <Counter value={score} className="leading-none font-bold text-zinc-50" style={{ fontSize: size * 0.3 }} />
        {label && <div className="mt-1.5 text-xs font-bold" style={{ color }}>{label}</div>}
        {sub && <div className="mt-0.5 text-[11px] text-zinc-500">{sub}</div>}
      </div>
    </div>
  );
}

export function Pill({ children, color = '#a1a1aa' }: { children: ReactNode; color?: string }) {
  return <span className="inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-xs font-bold" style={{ color, borderColor: `${color}33`, background: `${color}10` }}>{children}</span>;
}

export const fmtBytes = (n: number) => (n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(2)} MB`);
export const fmtTime = (t: number) => new Date(t * 1000).toISOString().replace('T', ' ').slice(0, 19) + 'Z';
export const fmtClock = (t: number) => new Date(t * 1000).toISOString().slice(11, 23);

export function Bar({ value, color, h = 6 }: { value: number; color: string; h?: number }) {
  return (
    <div className="w-full overflow-hidden rounded-full bg-white/[0.06]" style={{ height: h }}>
      <motion.div className="h-full rounded-full" style={{ background: color }}
        initial={{ width: 0 }} animate={{ width: `${Math.max(0, Math.min(100, value))}%` }} transition={{ duration: 0.9, ease: [0.16, 1, 0.3, 1] }} />
    </div>
  );
}
