import { motion } from 'motion/react';
import { useEffect, useState } from 'react';
import { AlertTriangle, Check, Loader2 } from 'lucide-react';
import { STAGES } from '../engine/analyze.ts';
import type { RunState } from '../App.tsx';
import { fmtBytes } from './common.tsx';

function HexRain() {
  const [rows, setRows] = useState<string[]>([]);
  useEffect(() => {
    const gen = () => Array.from({ length: 10 }, () => Math.floor(Math.random() * 256).toString(16).padStart(2, '0')).join(' ');
    setRows(Array.from({ length: 14 }, gen));
    const i = setInterval(() => setRows((r) => [...r.slice(1), gen()]), 90);
    return () => clearInterval(i);
  }, []);
  return (
    <div className="relative h-full overflow-hidden rounded-lg border border-white/[0.06] bg-ink-950 p-3 font-mono text-[11px] leading-5 text-zinc-500">
      {rows.map((r, i) => (
        <div key={i} style={{ opacity: 0.25 + (i / rows.length) * 0.75 }}>
          <span className="text-zinc-600">{(0x1a40 + i * 16).toString(16).padStart(6, '0')}  </span>{r}
        </div>
      ))}
    </div>
  );
}

export function PipelineOverlay({ run, onClose }: { run: RunState; onClose: () => void }) {
  const doneCount = Object.keys(run.done).length;
  const pct = (doneCount / STAGES.length) * 100;
  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="fixed inset-0 z-50 grid place-items-center bg-ink-950/85 p-4 backdrop-blur-md">
      <motion.div initial={{ scale: 0.95, y: 10, filter: 'blur(8px)' }} animate={{ scale: 1, y: 0, filter: 'blur(0px)' }} className="relative w-full max-w-4xl rounded-2xl border border-white/10 bg-ink-900 p-6 shadow-[0_30px_80px_-30px_rgba(0,0,0,0.9)] sm:p-8">
        <div className="flex flex-wrap items-end justify-between gap-3">
          <div>
            <div className="inline-flex items-center gap-2 rounded-full border border-white/[0.08] bg-white/[0.03] px-3 py-1 text-xs font-bold tracking-[0.14em] text-zinc-400 uppercase"><span className="h-1.5 w-1.5 animate-pulse rounded-full bg-accent" />Passive analysis in progress</div>
            <div className="mt-3 text-3xl font-bold text-white">{run.file}</div>
            <div className="text-sm text-zinc-500">{fmtBytes(run.size)} · processed locally in your browser</div>
          </div>
          <div className="text-4xl font-bold text-white tabular-nums">{Math.round(pct)}<span className="text-lg text-zinc-500">%</span></div>
        </div>
        <div className="mt-5 h-1.5 overflow-hidden rounded-full bg-white/5">
          <motion.div className="h-full rounded-full bg-zinc-50" animate={{ width: `${pct}%` }} transition={{ duration: 0.4 }} />
        </div>
        <div className="mt-6 grid gap-6 md:grid-cols-[1fr_0.8fr]">
          <ol className="space-y-1.5">
            {STAGES.map((s, i) => {
              const done = run.done[s.id];
              const active = run.active === s.id && !run.error;
              return (
                <motion.li key={s.id} initial={{ opacity: 0, x: -10 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: i * 0.04 }}
                  className={`flex items-center gap-3 rounded-xl px-3 py-2 transition ${active ? 'bg-white/[0.05] ring-1 ring-white/10' : ''}`}>
                  <span className={`grid h-7 w-7 shrink-0 place-items-center rounded-full ${done ? 'bg-[#3fb27f]/10 text-[#3fb27f]' : active ? 'bg-accent/10 text-accent' : 'bg-white/5 text-zinc-600'}`}>
                    {done ? <Check size={15} /> : active ? <Loader2 size={15} className="animate-spin" /> : <span className="font-mono text-[11px]">{i + 1}</span>}
                  </span>
                  <div className="min-w-0 flex-1">
                    <div className={`text-sm font-semibold ${done || active ? 'text-white' : 'text-zinc-500'}`}>{s.label}</div>
                    <div className="text-xs text-zinc-500">{s.detail}</div>
                  </div>
                  {done && <motion.span initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="font-mono text-xs text-zinc-100">{done}</motion.span>}
                </motion.li>
              );
            })}
          </ol>
          <div className="hidden min-h-[300px] md:block"><HexRain /></div>
        </div>
        {run.error && (
          <div className="mt-5 flex items-center justify-between gap-3 rounded-xl bg-[#f05252]/10 px-4 py-3 text-sm text-[#f05252] ring-1 ring-[#f05252]/30">
            <span className="flex items-center gap-2"><AlertTriangle size={16} /> {run.error}</span>
            <button onClick={onClose} className="rounded-lg bg-white/10 px-3 py-1 text-white">Close</button>
          </div>
        )}
      </motion.div>
    </motion.div>
  );
}
