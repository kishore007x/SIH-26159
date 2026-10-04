import { AnimatePresence, motion } from 'motion/react';
import { BrainCircuit, FileDown, FlaskConical, LayoutDashboard, ListTree, RotateCcw, Share2, ShieldAlert } from 'lucide-react';
import { useStore, type View } from './store.tsx';
import { Logo } from './Landing.tsx';
import { fmtBytes, fmtTime, scoreColor } from './common.tsx';
import { Overview } from './views/Overview.tsx';
import { Sessions } from './views/Sessions.tsx';
import { Findings } from './views/Findings.tsx';
import { Graph } from './views/Graph.tsx';
import { Drift } from './views/Drift.tsx';
import { Simulator } from './views/Simulator.tsx';
import { Reports } from './views/Reports.tsx';

const NAV: { id: View; label: string; icon: typeof LayoutDashboard }[] = [
  { id: 'overview', label: 'Posture Overview', icon: LayoutDashboard },
  { id: 'findings', label: 'Prioritised Findings', icon: ShieldAlert },
  { id: 'sessions', label: 'Session Forensics', icon: ListTree },
  { id: 'graph', label: 'Crypto Security Graph', icon: Share2 },
  { id: 'drift', label: 'Drift & AI Analysis', icon: BrainCircuit },
  { id: 'simulator', label: 'Remediation What-If', icon: FlaskConical },
  { id: 'reports', label: 'Forensic Reports', icon: FileDown },
];

export function Shell() {
  const { a, view, go, reset } = useStore();
  const counts: Partial<Record<View, number>> = { findings: a.findings.length, sessions: a.sessions.length };
  const crit = a.findings.filter((f) => f.severity === 'critical').length;
  const color = scoreColor(a.posture.overall);
  const current = NAV.find((n) => n.id === view)!;
  return (
    <div className="flex min-h-full bg-ink-950">
      <aside className="no-print sticky top-0 hidden h-screen w-[264px] shrink-0 flex-col border-r border-white/[0.06] bg-ink-900 px-3 py-4 lg:flex">
        <div className="px-2"><Logo small /></div>
        <div className="mt-7 px-3 text-[11px] font-bold tracking-[0.16em] text-zinc-600 uppercase">Investigation</div>
        <nav className="mt-2 space-y-0.5">
          {NAV.map((n) => {
            const on = view === n.id;
            return (
              <button key={n.id} onClick={() => go(n.id)}
                className={`relative flex w-full items-center gap-3 rounded-lg px-3 py-2 text-left text-[15px] transition ${on ? 'text-white' : 'text-zinc-400 hover:bg-white/[0.04] hover:text-zinc-100'}`}>
                {on && <motion.span layoutId="nav-on" transition={{ type: 'spring', stiffness: 400, damping: 34 }} className="absolute inset-0 rounded-lg border border-white/[0.08] bg-white/[0.06] shadow-[0_1px_0_0_rgba(255,255,255,0.06)_inset]" />}
                {on && <motion.span layoutId="nav-bar" className="absolute top-2 bottom-2 -left-3 w-[3px] rounded-r-full bg-zinc-50" />}
                <n.icon size={17} className={`relative ${on ? 'text-zinc-100' : ''}`} />
                <span className="relative flex-1">{n.label}</span>
                {counts[n.id] !== undefined && <span className="relative rounded-md border border-white/[0.06] bg-white/[0.03] px-1.5 font-mono text-[11px] text-zinc-400">{counts[n.id]}</span>}
              </button>
            );
          })}
        </nav>
        <div className="mt-auto space-y-3">
          <div className="relative overflow-hidden rounded-xl border border-white/[0.07] bg-white/[0.02] p-4">
            <div className="relative flex items-center gap-3">
              <span className="grid h-11 w-11 place-items-center rounded-xl text-xl font-bold text-zinc-950" style={{ background: color }}>{a.posture.grade}</span>
              <div><div className="text-2xl leading-none font-bold text-white">{a.posture.overall}<span className="text-sm text-zinc-500">/100</span></div><div className="text-xs text-zinc-400">{a.posture.label}</div></div>
            </div>
            <div className="relative mt-3 truncate font-mono text-[11px] text-zinc-400" title={a.fileName}>{a.fileName}</div>
            <div className="relative text-xs text-zinc-500">{a.capture.format.toUpperCase()} · {fmtBytes(a.fileSize)} · {a.capture.packetCount} frames</div>
            <div className="relative mt-2 flex items-center gap-1.5 text-xs text-zinc-500"><span className="h-1.5 w-1.5 rounded-full bg-[#3fb27f]" /> Analysed offline · 0 bytes uploaded</div>
          </div>
          <button onClick={reset} className="flex w-full items-center justify-center gap-2 rounded-lg border border-white/[0.08] py-2 text-[15px] text-zinc-300 transition hover:bg-white/[0.05]"><RotateCcw size={14} /> New analysis</button>
        </div>
      </aside>

      <div className="min-w-0 flex-1">
        <header className="no-print sticky top-0 z-30 border-b border-white/[0.06] bg-ink-950/75 backdrop-blur-xl">
          <div className="flex items-center gap-4 px-5 py-3 lg:px-8">
            <div className="lg:hidden"><Logo small /></div>
            <div className="hidden min-w-0 flex-1 items-center gap-2 text-[15px] md:flex">
              <span className="text-zinc-500">Investigations</span><span className="text-zinc-700">/</span>
              <span className="max-w-[260px] truncate font-mono text-[13px] text-zinc-400">{a.fileName}</span><span className="text-zinc-700">/</span>
              <span className="font-bold text-zinc-100">{current.label}</span>
              <span className="ml-3 hidden rounded-md border border-white/[0.06] bg-white/[0.02] px-2 py-0.5 font-mono text-[11px] text-zinc-500 xl:inline">{fmtTime(a.capture.start)} → {fmtTime(a.capture.end).slice(11)}</span>
            </div>
            <div className="ml-auto flex items-center gap-2.5">
              {crit > 0 && (
                <button onClick={() => go('findings')} className="hidden items-center gap-2 rounded-full border border-[#f05252]/25 bg-[#f05252]/10 px-3 py-1 text-sm font-bold text-[#f05252] sm:flex">
                  <span className="h-2 w-2 rounded-full bg-[#f05252]" />
                  {crit} critical
                </button>
              )}
              <button onClick={() => go('reports')} className="rounded-full bg-white px-4 py-1.5 text-sm font-bold text-zinc-950 transition hover:bg-zinc-200">Export report</button>
            </div>
          </div>
          <div className="flex gap-1 overflow-x-auto px-3 pb-2 lg:hidden">
            {NAV.map((n) => (
              <button key={n.id} onClick={() => go(n.id)} className={`shrink-0 rounded-lg px-3 py-1.5 text-sm ${view === n.id ? 'bg-white/10 text-white' : 'text-zinc-400'}`}>{n.label}</button>
            ))}
          </div>
        </header>
        <main className="relative px-4 py-8 lg:px-8">
          <AnimatePresence mode="wait">
            <motion.div key={view} initial={{ opacity: 0, y: 8, filter: 'blur(4px)' }} animate={{ opacity: 1, y: 0, filter: 'blur(0px)' }} exit={{ opacity: 0, y: -6 }} transition={{ duration: 0.25 }} className="relative mx-auto max-w-[1500px]">
              {view === 'overview' && <Overview />}
              {view === 'sessions' && <Sessions />}
              {view === 'findings' && <Findings />}
              {view === 'graph' && <Graph />}
              {view === 'drift' && <Drift />}
              {view === 'simulator' && <Simulator />}
              {view === 'reports' && <Reports />}
            </motion.div>
          </AnimatePresence>
        </main>
      </div>
    </div>
  );
}

export function PageTitle({ kicker, title, sub, right }: { kicker: string; title: string; sub?: string; right?: React.ReactNode }) {
  return (
    <div className="mb-7 flex flex-wrap items-end justify-between gap-4">
      <div>
        <div className="text-sm font-bold text-accent">
          {kicker}
        </div>
        <h1 className="mt-3 text-[2.2rem] font-bold tracking-tight text-zinc-50">{title}</h1>
        {sub && <p className="mt-2 max-w-3xl text-[17px] leading-relaxed text-zinc-400">{sub}</p>}
      </div>
      {right}
    </div>
  );
}
