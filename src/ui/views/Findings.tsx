import { motion } from 'motion/react';
import { useState } from 'react';
import { ArrowDown, BookOpen, BrainCircuit, CheckCircle2, Circle, Crosshair, GitCompareArrows, ShieldAlert, Siren, Wrench, Cog } from 'lucide-react';
import { useStore } from '../store.tsx';
import { PageTitle } from '../Shell.tsx';
import { Bar, Card, Pill, SEV, SEV_ORDER, SevBadge } from '../common.tsx';
import { DIM_LABEL } from '../../engine/intel.ts';
import type { Severity } from '../../engine/types.ts';

const SRC = { rule: { l: 'Rule engine', c: '#5b8def', i: Cog }, drift: { l: 'Cross-session drift', c: '#d99ab8', i: GitCompareArrows }, ml: { l: 'ML anomaly', c: '#9b8cf0', i: BrainCircuit } };

export function Findings() {
  const { a, finding, openFinding, openSession, resolved, setResolved } = useStore();
  const [sev, setSev] = useState<Severity | 'all'>('all');
  const list = a.findings.filter((f) => sev === 'all' || f.severity === sev);
  const f = a.findings.find((x) => x.id === finding) ?? list[0];
  const toggle = (id: string) => { const n = new Set(resolved); if (n.has(id)) n.delete(id); else n.add(id); setResolved(n); };

  return (
    <>
      <PageTitle kicker="Threat prioritisation" title="Prioritised Findings"
        sub="Ranked by severity × evidence confidence × AI risk probability × blast radius. Every finding is traceable to frames in the capture." />
      <div className="mb-4 flex flex-wrap gap-2">
        {(['all', ...SEV_ORDER.filter((s) => a.findings.some((x) => x.severity === s))] as const).map((s) => (
          <button key={s} onClick={() => setSev(s)} className={`rounded-full px-3 py-1 text-xs font-medium ring-1 transition ${sev === s ? 'bg-white/10 text-white ring-white/25' : 'text-zinc-400 ring-white/10 hover:text-white'}`}>
            {s === 'all' ? `All ${a.findings.length}` : `${SEV[s].label} ${a.findings.filter((x) => x.severity === s).length}`}
          </button>
        ))}
      </div>
      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(0,1.15fr)]">
        <div className="space-y-2">
          {list.map((x, i) => {
            const on = f?.id === x.id;
            const S = SRC[x.source];
            return (
              <motion.button key={x.id} onClick={() => openFinding(x.id)} initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.025 }}
                className={`glass flex w-full items-center gap-3 rounded-xl p-3 text-left transition ${on ? '!border-accent/40 bg-accent/10' : 'hover:border-white/20'} ${resolved.has(x.id) ? 'opacity-45' : ''}`}>
                <span className="grid h-9 w-9 shrink-0 place-items-center rounded-lg font-mono text-sm font-bold" style={{ color: SEV[x.severity].color, background: SEV[x.severity].bg }}>{x.priority}</span>
                <div className="min-w-0 flex-1">
                  <div className={`truncate text-sm font-medium text-white ${resolved.has(x.id) ? 'line-through' : ''}`}>{x.title}</div>
                  <div className="mt-1 flex items-center gap-2 text-[11px] text-zinc-500">
                    <span className="font-mono">{x.ruleId}</span>·<span style={{ color: S.c }}>{S.l}</span>·<span>{x.sessions.length} session{x.sessions.length > 1 ? 's' : ''}</span>
                  </div>
                </div>
                <SevBadge sev={x.severity} />
              </motion.button>
            );
          })}
        </div>

        {f && (
          <motion.div key={f.id} initial={{ opacity: 0, x: 10 }} animate={{ opacity: 1, x: 0 }} className="xl:sticky xl:top-20 xl:self-start">
            <Card className="overflow-hidden">
              <div className="relative">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-mono text-xs text-zinc-500">{f.id} · {f.ruleId}</span>
                  <SevBadge sev={f.severity} />
                  <Pill color={SRC[f.source].c}>{SRC[f.source].l}</Pill>
                  <Pill color="#a1a1aa">{DIM_LABEL[f.dimension]}</Pill>
                </div>
                <h2 className="mt-2 text-2xl font-bold text-white">{f.title}</h2>
                <div className="mt-4 grid grid-cols-3 gap-3">
                  {[['Priority', `#${f.priority}`, '#5b8def', 100 - ((f.priority ?? 1) - 1) / a.findings.length * 100], ['Evidence confidence', `${Math.round(f.confidence * 100)}%`, '#3fb27f', f.confidence * 100], ['AI P(high-impact)', `${Math.round((f.mlScore ?? 0) * 100)}%`, '#9b8cf0', (f.mlScore ?? 0) * 100]].map(([k, v, c, p]) => (
                    <div key={k as string} className="rounded-xl bg-white/[0.03] p-3 ring-1 ring-white/5">
                      <div className="text-[11px] text-zinc-500">{k}</div>
                      <div className="text-xl font-bold" style={{ color: c as string }}>{v}</div>
                      <div className="mt-1.5"><Bar value={p as number} color={c as string} h={3} /></div>
                    </div>
                  ))}
                </div>

                <div className="mt-5 text-xs font-semibold tracking-wider text-zinc-400 uppercase">Causal risk mapping</div>
                <div className="mt-2 space-y-1">
                  {[[Crosshair, 'Weakness / cause', f.cause, '#d9a92b'], [Siren, 'Security exposure', f.exposure, SEV[f.severity].color], [Wrench, 'Recommended action', f.remediation, '#3fb27f']].map(([I, k, v, c], i) => (
                    <div key={k as string}>
                      <div className="flex gap-3 rounded-xl p-3" style={{ background: `${c}0d`, boxShadow: `inset 0 0 0 1px ${c}30` }}>
                        <I size={18} style={{ color: c as string }} className="mt-0.5 shrink-0" />
                        <div><div className="text-[11px] font-semibold tracking-wider uppercase" style={{ color: c as string }}>{k as string}</div><div className="mt-0.5 text-sm text-zinc-200">{v as string}</div></div>
                      </div>
                      {i < 2 && <ArrowDown size={14} className="mx-auto my-0.5 text-zinc-600" />}
                    </div>
                  ))}
                </div>

                <div className="mt-5 text-xs font-semibold tracking-wider text-zinc-400 uppercase">Evidence ({f.evidence.length})</div>
                <div className="mt-2 space-y-2">
                  {f.evidence.map((e, i) => (
                    <div key={i} className="rounded-xl bg-black/30 p-3 ring-1 ring-white/5">
                      <div className="flex items-center gap-2 text-xs">
                        <button onClick={() => openSession(e.session)} className="rounded bg-accent/10 px-1.5 py-0.5 font-mono font-bold text-accent hover:bg-accent/10">{e.session} ↗</button>
                        <span className="text-zinc-400">{e.label}</span>
                        <span className="ml-auto font-mono text-[11px] text-zinc-500">frames {e.frames.map((x) => `#${x}`).join(', ')}</span>
                      </div>
                      <div className="mt-1.5 font-mono text-[12px] break-words text-zinc-300">{e.detail}</div>
                    </div>
                  ))}
                </div>

                {f.references.length > 0 && (
                  <div className="mt-4 flex flex-wrap items-center gap-2 text-xs text-zinc-400"><BookOpen size={14} />{f.references.map((r) => <span key={r} className="rounded bg-white/5 px-2 py-0.5">{r}</span>)}</div>
                )}
                <button onClick={() => toggle(f.id)} className={`mt-5 flex w-full items-center justify-center gap-2 rounded-xl py-2.5 text-sm font-semibold transition ${resolved.has(f.id) ? 'bg-[#3fb27f]/10 text-[#3fb27f] ring-1 ring-[#3fb27f]/30' : 'bg-white/5 text-white ring-1 ring-white/10 hover:bg-white/10'}`}>
                  {resolved.has(f.id) ? <><CheckCircle2 size={16} /> Marked as remediated (what-if)</> : <><Circle size={16} /> Mark as remediated in what-if simulation</>}
                </button>
              </div>
            </Card>
          </motion.div>
        )}
        {!f && <Card><ShieldAlert /> No findings.</Card>}
      </div>
    </>
  );
}
