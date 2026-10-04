import { motion } from 'motion/react';
import { ArrowRight, CheckCircle2, Circle, FlaskConical, Sparkles, TrendingUp } from 'lucide-react';
import { useStore } from '../store.tsx';
import { PageTitle } from '../Shell.tsx';
import { Card, SEV, ScoreRing, scoreColor } from '../common.tsx';
import { DIM_LABEL, posture } from '../../engine/intel.ts';
import type { Dimension } from '../../engine/types.ts';

const PLAYS: { label: string; dims: Dimension[]; desc: string }[] = [
  { label: 'Enforce TLS on every mail service', dims: ['starttls', 'protocol'], desc: 'smtpd_tls_auth_only, MTA-STS enforce, disable cleartext POP3/IMAP login' },
  { label: 'TLS ≥ 1.2, AEAD + ECDHE only', dims: ['tls', 'cipher', 'keyExchange'], desc: 'remove TLS 1.0/1.1, RC4, 3DES, static RSA' },
  { label: 'Re-issue & pin certificates', dims: ['certificate'], desc: 'RSA-3072/P-256, SHA-256, enterprise CA, remove interception proxy' },
  { label: 'Investigate behavioural anomalies', dims: ['anomaly'], desc: 'trace downgrade path, block injecting relay' },
];

export function Simulator() {
  const { a, resolved, setResolved } = useStore();
  const before = a.posture;
  const after = posture(a.findings, a.sessions, resolved);
  const delta = after.overall - before.overall;
  const toggle = (id: string) => { const n = new Set(resolved); if (n.has(id)) n.delete(id); else n.add(id); setResolved(n); };
  const play = (dims: Dimension[]) => {
    const ids = a.findings.filter((f) => dims.includes(f.dimension)).map((f) => f.id);
    const allOn = ids.every((i) => resolved.has(i));
    const n = new Set(resolved);
    ids.forEach((i) => (allOn ? n.delete(i) : n.add(i)));
    setResolved(n);
  };

  return (
    <>
      <PageTitle kicker="Remediation what-if" title="Posture Simulation"
        sub="Toggle remediations to project how the cryptographic posture changes — computed with the same scoring model, without modifying the original capture."
        right={<button onClick={() => setResolved(new Set())} className="rounded-xl border border-white/10 px-3 py-1.5 text-sm text-zinc-300 hover:bg-white/5">Reset simulation</button>} />

      <div className="grid gap-4 xl:grid-cols-[1fr_1.1fr]">
        <div className="space-y-4">
          <Card title="Remediation playbooks" icon={<Sparkles size={15} />}>
            <div className="grid gap-2 sm:grid-cols-2">
              {PLAYS.map((p) => {
                const ids = a.findings.filter((f) => p.dims.includes(f.dimension)).map((f) => f.id);
                const on = ids.length > 0 && ids.every((i) => resolved.has(i));
                return (
                  <button key={p.label} disabled={!ids.length} onClick={() => play(p.dims)}
                    className={`rounded-xl p-3 text-left ring-1 transition disabled:opacity-40 ${on ? 'bg-[#3fb27f]/10 ring-[#3fb27f]/30' : 'bg-white/[0.03] ring-white/10 hover:ring-accent/40'}`}>
                    <div className="flex items-center gap-2 text-sm font-semibold text-white">{on ? <CheckCircle2 size={16} className="text-[#3fb27f]" /> : <Circle size={16} className="text-zinc-500" />}{p.label}</div>
                    <div className="mt-1 pl-6 text-xs text-zinc-400">{p.desc}</div>
                    <div className="mt-1 pl-6 text-[11px] text-accent">{ids.length} finding{ids.length === 1 ? '' : 's'}</div>
                  </button>
                );
              })}
            </div>
          </Card>
          <Card title="Individual fixes" icon={<FlaskConical size={15} />}>
            <div className="max-h-[480px] space-y-1.5 overflow-y-auto pr-1">
              {a.findings.map((f) => {
                const on = resolved.has(f.id);
                return (
                  <button key={f.id} onClick={() => toggle(f.id)} className={`flex w-full items-center gap-3 rounded-lg p-2.5 text-left transition ${on ? 'bg-[#3fb27f]/10' : 'hover:bg-white/[0.04]'}`}>
                    <span className={`grid h-5 w-9 shrink-0 items-center rounded-full p-0.5 transition ${on ? 'bg-[#3fb27f]' : 'bg-white/10'}`}>
                      <motion.span layout className={`h-4 w-4 rounded-full bg-white ${on ? 'justify-self-end' : ''}`} />
                    </span>
                    <span className="h-2 w-2 shrink-0 rounded-full" style={{ background: SEV[f.severity].color }} />
                    <span className={`flex-1 truncate text-sm ${on ? 'text-zinc-400 line-through' : 'text-zinc-200'}`}>{f.title}</span>
                    <span className="font-mono text-[11px] text-zinc-500">{f.id}</span>
                  </button>
                );
              })}
            </div>
          </Card>
        </div>

        <div className="space-y-4 xl:sticky xl:top-20 xl:self-start">
          <Card>
            <div className="flex flex-col items-center justify-around gap-6 sm:flex-row">
              <div className="text-center"><div className="mb-2 text-xs tracking-widest text-zinc-500 uppercase">Observed</div><ScoreRing score={before.overall} size={170} label={before.label} sub={`Grade ${before.grade}`} /></div>
              <div className="flex flex-col items-center">
                <ArrowRight className="text-zinc-500" />
                <motion.div key={delta} initial={{ scale: 0.7, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} className="mt-2 rounded-full px-3 py-1 text-lg font-bold" style={{ color: delta > 0 ? '#3fb27f' : '#a1a1aa', background: delta > 0 ? 'rgb(52 211 153 / 0.1)' : 'rgb(148 163 184 / 0.1)' }}>
                  {delta > 0 ? '+' : ''}{delta}
                </motion.div>
              </div>
              <div className="text-center"><div className="mb-2 text-xs tracking-widest text-zinc-500 uppercase">Projected</div><ScoreRing key={after.overall} score={after.overall} size={170} label={after.label} sub={`Grade ${after.grade}`} /></div>
            </div>
          </Card>
          <Card title="Dimension impact" icon={<TrendingUp size={15} />}>
            <div className="space-y-3.5">
              {(Object.keys(before.dimensions) as Dimension[]).map((d) => {
                const b = before.dimensions[d], x = after.dimensions[d];
                return (
                  <div key={d}>
                    <div className="mb-1 flex justify-between text-xs"><span className="text-zinc-300">{DIM_LABEL[d]}</span><span className="font-mono"><span className="text-zinc-500">{b}</span> → <span style={{ color: scoreColor(x) }}>{x}</span></span></div>
                    <div className="relative h-2 overflow-hidden rounded-full bg-white/5">
                      <motion.div className="absolute h-full rounded-full" style={{ background: scoreColor(x) }} animate={{ width: `${x}%` }} transition={{ duration: 0.6 }} />
                      <div className="absolute h-full border-r-2 border-white/70" style={{ width: `${b}%` }} />
                    </div>
                  </div>
                );
              })}
            </div>
            <div className="mt-4 rounded-xl bg-white/[0.03] p-3 text-xs text-zinc-400 ring-1 ring-white/5">
              {resolved.size === 0 ? 'Select playbooks or individual fixes to project the post-remediation posture.' :
                `${resolved.size} of ${a.findings.length} findings remediated · ${a.findings.filter((f) => !resolved.has(f.id) && (f.severity === 'critical' || f.severity === 'high')).length} critical/high remaining.`}
            </div>
          </Card>
        </div>
      </div>
    </>
  );
}
