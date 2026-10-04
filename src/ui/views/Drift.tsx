import { motion } from 'motion/react';
import { BrainCircuit, FileBadge2, GitCompareArrows, ScanSearch } from 'lucide-react';
import { useStore } from '../store.tsx';
import { PageTitle } from '../Shell.tsx';
import { Card, PROTO_COLOR, SEV } from '../common.tsx';
import { FEATURE_NAMES, RISK_WEIGHTS } from '../../engine/intel.ts';
import { cipherInfo, groupName, versionName } from '../../engine/catalog.ts';
import type { EmailProtocol, EmailSession } from '../../engine/types.ts';

const fieldVal = (s: EmailSession, f: string) => {
  const sh = s.tls?.serverHello;
  switch (f) {
    case 'TLS version': return sh ? versionName(sh.version) : s.tls ? 'aborted' : 'none';
    case 'Cipher suite': return sh ? cipherInfo(sh.cipher).name : 'none';
    case 'Key exchange': return sh ? (cipherInfo(sh.cipher).kx === 'RSA' ? 'RSA (static)' : groupName(s.tls?.kxGroup)) : 'none';
    case 'STARTTLS offered': return s.mode === 'IMPLICIT_TLS' ? 'implicit' : s.starttlsAdvertised ? 'yes' : 'no';
    default: return s.tls?.certificates[0]?.issuerCN ?? (sh?.version === 0x0304 ? '(encrypted)' : 'none');
  }
};
const short = (v: string) => v.replace(/^TLS_/, '').replace('_WITH_', ' ').replace(/_/g, '-').slice(0, 26);

export function Drift() {
  const { a, openSession } = useStore();
  const fields = ['TLS version', 'Cipher suite', 'Key exchange', 'STARTTLS offered', 'Certificate issuer'];
  const svc = a.baselines.filter((b) => b.sessions.length >= 2).sort((x, y) => y.sessions.length - x.sessions.length);

  // certificate lineage
  const byCN = new Map<string, { issuer: string; fp: string; sessions: string[] }[]>();
  for (const s of a.sessions) {
    const c = s.tls?.certificates[0]; if (!c) continue;
    const arr = byCN.get(c.subjectCN) ?? [];
    const e = arr.find((x) => x.fp === c.fingerprint);
    if (e) e.sessions.push(s.id); else arr.push({ issuer: c.issuerCN, fp: c.fingerprint, sessions: [s.id] });
    byCN.set(c.subjectCN, arr);
  }

  return (
    <>
      <PageTitle kicker="Behavioural intelligence" title="Drift & AI Analysis"
        sub="Per-service cryptographic baselines learned from the capture itself. Sessions that deviate from how their peers were treated are surfaced — not just “TLS 1.0 detected”, but “this client was downgraded”." />

      <div className="space-y-4">
        {svc.map((b, bi) => {
          const ss = a.sessions.filter((s) => b.sessions.includes(s.id));
          const proto = b.service.split('/')[1] as EmailProtocol;
          return (
            <Card key={b.service} delay={bi * 0.05} title={<span className="flex items-center gap-2 normal-case tracking-normal"><span className="font-mono" style={{ color: PROTO_COLOR[proto] }}>{proto}</span><span className="font-mono text-zinc-300">{b.service.split('/')[0]}</span><span className="text-zinc-500">· baseline from {b.sessions.length} sessions{b.sessions.length < 3 && ' (too few for drift scoring — see certificate lineage)'}</span></span>} icon={<GitCompareArrows size={15} />}>
              <div className="overflow-x-auto">
                <table className="w-full min-w-[760px] border-separate border-spacing-1 text-xs">
                  <thead>
                    <tr className="text-left text-[10.5px] tracking-wider text-zinc-500 uppercase">
                      <th className="px-2 font-medium">Session</th>
                      {fields.map((f) => <th key={f} className="px-2 font-medium">{f}</th>)}
                      <th className="px-2 font-medium">Verdict</th>
                    </tr>
                    <tr>
                      <td className="rounded-lg bg-accent/10 px-2 py-1.5 font-semibold text-zinc-100">Baseline</td>
                      {fields.map((f) => <td key={f} className="rounded-lg bg-accent/10 px-2 py-1.5 font-mono text-zinc-100">{short(b.fields[f]?.[0]?.value ?? '—')} <span className="text-accent/60">{Math.round(((b.fields[f]?.[0]?.count ?? 0) / b.sessions.length) * 100)}%</span></td>)}
                      <td className="rounded-lg bg-accent/10 px-2 py-1.5" />
                    </tr>
                  </thead>
                  <tbody>
                    {ss.map((s, i) => {
                      let devs = 0;
                      return (
                        <motion.tr key={s.id} initial={{ opacity: 0, x: -6 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: 0.1 + i * 0.04 }} className="cursor-pointer" onClick={() => openSession(s.id)}>
                          <td className="rounded-lg bg-white/[0.03] px-2 py-1.5 font-mono font-bold text-white">{s.id}<span className="ml-2 font-normal text-zinc-500">{s.stream.client}</span></td>
                          {fields.map((f) => {
                            const v = fieldVal(s, f), base = b.fields[f]?.[0];
                            const dev = b.sessions.length >= 3 && base && base.count / b.sessions.length >= 0.5 && v !== base.value && v !== '(encrypted)' && base.value !== '(encrypted)';
                            if (dev) devs++;
                            return <td key={f} className={`rounded-lg px-2 py-1.5 font-mono ${dev ? 'bg-[#f05252]/10 text-[#f05252] ring-1 ring-[#f05252]/30' : 'bg-[#3fb27f]/10 text-[#3fb27f]'}`}>{short(v)}</td>;
                          })}
                          <td className={`rounded-lg px-2 py-1.5 font-semibold ${devs ? 'text-[#f05252]' : b.sessions.length < 3 ? 'text-zinc-500' : 'text-[#3fb27f]'}`}>{devs ? `← ${devs} deviation${devs > 1 ? 's' : ''}` : b.sessions.length < 3 ? 'n/a' : 'consistent'}</td>
                        </motion.tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </Card>
          );
        })}

        <div className="grid gap-4 xl:grid-cols-[1.3fr_1fr]">
          <Card title="Isolation Forest — session anomaly scores" icon={<ScanSearch size={15} />}>
            <AnomalyPlot />
          </Card>
          <Card title="Certificate lineage" icon={<FileBadge2 size={15} />}>
            <div className="space-y-4">
              {[...byCN.entries()].map(([cn, list]) => {
                const issuers = new Set(list.map((l) => l.issuer));
                const broken = issuers.size > 1;
                return (
                  <div key={cn} className={`rounded-xl p-3 ring-1 ${broken ? 'bg-[#f05252]/10 ring-[#f05252]/30' : 'bg-white/[0.02] ring-white/5'}`}>
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-sm font-semibold text-white">{cn}</span>
                      <span className={`text-[11px] font-semibold ${broken ? 'text-[#f05252]' : 'text-[#3fb27f]'}`}>{broken ? 'LINEAGE BREAK' : 'consistent'}</span>
                    </div>
                    <div className="mt-2 space-y-1.5">
                      {list.map((l) => (
                        <div key={l.fp} className="flex items-center gap-2 text-xs">
                          <span className="h-2 w-2 rounded-full" style={{ background: broken && list.filter((x) => x.issuer === l.issuer).reduce((n, x) => n + x.sessions.length, 0) < Math.max(...[...issuers].map((iss) => list.filter((x) => x.issuer === iss).reduce((n, x) => n + x.sessions.length, 0))) ? '#f05252' : '#3fb27f' }} />
                          <span className="text-zinc-300">{l.issuer}</span>
                          <span className="font-mono text-[10.5px] text-zinc-500">{l.fp.slice(0, 12)}…</span>
                          <span className="ml-auto font-mono text-[11px] text-zinc-400">{l.sessions.join(' ')}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                );
              })}
              {byCN.size === 0 && <div className="text-sm text-zinc-500">No certificates observable (all TLS 1.3).</div>}
            </div>
          </Card>
        </div>

        <Card title="Model card — explainable risk model" icon={<BrainCircuit size={15} />}>
          <div className="grid gap-6 lg:grid-cols-3">
            <div className="text-sm leading-relaxed text-zinc-300">
              <p><b className="text-white">Unsupervised:</b> Isolation Forest (200 trees, sub-sample ψ ≤ 64, seeded) over a {FEATURE_NAMES.length}-dimensional per-session feature vector. Scores near 1 are isolated in few splits.</p>
              <p className="mt-3"><b className="text-white">Supervised-style:</b> ordinal logistic risk model with expert-calibrated weights; outputs P(critical / high / medium / low) and additive feature attributions for every session.</p>
              <p className="mt-3"><b className="text-white">Drift:</b> majority baselines per server:port/protocol, TLS-fallback correlation per client, and certificate-lineage tracking per subject CN.</p>
            </div>
            <div className="lg:col-span-2">
              <div className="grid grid-cols-2 gap-x-6 gap-y-1.5 text-xs">
                {FEATURE_NAMES.map((f, i) => {
                  const w = RISK_WEIGHTS[i];
                  return (
                    <div key={f} className="flex items-center gap-2">
                      <span className="w-44 shrink-0 text-zinc-400">{f}</span>
                      <div className="relative h-2 flex-1 rounded-full bg-white/5">
                        <motion.div initial={{ width: 0 }} animate={{ width: `${(Math.abs(w) / 3.4) * 50}%` }} transition={{ delay: i * 0.03 }}
                          className="absolute top-0 h-full rounded-full" style={{ left: w < 0 ? undefined : '50%', right: w < 0 ? '50%' : undefined, background: w < 0 ? '#3fb27f' : '#f05252' }} />
                        <span className="absolute top-[-2px] left-1/2 h-3 w-px bg-zinc-500" />
                      </div>
                      <span className={`w-9 text-right font-mono ${w < 0 ? 'text-[#3fb27f]' : 'text-[#f05252]'}`}>{w > 0 ? '+' : ''}{w}</span>
                    </div>
                  );
                })}
              </div>
              <div className="mt-3 text-[11px] text-zinc-500">Green = protective property (risk added when absent) · Red = risk indicator (risk added when present)</div>
            </div>
          </div>
        </Card>
      </div>
    </>
  );
}

function AnomalyPlot() {
  const { a, openSession } = useStore();
  const W = 640, H = 260, L = 40, B = 30;
  const n = a.ml.length;
  const ys = (v: number) => H - B - ((v - 0.3) / 0.5) * (H - B - 14);
  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="w-full">
      {[0.3, 0.4, 0.5, 0.6, 0.7, 0.8].map((v) => (
        <g key={v}><line x1={L} x2={W - 10} y1={ys(v)} y2={ys(v)} stroke="#27272a" /><text x={L - 8} y={ys(v) + 3} textAnchor="end" fontSize="10" fill="#71717a" fontFamily="JetBrains Mono">{v.toFixed(1)}</text></g>
      ))}
      <line x1={L} x2={W - 10} y1={ys(0.6)} y2={ys(0.6)} stroke="#9b8cf0" strokeDasharray="5 4" />
      <text x={W - 12} y={ys(0.6) - 6} textAnchor="end" fontSize="10" fill="#9b8cf0">anomaly threshold</text>
      {a.ml.map((m, i) => {
        const x = L + 16 + (i / Math.max(1, n - 1)) * (W - L - 40);
        const c = SEV[m.riskClass].color;
        return (
          <g key={m.session} className="cursor-pointer" onClick={() => openSession(m.session)}>
            <motion.line x1={x} x2={x} y1={H - B} initial={{ y2: H - B }} animate={{ y2: ys(Math.max(0.3, m.anomaly)) }} transition={{ delay: i * 0.03, duration: 0.6 }} stroke={c} strokeOpacity={0.3} />
            <motion.circle cx={x} initial={{ cy: H - B, r: 0 }} animate={{ cy: ys(Math.max(0.3, m.anomaly)), r: 6 }} transition={{ delay: i * 0.03, duration: 0.6 }} fill={c} />
            <text x={x} y={H - 12} textAnchor="middle" fontSize="9" fill="#a1a1aa" fontFamily="JetBrains Mono">{m.session}</text>
            <title>{`${m.session}: anomaly ${m.anomaly.toFixed(3)} · risk ${m.riskClass}`}</title>
          </g>
        );
      })}
    </svg>
  );
}
