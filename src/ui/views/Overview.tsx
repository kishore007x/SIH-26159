import { motion } from 'motion/react';
import { Activity, AlertOctagon, ArrowUpRight, Award, BrainCircuit, FileBadge2, Gauge, Layers, Lock, Mail, Radar as RadarIcon, Timer } from 'lucide-react';
import { Cell, Pie, PieChart, PolarAngleAxis, PolarGrid, Radar, RadarChart, ResponsiveContainer, Tooltip } from 'recharts';
import { useStore } from '../store.tsx';
import { PageTitle } from '../Shell.tsx';
import { Bar, Card, Counter, PROTO_COLOR, SEV, SEV_ORDER, ScoreRing, SevBadge, scoreColor } from '../common.tsx';
import { DIM_LABEL } from '../../engine/intel.ts';
import { versionName } from '../../engine/catalog.ts';
import type { Dimension, EmailProtocol } from '../../engine/types.ts';

const tooltipStyle = { background: '#121215', border: '1px solid #27272a', borderRadius: 10, fontSize: 12, color: '#e4e4e7' };

export function Overview() {
  const { a, openFinding, openSession, go } = useStore();
  const { posture, sessions, findings, ml } = a;
  const sevCount = Object.fromEntries(SEV_ORDER.map((s) => [s, findings.filter((f) => f.severity === s).length]));
  const tlsSessions = sessions.filter((s) => s.tls?.serverHello);
  const certs = new Map(sessions.flatMap((s) => s.tls?.certificates.map((c) => [c.fingerprint, c] as const) ?? []));
  const anomalies = new Set([...ml.filter((m) => m.anomaly > 0.6 || m.deviations.length).map((m) => m.session), ...findings.filter((f) => f.source === 'drift').flatMap((f) => f.sessions)]);

  const protoData = (['SMTP', 'IMAP', 'POP3'] as EmailProtocol[]).map((p) => ({ name: p, value: sessions.filter((s) => s.protocol === p).length })).filter((d) => d.value);
  const vmap = new Map<string, number>();
  for (const s of sessions) {
    const k = s.tls?.serverHello ? versionName(s.tls.serverHello.version) : s.tls ? 'Aborted' : 'Plaintext';
    vmap.set(k, (vmap.get(k) ?? 0) + 1);
  }
  const VCOL: Record<string, string> = { 'TLS 1.3': '#3fb27f', 'TLS 1.2': '#5b8def', 'TLS 1.1': '#d9a92b', 'TLS 1.0': '#f08c3e', 'SSL 3.0': '#f05252', Plaintext: '#f05252', Aborted: '#71717a' };
  const versions = ['TLS 1.3', 'TLS 1.2', 'TLS 1.1', 'TLS 1.0', 'SSL 3.0', 'Aborted', 'Plaintext'].filter((v) => vmap.has(v)).map((v) => ({ v, n: vmap.get(v)! }));
  const radar = (Object.keys(posture.dimensions) as Dimension[]).map((d) => ({ dim: ({ keyExchange: 'Key Exch.', anomaly: 'Anomaly', tls: 'TLS', certificate: 'Cert' } as Record<string, string>)[d] ?? DIM_LABEL[d], score: posture.dimensions[d] }));
  const top = findings.slice(0, 6);
  const worst = (Object.entries(posture.dimensions) as [Dimension, number][]).sort((x, y) => x[1] - y[1])[0];
  const plainCred = findings.find((f) => f.ruleId === 'SMS-ST-002');

  return (
    <>
      <PageTitle kicker="Cryptographic security posture" title="Executive Overview"
        sub={`${sessions.length} email sessions reconstructed from ${a.capture.packetCount.toLocaleString()} frames across ${a.baselines.length} services.`} />

      <div className="grid gap-4 xl:grid-cols-[minmax(0,1.25fr)_minmax(0,1fr)_minmax(0,1fr)]">
        <Card className="overflow-hidden">
          <div className="relative flex flex-col items-center gap-6 sm:flex-row">
            <ScoreRing score={posture.overall} size={210} label={posture.label} sub={`Grade ${posture.grade}`} />
            <div className="flex-1">
              <div className="text-xs font-semibold tracking-[0.2em] text-zinc-500 uppercase">Overall assessment</div>
              <div className="mt-1 text-3xl font-bold" style={{ color: scoreColor(posture.overall) }}>{posture.label.toUpperCase()}</div>
              <p className="mt-3 text-sm leading-relaxed text-zinc-300">
                {sevCount.critical ? <><b className="text-[#f05252]">{sevCount.critical} critical</b> and </> : null}
                <b className="text-[#f08c3e]">{sevCount.high} high</b> severity issues across {new Set(findings.flatMap((f) => f.sessions)).size} of {sessions.length} sessions.
                {' '}Weakest dimension: <b className="text-white">{DIM_LABEL[worst[0]]}</b> ({worst[1]}/100).
                {plainCred && <> Mailbox credentials were observed in cleartext.</>}
              </p>
              <div className="mt-4 flex flex-wrap gap-2 text-xs">
                <span className="rounded-lg bg-white/5 px-2.5 py-1 text-zinc-300 ring-1 ring-white/10">Evidence confidence <b className="text-accent">{Math.round(posture.confidence * 100)}%</b></span>
                <span className="rounded-lg bg-white/5 px-2.5 py-1 text-zinc-300 ring-1 ring-white/10">Analysis <b className="text-accent">{a.timings.reduce((x, t) => x + t.ms, 0).toFixed(0)} ms</b></span>
              </div>
              <button onClick={() => go('simulator')} className="mt-4 inline-flex items-center gap-1.5 text-sm font-bold whitespace-nowrap text-accent hover:text-zinc-100">Simulate remediation impact <ArrowUpRight size={15} /></button>
            </div>
          </div>
        </Card>

        <Card title="Posture dimensions" icon={<Layers size={15} />} delay={0.05}>
          <div className="space-y-3">
            {(Object.entries(posture.dimensions) as [Dimension, number][]).map(([d, v], i) => (
              <div key={d}>
                <div className="mb-1 flex justify-between text-xs"><span className="text-zinc-300">{DIM_LABEL[d]}</span><span className="font-mono" style={{ color: scoreColor(v) }}>{v}</span></div>
                <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.1 + i * 0.05 }}><Bar value={v} color={scoreColor(v)} /></motion.div>
              </div>
            ))}
          </div>
        </Card>

        <Card title="Posture radar" icon={<RadarIcon size={15} />} delay={0.1}>
          <div className="h-[260px]">
            <ResponsiveContainer>
              <RadarChart data={radar} outerRadius="68%">
                <PolarGrid stroke="#27272a" />
                <PolarAngleAxis dataKey="dim" tick={{ fill: '#a1a1aa', fontSize: 10.5 }} />
                <Radar dataKey="score" stroke="#5b8def" fill="#5b8def" fillOpacity={0.22} strokeWidth={2} isAnimationActive />
                <Tooltip contentStyle={tooltipStyle} />
              </RadarChart>
            </ResponsiveContainer>
          </div>
        </Card>
      </div>

      <div className="mt-4 grid grid-cols-2 gap-4 md:grid-cols-3 xl:grid-cols-6">
        {[
          { icon: Mail, label: 'Email sessions', v: sessions.length, sub: `${a.streams} TCP streams`, c: '#5b8def' },
          { icon: Lock, label: 'TLS protected', v: Math.round((tlsSessions.length / Math.max(1, sessions.length)) * 100), suffix: '%', sub: `${tlsSessions.length} handshakes`, c: '#3fb27f' },
          { icon: AlertOctagon, label: 'Critical + High', v: sevCount.critical + sevCount.high, sub: `${findings.length} findings total`, c: '#f05252' },
          { icon: BrainCircuit, label: 'Anomalous sessions', v: anomalies.size, sub: 'drift + isolation forest', c: '#9b8cf0' },
          { icon: FileBadge2, label: 'Certificates', v: certs.size, sub: `${[...certs.values()].filter((c) => !c.isCA).length} leaf · ${[...certs.values()].filter((c) => c.isCA).length} CA`, c: '#d9a92b' },
          { icon: Timer, label: 'Frames decoded', v: a.capture.packetCount, sub: `${((a.capture.end - a.capture.start) / 60).toFixed(1)} min window`, c: '#5b8def' },
        ].map((k, i) => (
          <Card key={k.label} delay={0.12 + i * 0.04} className="!p-4">
            <div className="flex items-center justify-between">
              <span className="text-xs text-zinc-400">{k.label}</span>
              <k.icon size={16} style={{ color: k.c }} />
            </div>
            <div className="mt-2 text-3xl font-bold text-white"><Counter value={k.v} />{k.suffix && <span className="text-lg text-zinc-400">{k.suffix}</span>}</div>
            <div className="mt-0.5 text-[11px] text-zinc-500">{k.sub}</div>
          </Card>
        ))}
      </div>

      <div className="mt-4 grid gap-4 xl:grid-cols-3">
        <Card title="Protocol mix" icon={<Mail size={15} />} delay={0.2}>
          <div className="flex items-center gap-4">
            <div className="h-[170px] w-[170px]">
              <ResponsiveContainer>
                <PieChart>
                  <Pie data={protoData} dataKey="value" innerRadius={52} outerRadius={78} paddingAngle={3} stroke="none">
                    {protoData.map((d) => <Cell key={d.name} fill={PROTO_COLOR[d.name as EmailProtocol]} />)}
                  </Pie>
                  <Tooltip contentStyle={tooltipStyle} />
                </PieChart>
              </ResponsiveContainer>
            </div>
            <div className="flex-1 space-y-2">
              {protoData.map((d) => (
                <div key={d.name} className="flex items-center justify-between text-sm">
                  <span className="flex items-center gap-2"><span className="h-2.5 w-2.5 rounded-sm" style={{ background: PROTO_COLOR[d.name as EmailProtocol] }} />{d.name}</span>
                  <span className="font-mono text-zinc-300">{d.value}</span>
                </div>
              ))}
              <div className="border-t border-white/5 pt-2 text-xs text-zinc-500">
                {sessions.filter((s) => s.mode === 'STARTTLS').length} STARTTLS · {sessions.filter((s) => s.mode === 'IMPLICIT_TLS').length} implicit TLS · {sessions.filter((s) => s.mode === 'PLAINTEXT').length} plaintext
              </div>
            </div>
          </div>
        </Card>

        <Card title="Negotiated protocol versions" icon={<Gauge size={15} />} delay={0.24}>
          <div className="space-y-2.5">
            {versions.map((v) => (
              <div key={v.v} className="flex items-center gap-3">
                <span className="w-20 shrink-0 font-mono text-xs text-zinc-300">{v.v}</span>
                <div className="flex-1"><Bar value={(v.n / sessions.length) * 100} color={VCOL[v.v]} h={10} /></div>
                <span className="w-6 text-right font-mono text-xs text-zinc-400">{v.n}</span>
              </div>
            ))}
          </div>
        </Card>

        <Card title="Findings by severity" icon={<Activity size={15} />} delay={0.28}>
          <div className="flex h-[150px] items-end gap-3">
            {SEV_ORDER.filter((s) => s !== 'info').map((s, i) => {
              const max = Math.max(1, ...SEV_ORDER.map((x) => sevCount[x]));
              return (
                <div key={s} className="flex flex-1 flex-col items-center gap-2">
                  <span className="font-mono text-sm font-bold" style={{ color: SEV[s].color }}>{sevCount[s]}</span>
                  <motion.div initial={{ height: 0 }} animate={{ height: `${(sevCount[s] / max) * 100}px` }} transition={{ delay: 0.3 + i * 0.08, duration: 0.7 }}
                    className="w-full rounded-t-md" style={{ background: SEV[s].color, opacity: 0.85 }} />
                  <span className="text-[11px] text-zinc-400">{SEV[s].label}</span>
                </div>
              );
            })}
          </div>
        </Card>
      </div>

      <div className="mt-4 grid gap-4 xl:grid-cols-[minmax(0,1.1fr)_minmax(0,1fr)]">
        <Card title="Top priority findings" icon={<Award size={15} />} delay={0.3} action={<button onClick={() => go('findings')} className="text-xs text-accent hover:text-zinc-100">View all →</button>}>
          <div className="space-y-2">
            {top.map((f, i) => (
              <motion.button key={f.id} onClick={() => openFinding(f.id)} initial={{ opacity: 0, x: -8 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: 0.35 + i * 0.05 }}
                className="group flex w-full items-center gap-3 rounded-xl bg-white/[0.02] p-3 text-left ring-1 ring-white/5 transition hover:bg-white/[0.05] hover:ring-accent/40">
                <span className="grid h-8 w-8 shrink-0 place-items-center rounded-lg font-mono text-sm font-bold" style={{ color: SEV[f.severity].color, background: SEV[f.severity].bg }}>{f.priority}</span>
                <div className="min-w-0 flex-1">
                  <div className="truncate text-sm font-medium text-white">{f.title}</div>
                  <div className="mt-0.5 truncate text-xs text-zinc-500">{f.sessions.join(', ')} · {f.evidence[0]?.detail}</div>
                </div>
                <SevBadge sev={f.severity} />
              </motion.button>
            ))}
          </div>
        </Card>
        <Card title="Session timeline" icon={<Timer size={15} />} delay={0.34}>
          <Timeline onPick={openSession} />
        </Card>
      </div>
    </>
  );
}

function Timeline({ onPick }: { onPick: (id: string) => void }) {
  const { a } = useStore();
  const services = a.baselines.map((b) => b.service);
  const t0 = a.capture.start, t1 = a.capture.end || t0 + 1;
  const W = 600, rowH = 34, H = services.length * rowH + 30, L = 150;
  const mlBy = new Map(a.ml.map((m) => [m.session, m]));
  const sevOf = (id: string) => {
    const fs = a.findings.filter((f) => f.sessions.includes(id));
    return SEV_ORDER.find((s) => fs.some((f) => f.severity === s));
  };
  return (
    <div className="overflow-x-auto">
      <svg viewBox={`0 0 ${W} ${H}`} className="w-full min-w-[520px]">
        {services.map((s, i) => (
          <g key={s}>
            <line x1={L} x2={W - 10} y1={i * rowH + 18} y2={i * rowH + 18} stroke="#27272a" strokeDasharray="2 4" />
            <text x={L - 10} y={i * rowH + 22} textAnchor="end" fontSize="10.5" fill="#a1a1aa" fontFamily="JetBrains Mono">{s.replace('/SMTP', '').replace('/IMAP', '').replace('/POP3', '')}</text>
            <text x={8} y={i * rowH + 22} fontSize="10" fill={PROTO_COLOR[s.split('/')[1] as EmailProtocol]} fontWeight={700} fontFamily="JetBrains Mono">{s.split('/')[1]}</text>
          </g>
        ))}
        {a.sessions.map((s, i) => {
          const row = services.indexOf(`${s.stream.server}:${s.stream.sport}/${s.protocol}`);
          const x = L + ((s.stream.start - t0) / (t1 - t0)) * (W - L - 20);
          const sev = sevOf(s.id);
          const c = sev ? SEV[sev].color : '#3fb27f';
          const an = (mlBy.get(s.id)?.anomaly ?? 0) > 0.6;
          return (
            <g key={s.id} className="cursor-pointer" onClick={() => onPick(s.id)}>
              {an && <circle cx={x} cy={row * rowH + 18} r={11} fill="none" stroke="#9b8cf0" strokeDasharray="2 2" />}
              <motion.circle initial={{ r: 0 }} animate={{ r: 6 }} transition={{ delay: 0.4 + i * 0.03 }} cx={x} cy={row * rowH + 18} fill={c} />
              <title>{`${s.id} · ${s.stream.client} → ${s.stream.server}:${s.stream.sport}`}</title>
            </g>
          );
        })}
        <text x={L} y={H - 4} fontSize="10" fill="#71717a" fontFamily="JetBrains Mono">{new Date(t0 * 1000).toISOString().slice(11, 19)}</text>
        <text x={W - 10} y={H - 4} textAnchor="end" fontSize="10" fill="#71717a" fontFamily="JetBrains Mono">{new Date(t1 * 1000).toISOString().slice(11, 19)}</text>
      </svg>
      <div className="mt-2 flex flex-wrap gap-3 text-[11px] text-zinc-500">
        <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-full bg-[#3fb27f]" />clean</span>
        <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-full bg-rose-500" />worst finding colour</span>
        <span className="flex items-center gap-1"><span className="h-3 w-3 rounded-full border border-dashed border-zinc-500" />ML anomaly</span>
      </div>
    </div>
  );
}
