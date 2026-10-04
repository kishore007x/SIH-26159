import { motion } from 'motion/react';
import { useMemo, useState } from 'react';
import { BadgeCheck, BrainCircuit, ChevronRight, FileBadge2, Binary, MessagesSquare, Waypoints, ShieldAlert, Wrench, Lock, LockOpen, Mail, Network, KeyRound, Gauge } from 'lucide-react';
import { useStore } from '../store.tsx';
import { Bar, Card, Pill, ProtoBadge, SEV, SEV_ORDER, SevBadge, fmtBytes, fmtClock } from '../common.tsx';
import { cipherInfo, groupName, versionName } from '../../engine/catalog.ts';
import type { CertInfo, EmailSession, Finding, Severity } from '../../engine/types.ts';

type Tab = 'ladder' | 'transcript' | 'cert' | 'ai' | 'hex';

export function Investigation({ id }: { id: string }) {
  const { a, openFinding } = useStore();
  const s = a.sessions.find((x) => x.id === id)!;
  const m = a.ml.find((x) => x.session === id)!;
  const fs = a.findings.filter((f) => f.sessions.includes(id));
  const [tab, setTab] = useState<Tab>('ladder');
  const [hexFrame, setHexFrame] = useState<number | null>(null);
  const sh = s.tls?.serverHello;
  const ci = sh ? cipherInfo(sh.cipher) : undefined;
  const worst = SEV_ORDER.find((sv) => fs.some((f) => f.severity === sv));
  const evFrames = [...new Set(fs.flatMap((f) => f.evidence.filter((e) => e.session === id).flatMap((e) => e.frames)))].sort((x, y) => x - y);

  const showFrame = (f: number) => { setHexFrame(f); setTab('hex'); };

  return (
    <div className="min-w-0 space-y-4">
      <Card className="overflow-hidden">
        <div className="relative flex flex-wrap items-start justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <span className="text-2xl font-bold text-white">{s.id}</span>
              <ProtoBadge p={s.protocol} />
              <Pill color={s.mode === 'PLAINTEXT' ? '#f05252' : '#3fb27f'}>{s.mode === 'PLAINTEXT' ? <LockOpen size={11} /> : <Lock size={11} />}{s.mode.replace('_', ' ')}</Pill>
              {worst && <SevBadge sev={worst} />}
            </div>
            <div className="mt-1.5 font-mono text-sm text-zinc-300">{s.stream.client}:{s.stream.cport} <span className="text-accent">⇄</span> {s.stream.server}:{s.stream.sport} {s.serverName && <span className="text-zinc-500">({s.serverName})</span>}</div>
            <div className="mt-1 text-xs text-zinc-500">
              {fmtClock(s.stream.start)} · {((s.stream.end - s.stream.start) * 1000).toFixed(0)} ms · {s.stream.frames.length} frames (#{s.stream.frames[0]}–#{s.stream.frames[s.stream.frames.length - 1]}) · ↑{fmtBytes(s.stream.bytes.c2s)} ↓{fmtBytes(s.stream.bytes.s2c)}{s.stream.sawRst && ' · RST'}
            </div>
          </div>
          <div className="text-right">
            <div className="text-[11px] tracking-wider text-zinc-500 uppercase">AI risk class</div>
            <div className="text-2xl font-bold capitalize" style={{ color: SEV[m.riskClass].color }}>{m.riskClass}</div>
            <div className="text-[11px] text-zinc-500">anomaly score <span className="font-mono text-zinc-200">{m.anomaly.toFixed(2)}</span></div>
          </div>
        </div>
        <EvidenceChain s={s} fs={fs} />
      </Card>

      <div className="glass flex gap-1 overflow-x-auto rounded-xl p-1">
        {([['ladder', 'Handshake ladder', Waypoints], ['transcript', 'Protocol transcript', MessagesSquare], ['cert', 'Certificates', FileBadge2], ['ai', 'AI explanation', BrainCircuit], ['hex', 'Packet evidence', Binary]] as const).map(([k, l, I]) => (
          <button key={k} onClick={() => setTab(k)} className={`relative flex shrink-0 items-center gap-2 rounded-lg px-3.5 py-2 text-sm font-medium transition ${tab === k ? 'text-white' : 'text-zinc-400 hover:text-zinc-200'}`}>
            {tab === k && <motion.span layoutId="inv-tab" className="absolute inset-0 rounded-lg bg-white/10 ring-1 ring-white/10" />}
            <I size={15} className="relative" /><span className="relative">{l}</span>
          </button>
        ))}
      </div>

      <div className="grid gap-4">
        <Card className="min-w-0">
          {tab === 'ladder' && <Ladder s={s} evFrames={evFrames} onFrame={showFrame} />}
          {tab === 'transcript' && <Transcript s={s} evFrames={evFrames} onFrame={showFrame} />}
          {tab === 'cert' && <Certs s={s} />}
          {tab === 'ai' && <AiExplain id={id} />}
          {tab === 'hex' && <Hex frames={s.stream.frames} ev={evFrames} initial={hexFrame ?? evFrames[0] ?? s.stream.frames[0]} />}
        </Card>
        <Card title="Findings in this session" icon={<ShieldAlert size={15} />}>
          {fs.length === 0 && <div className="rounded-xl bg-[#3fb27f]/10 p-4 text-sm text-[#3fb27f] ring-1 ring-[#3fb27f]/30"><BadgeCheck className="mb-2" />No weaknesses detected. {ci && `${versionName(sh!.version)} with ${ci.enc} and ${ci.kx === 'TLS13' ? 'ephemeral key exchange' : ci.kx}.`}</div>}
          <div className="grid gap-2 lg:grid-cols-2">
            {fs.map((f) => <FindingMini key={f.id} f={f} sid={id} onOpen={() => openFinding(f.id)} onFrame={showFrame} />)}
          </div>
          {sh && (
            <div className="mt-4 grid grid-cols-3 gap-2 border-t border-white/5 pt-4 text-xs md:grid-cols-6">
              {[['Version', versionName(sh.version)], ['Cipher', ci!.enc], ['Key exchange', ci!.kx === 'TLS13' || ci!.kx === 'ECDHE' ? `ECDHE ${groupName(s.tls?.kxGroup)}` : ci!.kx], ['Forward secrecy', ci!.kx === 'RSA' ? 'No' : 'Yes'], ['MAC', ci!.mac], ['App records', String(s.tls!.appRecords)]].map(([k, v]) => (
                <div key={k} className="rounded-lg bg-white/[0.03] p-2 ring-1 ring-white/5"><div className="text-zinc-500">{k}</div><div className="font-mono text-zinc-200">{v}</div></div>
              ))}
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}

function FindingMini({ f, sid, onOpen, onFrame }: { f: Finding; sid: string; onOpen: () => void; onFrame: (n: number) => void }) {
  const ev = f.evidence.filter((e) => e.session === sid);
  return (
    <div className="rounded-xl bg-white/[0.02] p-3 ring-1 ring-white/5">
      <div className="flex items-start gap-2">
        <span className="mt-1 h-2 w-2 shrink-0 rounded-full" style={{ background: SEV[f.severity].color }} />
        <button onClick={onOpen} className="text-left text-sm font-medium text-white hover:text-zinc-100">{f.title}</button>
      </div>
      {ev.map((e, i) => (
        <div key={i} className="mt-1.5 pl-4 text-xs text-zinc-400">
          {e.detail}{' '}
          {e.frames.map((fr) => <button key={fr} onClick={() => onFrame(fr)} className="ml-1 rounded bg-accent/10 px-1 font-mono text-[10.5px] text-accent hover:bg-accent/10">#{fr}</button>)}
        </div>
      ))}
    </div>
  );
}

function EvidenceChain({ s, fs }: { s: EmailSession; fs: Finding[] }) {
  const sh = s.tls?.serverHello;
  const ci = sh ? cipherInfo(sh.cipher) : undefined;
  const leaf = s.tls?.certificates[0];
  const dimSev = (dims: string[]) => SEV_ORDER.find((sv) => fs.some((f) => f.severity === sv && dims.includes(f.dimension)));
  const worst = SEV_ORDER.find((sv) => fs.some((f) => f.severity === sv));
  const nodes: { icon: typeof Mail; k: string; v: string; sev?: Severity; ok?: boolean }[] = [
    { icon: Mail, k: 'Protocol', v: `${s.protocol} :${s.stream.sport}`, sev: dimSev(['protocol']) },
    { icon: Network, k: 'Session', v: `${s.stream.frames.length} frames`, ok: true },
    { icon: s.mode === 'PLAINTEXT' ? LockOpen : Lock, k: 'STARTTLS', v: s.mode === 'IMPLICIT_TLS' ? 'implicit' : s.starttlsAccepted ? 'upgraded' : s.starttlsRefused ? 'refused' : s.strippingSignature ? 'stripped' : s.starttlsAdvertised ? 'not used' : 'absent', sev: dimSev(['starttls']) },
    { icon: Waypoints, k: 'Handshake', v: sh ? versionName(sh.version) : s.tls ? 'aborted' : '—', sev: dimSev(['tls']) ?? (s.tls && !sh ? 'medium' : undefined) },
    { icon: KeyRound, k: 'Crypto', v: ci ? ci.enc : '—', sev: dimSev(['cipher', 'keyExchange']) },
    { icon: FileBadge2, k: 'Certificate', v: leaf ? `${leaf.keyAlg}-${leaf.keyBits}` : sh?.version === 0x0304 ? 'encrypted' : '—', sev: dimSev(['certificate']) },
    { icon: ShieldAlert, k: 'Findings', v: `${fs.length}`, sev: worst },
    { icon: Gauge, k: 'Risk', v: worst ? SEV[worst].label : 'Low', sev: worst },
    { icon: Wrench, k: 'Action', v: fs.length ? `${new Set(fs.map((f) => f.remediation)).size} fixes` : 'none', ok: !fs.length },
  ];
  return (
    <div className="relative mt-5 flex flex-wrap items-stretch gap-y-2 gap-x-1 pb-1">
      {nodes.map((n, i) => {
        const c = n.sev ? SEV[n.sev].color : n.v === '—' ? '#52525b' : '#3fb27f';
        return (
          <div key={n.k} className="flex items-center gap-1">
            <motion.div initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.05 }}
              className="min-w-[92px] rounded-xl px-2.5 py-2 ring-1" style={{ background: `${c}10`, border: `1px solid ${c}30` }}>
              <div className="flex items-center gap-1.5 text-[10px] tracking-wider uppercase" style={{ color: c }}><n.icon size={12} />{n.k}</div>
              <div className="mt-0.5 truncate font-mono text-[11.5px] text-zinc-200">{n.v}</div>
            </motion.div>
            {i < nodes.length - 1 && <ChevronRight size={14} className="shrink-0 text-zinc-600" />}
          </div>
        );
      })}
    </div>
  );
}

type Step = { frame: number; dir: 'c2s' | 's2c'; label: string; detail?: string; kind: 'app' | 'tls' | 'enc' | 'alert' | 'bad' };

function Ladder({ s, evFrames, onFrame }: { s: EmailSession; evFrames: number[]; onFrame: (f: number) => void }) {
  const steps = useMemo(() => {
    const out: Step[] = [];
    for (const t of s.transcript) {
      if (!t.tag && !/^(EHLO|HELO|220|\* OK|\+OK|QUIT|221|USER|STAT|CAPA|a\d)/i.test(t.text)) continue;
      const last = out[out.length - 1];
      if (last && last.frame === t.frame && last.dir === t.dir) { if (t.tag === 'inject' || t.tag === 'cred') { last.kind = 'bad'; last.detail = (last.detail ? last.detail + ' ⏎ ' : '') + (t.redacted ?? t.text); } continue; }
      const kind = t.tag === 'cred' || t.tag === 'inject' || t.tag === 'error' ? 'bad' : 'app';
      out.push({ frame: t.frame, dir: t.dir, label: (t.redacted ?? t.text).slice(0, 64), kind });
    }
    for (const e of s.tls?.events ?? []) {
      out.push({ frame: e.frame, dir: e.dir, label: e.label + (e.label === 'Application Data' && Number(e.detail) > 1 ? ` ×${e.detail}` : ''), detail: e.label === 'Application Data' ? undefined : e.detail, kind: e.label.startsWith('Alert') ? 'alert' : e.encrypted ? 'enc' : 'tls' });
    }
    out.sort((x, y) => x.frame - y.frame);
    if (s.stream.sawRst) out.push({ frame: s.stream.frames[s.stream.frames.length - 1], dir: s.stream.rstFrom === 'client' ? 'c2s' : 's2c', label: 'TCP RST — connection torn down', kind: 'alert' });
    return out.slice(0, 40);
  }, [s]);
  const W = 760, top = 50, rowH = 40, H = top + steps.length * rowH + 20, xc = 110, xs = W - 110;
  const color = (k: Step['kind']) => ({ app: '#a1a1aa', tls: '#5b8def', enc: '#9b8cf0', alert: '#f08c3e', bad: '#f05252' }[k]);
  return (
    <div className="overflow-x-auto">
      <svg viewBox={`0 0 ${W} ${H}`} className="w-full min-w-[620px]">
        <defs>
          {['app', 'tls', 'enc', 'alert', 'bad'].map((k) => (
            <marker key={k} id={`ar-${k}`} viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill={color(k as Step['kind'])} /></marker>
          ))}
        </defs>
        {[[xc, 'CLIENT', s.stream.client], [xs, 'SERVER', `${s.stream.server}:${s.stream.sport}`]].map(([x, l, ip]) => (
          <g key={l as string}>
            <rect x={(x as number) - 80} y={4} width={160} height={36} rx={10} fill="#121215" stroke="#5b8def" strokeOpacity={0.35} />
            <text x={x as number} y={19} textAnchor="middle" fill="#a1a1aa" fontSize="10" fontWeight={700} letterSpacing="2">{l}</text>
            <text x={x as number} y={33} textAnchor="middle" fill="#d4d4d8" fontSize="10.5" fontFamily="JetBrains Mono">{ip}</text>
            <line x1={x as number} x2={x as number} y1={42} y2={H - 6} stroke="#3f3f46" strokeDasharray="3 4" />
          </g>
        ))}
        {(() => {
          const tlsStart = steps.findIndex((st) => st.label === 'ClientHello' || st.kind === 'tls');
          return tlsStart >= 0 ? (
            <g>
              <rect x={xc - 6} y={top + tlsStart * rowH - 6} width={xs - xc + 12} height={H - (top + tlsStart * rowH)} fill="#5b8def" opacity={0.035} rx={8} />
              <text x={xc + 8} y={top + tlsStart * rowH + 6} fill="#5b8def" opacity={0.55} fontSize="8.5" letterSpacing="2.5">TLS LAYER</text>
            </g>
          ) : null;
        })()}
        {steps.map((st, i) => {
          const y = top + i * rowH + 18;
          const c = color(st.kind);
          const [x1, x2] = st.dir === 'c2s' ? [xc, xs] : [xs, xc];
          const isEv = evFrames.includes(st.frame);
          return (
            <motion.g key={i} initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: i * 0.03 }} className="cursor-pointer" onClick={() => onFrame(st.frame)}>
              {isEv && <rect x={xc + 4} y={y - 17} width={xs - xc - 8} height={rowH - 4} rx={6} fill="#f05252" opacity={0.07} />}
              <line x1={x1} x2={x2 + (st.dir === 'c2s' ? -4 : 4)} y1={y} y2={y} stroke={c} strokeWidth={st.kind === 'bad' ? 2 : 1.4} markerEnd={`url(#ar-${st.kind})`} strokeDasharray={st.kind === 'enc' ? '5 4' : undefined} />
              <text x={(xc + xs) / 2} y={y - 5} textAnchor="middle" fill={st.kind === 'app' ? '#d4d4d8' : c} fontSize="11.5" fontFamily="JetBrains Mono" fontWeight={st.kind === 'app' ? 400 : 600}>
                {st.kind === 'enc' ? '🔒 ' : ''}{st.label}
              </text>
              {st.detail && <text x={(xc + xs) / 2} y={y + 13} textAnchor="middle" fill="#71717a" fontSize="9.5" fontFamily="JetBrains Mono">{st.detail.slice(0, 80)}</text>}
              <text x={st.dir === 'c2s' ? xc - 12 : xs + 12} y={y + 4} textAnchor={st.dir === 'c2s' ? 'end' : 'start'} fill={isEv ? '#f05252' : '#52525b'} fontSize="10" fontFamily="JetBrains Mono">#{st.frame}</text>
            </motion.g>
          );
        })}
      </svg>
      <div className="mt-2 flex flex-wrap gap-4 text-[11px] text-zinc-500">
        {[['#a1a1aa', 'application command'], ['#5b8def', 'TLS handshake (cleartext)'], ['#9b8cf0', 'encrypted'], ['#f08c3e', 'alert / reset'], ['#f05252', 'security-relevant evidence']].map(([c, l]) => <span key={l} className="flex items-center gap-1.5"><span className="h-0.5 w-4" style={{ background: c }} />{l}</span>)}
      </div>
    </div>
  );
}

function Transcript({ s, evFrames, onFrame }: { s: EmailSession; evFrames: number[]; onFrame: (f: number) => void }) {
  const TAG: Record<string, string> = { starttls: '#5b8def', cred: '#f05252', inject: '#f05252', error: '#f08c3e', data: '#d9a92b', auth: '#f08c3e', cap: '#3fb27f' };
  if (!s.transcript.length) return <div className="p-6 text-center text-sm text-zinc-400"><Lock className="mx-auto mb-2 text-emerald-400" />Implicit TLS from the first byte — no plaintext application dialogue exists. See the handshake ladder for the TLS exchange.</div>;
  return (
    <div className="rounded-xl bg-black/50 p-4 font-mono text-[12px] leading-6 ring-1 ring-white/5">
      <div className="mb-3 flex items-center gap-1.5"><span className="h-2.5 w-2.5 rounded-full bg-[#f05252]/10" /><span className="h-2.5 w-2.5 rounded-full bg-amber-400/70" /><span className="h-2.5 w-2.5 rounded-full bg-[#3fb27f]/10" /><span className="ml-2 text-[11px] text-zinc-500">tcp.stream eq {s.stream.id} · follow {s.protocol}</span></div>
      {s.transcript.map((t, i) => (
        <div key={i} className={`group flex gap-3 rounded px-1 ${evFrames.includes(t.frame) && t.tag ? 'bg-[#f05252]/10' : ''}`}>
          <button onClick={() => onFrame(t.frame)} className="w-12 shrink-0 text-right text-zinc-600 hover:text-accent">#{t.frame}</button>
          <span className={`w-5 shrink-0 ${t.dir === 'c2s' ? 'text-accent' : 'text-violet-400'}`}>{t.dir === 'c2s' ? 'C:' : 'S:'}</span>
          <span className="break-all" style={{ color: t.tag ? TAG[t.tag] : t.dir === 'c2s' ? '#e4e4e7' : '#a1a1aa' }}>{t.redacted ?? t.text}</span>
          {t.tag && ['cred', 'inject', 'error'].includes(t.tag) && <span className="ml-auto shrink-0 rounded bg-[#f05252]/10 px-1.5 text-[10px] text-[#f05252] uppercase">{t.tag === 'cred' ? 'credential' : t.tag === 'inject' ? 'injected' : 'downgrade'}</span>}
        </div>
      ))}
      {s.tls && <div className="mt-2 flex gap-3 px-1 text-emerald-400/80"><span className="w-12 shrink-0 text-right text-zinc-600">#{s.tls.startFrame}</span><span>── TLS session begins ({s.tls.appRecords} encrypted records, {fmtBytes(s.tls.appBytes)}) ──</span></div>}
    </div>
  );
}

function CertCard({ c, idx, capTime }: { c: CertInfo; idx: number; capTime: number }) {
  const expired = Date.parse(c.notAfter) / 1000 < capTime;
  const weakKey = (c.keyAlg === 'RSA' && c.keyBits < 2048) || (c.keyAlg === 'EC' && c.keyBits < 256);
  const weakSig = /sha1|md5/i.test(c.sigAlg);
  const life = (Date.parse(c.notAfter) - Date.parse(c.notBefore)) / 864e5;
  const used = Math.min(1, Math.max(0, (capTime * 1000 - Date.parse(c.notBefore)) / (Date.parse(c.notAfter) - Date.parse(c.notBefore))));
  const rows: [string, string, boolean?][] = [
    ['Subject', c.subject], ['Issuer', c.issuer], ['Serial', c.serial.slice(0, 47)], ['Validity', `${c.notBefore.slice(0, 10)} → ${c.notAfter.slice(0, 10)} (${Math.round(life)} d)`, expired],
    ['Public key', `${c.keyAlg} ${c.keyBits}-bit${c.curve ? ` (${c.curve})` : ''}`, weakKey], ['Signature', c.sigAlg, weakSig], ['SAN', c.san.join(', ') || '—'], ['SHA-256', c.fingerprint.match(/.{2}/g)!.slice(0, 16).join(':') + '…'],
  ];
  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: idx * 0.08 }} className="relative rounded-xl bg-white/[0.02] p-4 ring-1 ring-white/10">
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <FileBadge2 size={18} className={c.isCA ? 'text-zinc-200' : 'text-accent'} />
          <span className="font-semibold text-white">{c.subjectCN}</span>
          <Pill color={c.isCA ? '#9b8cf0' : '#5b8def'}>{idx === 0 ? 'Leaf' : c.isCA ? 'CA' : 'Intermediate'}</Pill>
          {c.selfSigned && <Pill color="#d9a92b">self-signed</Pill>}
        </div>
        {(expired || weakKey || weakSig) && <Pill color="#f05252">weak</Pill>}
      </div>
      <div className="mt-3 grid gap-1.5 text-xs">
        {rows.map(([k, v, bad]) => (
          <div key={k} className="grid grid-cols-[90px_1fr] gap-2"><span className="text-zinc-500">{k}</span><span className={`font-mono break-all ${bad ? 'text-[#f05252]' : 'text-zinc-300'}`}>{v}{bad ? ' ⚠' : ''}</span></div>
        ))}
      </div>
      <div className="mt-3">
        <div className="mb-1 flex justify-between text-[10px] text-zinc-500"><span>lifetime used at capture</span><span>{Math.round(used * 100)}%</span></div>
        <Bar value={used * 100} color={expired ? '#f05252' : used > 0.85 ? '#d9a92b' : '#3fb27f'} h={4} />
      </div>
    </motion.div>
  );
}

function Certs({ s }: { s: EmailSession }) {
  const { a } = useStore();
  const certs = s.tls?.certificates ?? [];
  if (!certs.length) return (
    <div className="p-6 text-center text-sm text-zinc-400">
      <Lock className="mx-auto mb-2 text-zinc-200" />
      {s.tls?.serverHello?.version === 0x0304 ? 'TLS 1.3 encrypts the Certificate message — passive capture cannot observe it. SecureMailScope lowers the evidence-confidence score accordingly instead of guessing.' : 'No certificate exchanged in this session.'}
    </div>
  );
  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2 text-xs text-zinc-400"><span>Chain presented in frame</span><span className="font-mono text-accent">#{s.tls?.certFrame}</span></div>
      {certs.map((c, i) => <CertCard key={c.fingerprint} c={c} idx={i} capTime={a.capture.end} />)}
    </div>
  );
}

function AiExplain({ id }: { id: string }) {
  const { a } = useStore();
  const m = a.ml.find((x) => x.session === id)!;
  const pct = a.ml.filter((x) => x.anomaly < m.anomaly).length / a.ml.length;
  return (
    <div className="grid gap-5 lg:grid-cols-2">
      <div>
        <div className="mb-3 text-xs font-semibold tracking-wider text-zinc-400 uppercase">Ordinal risk model — class probabilities</div>
        <div className="space-y-2.5">
          {(['critical', 'high', 'medium', 'low'] as const).map((k) => (
            <div key={k} className="flex items-center gap-3 text-sm">
              <span className="w-16 capitalize" style={{ color: SEV[k].color }}>{k}</span>
              <div className="flex-1"><Bar value={m.probs[k] * 100} color={SEV[k].color} h={8} /></div>
              <span className="w-12 text-right font-mono text-xs text-zinc-300">{(m.probs[k] * 100).toFixed(1)}%</span>
            </div>
          ))}
        </div>
        <div className="mt-6 mb-3 text-xs font-semibold tracking-wider text-zinc-400 uppercase">Why — top feature attributions</div>
        <div className="space-y-2">
          {m.contributions.length === 0 && <div className="text-sm text-zinc-500">No risk-increasing features.</div>}
          {m.contributions.map((c) => (
            <div key={c.feature} className="flex items-center gap-3 text-xs">
              <span className="w-44 shrink-0 text-zinc-300">{c.feature}</span>
              <div className="flex-1"><Bar value={(c.weight / 3.4) * 100} color="#9b8cf0" h={6} /></div>
              <span className="w-10 text-right font-mono text-zinc-200">+{c.weight.toFixed(2)}</span>
            </div>
          ))}
        </div>
      </div>
      <div>
        <div className="mb-3 text-xs font-semibold tracking-wider text-zinc-400 uppercase">Isolation Forest anomaly</div>
        <div className="rounded-xl bg-white/[0.02] p-4 ring-1 ring-white/10">
          <div className="flex items-end gap-2"><span className="text-4xl font-bold text-zinc-200">{m.anomaly.toFixed(2)}</span><span className="pb-1 text-xs text-zinc-400">score (0.5 ≈ normal, → 1 isolated)</span></div>
          <div className="mt-3"><Bar value={m.anomaly * 100} color="#9b8cf0" h={8} /></div>
          <div className="mt-2 text-xs text-zinc-400">More isolated than <b className="text-white">{Math.round(pct * 100)}%</b> of sessions in this capture (200 trees, ψ = {Math.min(64, a.sessions.length)}).</div>
        </div>
        <div className="mt-5 mb-3 text-xs font-semibold tracking-wider text-zinc-400 uppercase">Deviation from service baseline</div>
        {m.deviations.length === 0 ? <div className="text-sm text-zinc-500">Consistent with every other session to this service.</div> : (
          <div className="space-y-2">
            {m.deviations.map((d) => (
              <div key={d.field} className="rounded-lg bg-white/[0.03] p-2.5 text-xs ring-1 ring-white/5">
                <div className="text-zinc-400">{d.field}</div>
                <div className="mt-0.5 font-mono"><span className="text-[#f05252]">{d.observed}</span> <span className="text-zinc-600">vs baseline</span> <span className="text-[#3fb27f]">{d.baseline}</span></div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function Hex({ frames, ev, initial }: { frames: number[]; ev: number[]; initial: number }) {
  const { a } = useStore();
  const [f, setF] = useState(initial);
  const pkt = a.rawPackets[f - 1];
  const d = pkt?.data ?? new Uint8Array();
  // layer boundaries (Ethernet / IPv4 / TCP)
  const ihl = (d[14] & 0x0f) * 4, thl = (d[14 + ihl + 12] >> 4) * 4;
  const l3 = 14, l4 = 14 + ihl, l7 = l4 + thl;
  const layerColor = (i: number) => (i < l3 ? '#71717a' : i < l4 ? '#5b8def' : i < l7 ? '#9b8cf0' : '#d9a92b');
  const rows = [];
  for (let o = 0; o < d.length; o += 16) rows.push(o);
  return (
    <div>
      <div className="mb-3 flex flex-wrap items-center gap-1.5">
        <span className="mr-1 text-xs text-zinc-500">Frame</span>
        {frames.filter((x) => ev.includes(x) || frames.indexOf(x) < 3 || x === f).slice(0, 20).map((x) => (
          <button key={x} onClick={() => setF(x)} className={`rounded-md px-2 py-0.5 font-mono text-[11px] ${x === f ? 'bg-zinc-50 text-ink-950' : ev.includes(x) ? 'bg-[#f05252]/10 text-[#f05252] ring-1 ring-[#f05252]/30' : 'bg-white/5 text-zinc-400'}`}>#{x}</button>
        ))}
      </div>
      <div className="mb-3 flex flex-wrap gap-3 text-[11px]">
        {[['#71717a', `Ethernet (${l3} B)`], ['#5b8def', `IPv4 (${ihl} B)`], ['#9b8cf0', `TCP (${thl} B)`], ['#d9a92b', `Payload (${Math.max(0, d.length - l7)} B)`]].map(([c, l]) => <span key={l} className="flex items-center gap-1.5 text-zinc-400"><span className="h-2 w-2 rounded-sm" style={{ background: c }} />{l}</span>)}
        <span className="ml-auto font-mono text-zinc-500">{pkt && fmtClock(pkt.ts)} · {d.length} bytes</span>
      </div>
      <div className="max-h-[420px] overflow-auto rounded-xl bg-black/50 p-3 font-mono text-[11.5px] leading-5 ring-1 ring-white/5">
        {rows.map((o) => (
          <div key={o} className="flex gap-4 whitespace-pre">
            <span className="text-zinc-600">{o.toString(16).padStart(4, '0')}</span>
            <span>{Array.from(d.subarray(o, o + 16)).map((b, i) => <span key={i} style={{ color: layerColor(o + i) }}>{b.toString(16).padStart(2, '0')}{i === 7 ? '  ' : ' '}</span>)}</span>
            <span className="text-zinc-500">{Array.from(d.subarray(o, o + 16)).map((b, i) => <span key={i} style={{ color: o + i >= l7 ? '#e4e4e7' : undefined }}>{b >= 32 && b < 127 ? String.fromCharCode(b) : '·'}</span>)}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
