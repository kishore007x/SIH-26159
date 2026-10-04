import { motion } from 'motion/react';
import { useRef, useState } from 'react';
import {
  Activity, ArrowRight, ArrowUpRight, BrainCircuit, Download, FileSearch, FileUp, Fingerprint, GitCompareArrows, Lock, Mail,
  ScrollText, ShieldCheck, Upload, Wrench,
} from 'lucide-react';
import { AnimatedContent, Button, CountUp, DecryptedText, DotGrid, LogoLoop, RotatingText, SplitText, SpotlightCard } from './bits.tsx';

const SAMPLES = [
  { file: 'acme-mail-incident.pcap', title: 'Incident capture', org: 'Acme Corp mail estate', desc: 'STARTTLS stripping, an interception certificate, a TLS downgrade dance, cleartext credentials and legacy cryptography.', meta: ['PCAP', '578 frames', '17 sessions'], score: 27, grade: 'F', color: '#f05252' },
  { file: 'acme-mail-hardened.pcapng', title: 'Post-hardening capture', org: 'Same estate, after remediation', desc: 'TLS 1.3 throughout, enforced STARTTLS and a modern PKI — the before/after comparison.', meta: ['PCAPNG', '301 frames', '9 sessions'], score: 100, grade: 'A', color: '#3fb27f' },
];

const FLOW = [
  { icon: FileUp, label: 'PCAP input', sub: 'Libpcap and PCAPNG frames are decoded in the browser.' },
  { icon: Mail, label: 'Email traffic', sub: 'TCP streams are reassembled into SMTP, IMAP and POP3 sessions.' },
  { icon: Lock, label: 'Crypto check', sub: 'STARTTLS state, TLS handshakes and X.509 chains are parsed.' },
  { icon: BrainCircuit, label: 'AI detection', sub: 'Rules, cross-session drift and Isolation Forest scoring.' },
  { icon: Activity, label: 'Risk assessment', sub: 'Seven-dimension posture score and prioritised findings.' },
  { icon: ScrollText, label: 'Report & action', sub: 'Evidence-linked remediation in JSON, HTML and PDF.' },
];

const STANDARDS = ['RFC 8314', 'RFC 3207 · STARTTLS', 'RFC 8996', 'RFC 7507 · FALLBACK_SCSV', 'RFC 8446 · TLS 1.3', 'RFC 5280 · X.509', 'CVE-2011-0411', 'CVE-2016-2183', 'RFC 7465', 'NIST SP 800-52r2', 'RFC 8461 · MTA-STS', 'RFC 7672 · DANE'];
const NAV = [['Product', '#product'], ['Capabilities', '#features'], ['Workflow', '#how'], ['Samples', '#samples']];

export function Landing({ onFile }: { onFile: (b: ArrayBuffer, name: string) => void }) {
  const input = useRef<HTMLInputElement>(null);
  const [drag, setDrag] = useState(false);
  const [loading, setLoading] = useState<string | null>(null);
  const [hoverNav, setHoverNav] = useState<number | null>(null);

  const loadSample = async (file: string) => {
    setLoading(file);
    const r = await fetch(`samples/${file}`);
    onFile(await r.arrayBuffer(), file);
    setLoading(null);
  };
  const handle = async (f?: File | null) => { if (f) onFile(await f.arrayBuffer(), f.name); };

  return (
    <div className="relative min-h-screen overflow-x-hidden bg-ink-950 text-zinc-200">
      <input ref={input} type="file" accept=".pcap,.pcapng,.cap,.dmp" className="hidden" onChange={(e) => handle(e.target.files?.[0])} />

      <header className="sticky top-0 z-40 border-b border-white/[0.06] bg-ink-950/80 backdrop-blur-md">
        <div className="mx-auto flex h-16 max-w-6xl items-center justify-between px-6">
          <Logo small />
          {/* React Bits PillNav-style navigation */}
          <nav className="hidden items-center rounded-full border border-white/[0.08] bg-ink-900 p-1 md:flex" onMouseLeave={() => setHoverNav(null)}>
            {NAV.map(([l, h], i) => (
              <a key={l} href={h} onMouseEnter={() => setHoverNav(i)} className="relative rounded-full px-4 py-1.5 text-[15px] text-zinc-400 transition-colors hover:text-zinc-50">
                {hoverNav === i && <motion.span layoutId="pill" className="absolute inset-0 rounded-full bg-white/[0.08]" transition={{ type: 'spring', stiffness: 500, damping: 40 }} />}
                <span className="relative">{l}</span>
              </a>
            ))}
          </nav>
          <Button onClick={() => loadSample(SAMPLES[0].file)} className="!rounded-full !py-1.5">Launch demo</Button>
        </div>
      </header>

      {/* HERO */}
      <section className="relative border-b border-white/[0.06]">
        <div className="absolute inset-0 [mask-image:radial-gradient(ellipse_75%_70%_at_50%_30%,black,transparent)]"><DotGrid /></div>
        <div className="relative mx-auto max-w-6xl px-6 pt-24 pb-16 text-center">
          <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.5 }}
            className="inline-flex items-center gap-2 rounded-full border border-white/10 bg-ink-900 px-3 py-1 text-sm text-zinc-400">
            <span className="rounded-full bg-accent/15 px-2 py-px text-xs font-bold text-accent">New</span>
            Passive cryptographic posture assessment for email
          </motion.div>
          <h1 className="mx-auto mt-7 max-w-4xl text-5xl leading-[1.05] font-bold tracking-tight text-zinc-50 sm:text-7xl">
            <SplitText text="Explainable cryptographic intelligence from email traffic." delay={0.1} />
          </h1>
          <motion.p initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.6, duration: 0.6 }} className="mx-auto mt-6 max-w-2xl text-xl leading-relaxed text-zinc-400">
            Reconstruct <RotatingText words={['SMTP', 'IMAP', 'POP3']} className="min-w-[3.4em] justify-center font-bold text-zinc-100" /> sessions from packet captures,
            evaluate STARTTLS, TLS and X.509 posture, and prioritise every weakness with traceable evidence.
          </motion.p>
          <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.75, duration: 0.5 }} className="mt-9 flex flex-wrap items-center justify-center gap-3">
            <Button onClick={() => loadSample(SAMPLES[0].file)} disabled={!!loading} className="!px-6 !py-3 !text-[17px]">
              {loading ? 'Loading capture…' : 'Analyze demo capture'} <ArrowRight size={17} />
            </Button>
            <Button variant="secondary" onClick={() => input.current?.click()} className="!px-6 !py-3 !text-[17px]"><Upload size={17} /> Upload PCAP</Button>
          </motion.div>
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.95 }} className="mt-6 flex flex-wrap items-center justify-center gap-x-6 gap-y-2 text-sm text-zinc-500">
            <span className="flex items-center gap-1.5"><ShieldCheck size={15} /> Runs entirely in the browser</span>
            <span className="flex items-center gap-1.5"><Lock size={15} /> No capture data uploaded</span>
            <span className="flex items-center gap-1.5"><FileSearch size={15} /> Frame-level evidence</span>
          </motion.div>
        </div>

        <div id="product" className="relative mx-auto max-w-6xl px-6 pb-20">
          <motion.div initial={{ opacity: 0, y: 40 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.9, delay: 0.85, ease: [0.16, 1, 0.3, 1] }}
            className="overflow-hidden rounded-xl border border-white/10 bg-ink-900 shadow-[0_30px_80px_-30px_rgba(0,0,0,0.9)]">
            <div className="flex items-center gap-2 border-b border-white/[0.06] px-4 py-2.5">
              <span className="h-2.5 w-2.5 rounded-full bg-zinc-700" /><span className="h-2.5 w-2.5 rounded-full bg-zinc-700" /><span className="h-2.5 w-2.5 rounded-full bg-zinc-700" />
              <span className="ml-3 rounded-md bg-ink-800 px-3 py-0.5 font-mono text-xs text-zinc-500">securemailscope / acme-mail-incident.pcap / overview</span>
            </div>
            <ProductPreview />
          </motion.div>
        </div>
      </section>

      {/* standards loop */}
      <section className="border-b border-white/[0.06] py-10">
        <p className="mb-6 text-center text-sm text-zinc-500">Findings are mapped to the standards your auditors already reference</p>
        <LogoLoop items={STANDARDS.map((t) => <span key={t} className="font-mono text-sm whitespace-nowrap text-zinc-500">{t}</span>)} />
      </section>

      {/* capabilities */}
      <section id="features" className="mx-auto max-w-6xl px-6 py-24">
        <AnimatedContent className="max-w-2xl">
          <div className="text-sm font-bold text-accent">Capabilities</div>
          <h2 className="mt-2 text-4xl font-bold tracking-tight text-zinc-50 sm:text-5xl">Not only which cipher was used — whether the infrastructure behaved securely.</h2>
        </AnimatedContent>
        <div className="mt-12 grid gap-4 md:grid-cols-6">
          <Feature className="md:col-span-4" icon={<Fingerprint size={18} />} title="Cryptographic profiling" desc="Each session is correlated across protocol, TLS version, cipher suite, key exchange and the full certificate chain."><CryptoVisual /></Feature>
          <Feature className="md:col-span-2" delay={0.05} icon={<BrainCircuit size={18} />} title="AI risk detection" desc="Isolation Forest anomaly scoring and an explainable risk model with feature attributions."><AiVisual /></Feature>
          <Feature className="md:col-span-2" delay={0.05} icon={<GitCompareArrows size={18} />} title="Cross-session drift" desc="Per-service baselines expose downgrades, stripping and certificate-lineage breaks."><DriftVisual /></Feature>
          <Feature className="md:col-span-2" delay={0.1} icon={<FileSearch size={18} />} title="Evidence mapping" desc="Every finding links to the frames and bytes that prove it."><HexVisual /></Feature>
          <Feature className="md:col-span-2" delay={0.15} icon={<Wrench size={18} />} title="Risk & remediation" desc="Prioritised fixes and a what-if simulator for posture after remediation."><SimVisual /></Feature>
        </div>
      </section>

      {/* workflow */}
      <section id="how" className="border-y border-white/[0.06] bg-ink-900/40">
        <div className="mx-auto max-w-6xl px-6 py-24">
          <AnimatedContent className="max-w-2xl">
            <div className="text-sm font-bold text-accent">Workflow</div>
            <h2 className="mt-2 text-4xl font-bold tracking-tight text-zinc-50 sm:text-5xl">From raw frames to decisions</h2>
          </AnimatedContent>
          <div className="mt-12 grid gap-px overflow-hidden rounded-xl border border-white/[0.07] bg-white/[0.07] sm:grid-cols-2 lg:grid-cols-3">
            {FLOW.map((f, i) => (
              <AnimatedContent key={f.label} delay={i * 0.06} distance={12} className="bg-ink-950 p-6">
                <div className="flex items-center justify-between">
                  <div className="grid h-10 w-10 place-items-center rounded-lg border border-white/10 bg-ink-800 text-zinc-200"><f.icon size={19} /></div>
                  <span className="font-mono text-sm text-zinc-600">0{i + 1}</span>
                </div>
                <div className="mt-5 text-lg font-bold text-zinc-50">{f.label}</div>
                <p className="mt-1 text-[15px] leading-snug text-zinc-400">{f.sub}</p>
              </AnimatedContent>
            ))}
          </div>
          <div className="mt-10 grid grid-cols-2 gap-6 md:grid-cols-4">
            {[[18, 'cryptographic checks'], [200, 'trees in the Isolation Forest'], [14, 'explainable risk features'], [0, 'bytes uploaded']].map(([n, l]) => (
              <div key={l} className="border-l border-white/10 pl-5">
                <div className="text-4xl font-bold text-zinc-50"><CountUp to={n as number} /></div>
                <div className="mt-1 text-[15px] text-zinc-500">{l}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* samples */}
      <section id="samples" className="mx-auto max-w-6xl px-6 py-24">
        <AnimatedContent className="max-w-2xl">
          <div className="text-sm font-bold text-accent">Get started</div>
          <h2 className="mt-2 text-4xl font-bold tracking-tight text-zinc-50 sm:text-5xl">Start an investigation</h2>
          <p className="mt-3 text-lg text-zinc-400">Drop a capture, or open a reference capture. Both samples are genuine PCAPs that open in Wireshark, so every cited frame can be verified.</p>
        </AnimatedContent>
        <div className="mt-12 grid gap-4 lg:grid-cols-3">
          <AnimatedContent>
            <div
              onDragOver={(e) => { e.preventDefault(); setDrag(true); }}
              onDragLeave={() => setDrag(false)}
              onDrop={(e) => { e.preventDefault(); setDrag(false); handle(e.dataTransfer.files[0]); }}
              onClick={() => input.current?.click()}
              className={`flex h-full min-h-[300px] cursor-pointer flex-col items-center justify-center rounded-xl border border-dashed p-6 text-center transition-colors ${drag ? 'border-accent bg-accent/5' : 'border-white/15 bg-ink-900/50 hover:border-white/30'}`}>
              <div className="grid h-12 w-12 place-items-center rounded-lg border border-white/10 bg-ink-800 text-zinc-300"><FileUp size={22} /></div>
              <div className="mt-4 text-lg font-bold text-zinc-50">Drop a capture file</div>
              <div className="mt-1 text-[15px] text-zinc-500">.pcap, .pcapng or .cap — processed locally</div>
              <span className="mt-5 text-sm font-bold text-zinc-300 underline decoration-zinc-600 underline-offset-4">or browse files</span>
            </div>
          </AnimatedContent>
          {SAMPLES.map((s, i) => (
            <AnimatedContent key={s.file} delay={0.06 + i * 0.06}>
              <SpotlightCard className="flex h-full flex-col p-6">
                <div className="flex items-center justify-between text-xs text-zinc-500">
                  <span className="flex gap-2">{s.meta.map((m) => <span key={m} className="rounded border border-white/10 px-1.5 py-px font-mono">{m}</span>)}</span>
                  <a href={`samples/${s.file}`} download title="Download (opens in Wireshark)" className="rounded-md p-1 hover:bg-white/5 hover:text-zinc-200"><Download size={16} /></a>
                </div>
                <div className="mt-6 flex items-baseline gap-2">
                  <span className="text-5xl font-bold text-zinc-50">{s.score}</span>
                  <span className="text-sm text-zinc-500">/100 · grade</span>
                  <span className="rounded px-1.5 text-sm font-bold" style={{ color: s.color, background: `${s.color}18` }}>{s.grade}</span>
                </div>
                <div className="mt-5 text-lg font-bold text-zinc-50">{s.title}</div>
                <div className="text-sm text-zinc-500">{s.org}</div>
                <p className="mt-2 flex-1 text-[15px] leading-snug text-zinc-400">{s.desc}</p>
                <Button variant="secondary" onClick={() => loadSample(s.file)} className="mt-6 w-full justify-between">
                  {loading === s.file ? 'Loading…' : 'Analyze capture'} <ArrowUpRight size={16} />
                </Button>
              </SpotlightCard>
            </AnimatedContent>
          ))}
        </div>
      </section>

      <footer className="border-t border-white/[0.06]">
        <div className="mx-auto flex max-w-6xl flex-wrap items-center justify-between gap-4 px-6 py-8 text-sm text-zinc-500">
          <Logo small />
          <span>SecureMailScope — passive email PCAPs to explainable cryptographic security intelligence.</span>
        </div>
      </footer>
    </div>
  );
}

function Feature({ children, className = '', delay = 0, icon, title, desc }: { children: React.ReactNode; className?: string; delay?: number; icon: React.ReactNode; title: string; desc: string }) {
  return (
    <AnimatedContent delay={delay} className={className}>
      <SpotlightCard className="flex h-full flex-col">
        <div className="h-52 overflow-hidden border-b border-white/[0.06] bg-ink-950/60">{children}</div>
        <div className="p-6">
          <div className="flex items-center gap-2 text-zinc-400">{icon}<span className="text-lg font-bold text-zinc-50">{title}</span></div>
          <p className="mt-1.5 text-[15px] leading-snug text-zinc-400">{desc}</p>
        </div>
      </SpotlightCard>
    </AnimatedContent>
  );
}

export function Logo({ small }: { small?: boolean }) {
  return (
    <div className="flex items-center gap-2.5">
      <div className={`grid place-items-center rounded-lg border border-white/10 bg-zinc-50 ${small ? 'h-8 w-8' : 'h-9 w-9'}`}>
        <Mail size={small ? 16 : 18} className="text-zinc-950" strokeWidth={2.4} />
      </div>
      <div className="leading-tight">
        <div className="text-[19px] font-bold tracking-tight text-zinc-50">SecureMailScope</div>
        {!small && <div className="text-[11px] text-zinc-500">Crypto posture intelligence</div>}
      </div>
    </div>
  );
}

/* ---------------- illustrative visuals (values taken from the incident capture) ---------------- */

function ProductPreview() {
  const dims = [['Protocol', 75], ['TLS version', 54], ['Cipher', 54], ['Key exchange', 88], ['Certificate', 0], ['STARTTLS', 0], ['Anomaly', 70]] as const;
  const col = (v: number) => (v >= 85 ? '#3fb27f' : v >= 55 ? '#d9a92b' : v >= 35 ? '#f08c3e' : '#f05252');
  const rows = [
    ['Credentials transmitted without encryption', 'S09, S11', 'Critical', '#f05252'],
    ['STARTTLS capability stripped from greeting', 'S09 · frame #281', 'Critical', '#f05252'],
    ['Certificate lineage break — possible interception', 'S10', 'Critical', '#f05252'],
    ['Insecure fallback without TLS_FALLBACK_SCSV', 'S07 → S08', 'High', '#f08c3e'],
  ];
  return (
    <div className="grid text-left md:grid-cols-[200px_1fr]">
      <div className="hidden border-r border-white/[0.06] p-3 md:block">
        {['Posture overview', 'Findings', 'Session forensics', 'Crypto graph', 'Drift & AI', 'What-if', 'Reports'].map((n, i) => (
          <div key={n} className={`rounded-md px-3 py-1.5 text-[14px] ${i === 0 ? 'bg-white/[0.06] text-zinc-50' : 'text-zinc-500'}`}>{n}</div>
        ))}
      </div>
      <div className="grid md:grid-cols-[1fr_1.3fr]">
        <div className="border-b border-white/[0.06] p-6 md:border-r md:border-b-0">
          <div className="text-sm text-zinc-500">Posture score</div>
          <div className="mt-1 flex items-baseline gap-2"><span className="text-6xl font-bold text-zinc-50"><CountUp to={27} /></span><span className="text-zinc-500">/100</span><span className="rounded bg-[#f05252]/15 px-1.5 text-sm font-bold text-[#f05252]">Critical risk</span></div>
          <div className="mt-6 space-y-2.5">
            {dims.map(([k, v], i) => (
              <div key={k} className="flex items-center gap-3 text-[13px]">
                <span className="w-24 shrink-0 text-zinc-400">{k}</span>
                <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-white/[0.06]"><motion.div className="h-full rounded-full" style={{ background: col(v) }} initial={{ width: 0 }} animate={{ width: `${Math.max(2, v)}%` }} transition={{ delay: 1.4 + i * 0.06, duration: 0.8 }} /></div>
                <span className="w-6 text-right font-mono text-[11px] text-zinc-500">{v}</span>
              </div>
            ))}
          </div>
        </div>
        <div className="p-6">
          <div className="flex items-center justify-between text-sm"><span className="text-zinc-500">Top priority findings</span><span className="text-zinc-500">21 total</span></div>
          <div className="mt-3 divide-y divide-white/[0.06] rounded-lg border border-white/[0.06]">
            {rows.map(([t, s, l, c], i) => (
              <motion.div key={t} initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 1.5 + i * 0.1 }} className="flex items-center gap-3 px-3 py-2.5">
                <span className="w-4 font-mono text-xs text-zinc-600">{i + 1}</span>
                <div className="min-w-0 flex-1"><div className="truncate text-[14px] font-bold text-zinc-100">{t}</div><div className="font-mono text-[11px] text-zinc-500">{s}</div></div>
                <span className="flex items-center gap-1.5 text-xs font-bold" style={{ color: c }}><span className="h-1.5 w-1.5 rounded-full" style={{ background: c }} />{l}</span>
              </motion.div>
            ))}
          </div>
          <div className="mt-4 rounded-lg border border-white/[0.06] bg-ink-950 p-3 font-mono text-[12px] leading-6">
            <div><span className="text-zinc-600">#279 S:</span> <span className="text-zinc-400">250-PIPELINING</span></div>
            <div><span className="text-zinc-600">#281 S:</span> <DecryptedText text="250-XXXXXXXA" className="text-[#f05252]" delay={1.8} /> <span className="text-zinc-600">// STARTTLS stripped</span></div>
            <div><span className="text-zinc-600">#287 C:</span> <span className="text-zinc-400">AUTH LOGIN</span> <span className="text-zinc-600">// before any TLS</span></div>
          </div>
        </div>
      </div>
    </div>
  );
}

function CryptoVisual() {
  const sessions = [
    ['S01', 'SMTP', 'TLS 1.3', 'AES-256-GCM', 'X25519', '#3fb27f'],
    ['S03', 'IMAP', 'TLS 1.2', 'ECDHE-RSA-AES256-GCM', 'X25519', '#3fb27f'],
    ['S08', 'SMTP', 'TLS 1.0', 'RSA-RC4-128-SHA', 'static RSA', '#f05252'],
    ['S12', 'POP3', 'TLS 1.0', 'RSA-3DES-EDE-CBC', 'RSA-1024', '#f05252'],
    ['S13', 'SMTP', 'TLS 1.2', 'RSA-AES128-CBC-SHA', 'static RSA', '#d9a92b'],
  ];
  return (
    <div className="p-5 font-mono text-[12px]">
      {sessions.map(([id, p, v, c, k, col]) => (
        <div key={id} className="grid grid-cols-[40px_48px_64px_1fr_auto] items-center gap-3 border-b border-white/[0.05] py-2 last:border-0">
          <span className="font-bold text-zinc-200">{id}</span><span className="text-zinc-500">{p}</span><span style={{ color: col }}>{v}</span><span className="truncate text-zinc-400">{c}</span><span className="text-zinc-500">{k}</span>
        </div>
      ))}
    </div>
  );
}

function AiVisual() {
  const bars = [0.47, 0.47, 0.47, 0.52, 0.47, 0.47, 0.64, 0.59, 0.66, 0.54, 0.66, 0.62, 0.57, 0.52, 0.65, 0.47, 0.47];
  return (
    <div className="flex h-full items-end gap-1 px-5 pt-8">
      {bars.map((b, i) => (
        <motion.div key={i} className="flex-1 rounded-t-sm" style={{ background: b > 0.6 ? '#f05252' : '#3f3f46' }}
          initial={{ height: 0 }} whileInView={{ height: `${(b - 0.3) * 260}%` }} viewport={{ once: true }} transition={{ delay: i * 0.03, duration: 0.6 }} />
      ))}
    </div>
  );
}

function DriftVisual() {
  const rows = [['S01', 'TLS 1.3', true], ['S02', 'TLS 1.3', true], ['S08', 'TLS 1.0', false], ['S16', 'TLS 1.3', true]] as const;
  return (
    <div className="space-y-1 p-5 font-mono text-[12px]">
      <div className="flex justify-between rounded-md border border-white/10 bg-ink-800 px-3 py-1.5 text-zinc-300"><span>Baseline :587</span><span>TLS 1.3 · 83%</span></div>
      {rows.map(([s, v, ok]) => (
        <div key={s} className={`flex justify-between rounded-md px-3 py-1.5 ${ok ? 'text-zinc-500' : 'bg-[#f05252]/10 text-[#f05252]'}`}><span>{s}</span><span>{v}{!ok && ' · deviation'}</span></div>
      ))}
    </div>
  );
}

function HexVisual() {
  return (
    <div className="p-5 font-mono text-[11.5px] leading-6 text-zinc-500">
      {['0070  4d 45 0d 0a 32 35 30 2d', '0078  50 49 50 45 4c 49 4e 49', '0080  4e 47 0d 0a 32 35 30 2d'].map((l) => <div key={l}>{l}</div>)}
      <div className="rounded bg-[#f05252]/10 px-1 text-[#f05252]">0088  58 58 58 58 58 58 58 41  XXXXXXXA</div>
      <div>0090  0d 0a 32 35 30 2d 41 55</div>
    </div>
  );
}

function SimVisual() {
  return (
    <div className="flex h-full items-center justify-center gap-6 p-5">
      <div className="text-center"><div className="text-5xl font-bold text-zinc-50">27</div><div className="text-xs text-zinc-500">observed</div></div>
      <ArrowRight className="text-zinc-600" />
      <div className="text-center"><div className="text-5xl font-bold text-[#3fb27f]">100</div><div className="text-xs text-zinc-500">after all fixes</div></div>
    </div>
  );
}
