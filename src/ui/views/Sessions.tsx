import { motion } from 'motion/react';
import { Search } from 'lucide-react';
import { useMemo, useState } from 'react';
import { useStore } from '../store.tsx';
import { PageTitle } from '../Shell.tsx';
import { Card, ProtoBadge, SEV, SEV_ORDER } from '../common.tsx';
import { cipherInfo, versionName } from '../../engine/catalog.ts';
import { Investigation } from './Investigation.tsx';

export function Sessions() {
  const { a, session, openSession } = useStore();
  const [q, setQ] = useState('');
  const sel = session ?? a.findings[0]?.sessions[0] ?? a.sessions[0]?.id;
  const mlBy = useMemo(() => new Map(a.ml.map((m) => [m.session, m])), [a]);
  const worst = (id: string) => SEV_ORDER.find((s) => a.findings.some((f) => f.severity === s && f.sessions.includes(id)));
  const list = a.sessions.filter((s) => !q || `${s.id} ${s.protocol} ${s.stream.client} ${s.stream.server} ${s.mode} ${s.serverName ?? ''}`.toLowerCase().includes(q.toLowerCase()));

  return (
    <>
      <PageTitle kicker="Session reconstruction" title="Session Forensics" sub="Every SMTP / IMAP / POP3 conversation rebuilt from TCP streams, with its STARTTLS state, TLS handshake and certificate chain." />
      <div className="grid gap-4 2xl:grid-cols-[440px_1fr] xl:grid-cols-[400px_1fr]">
        <div className="xl:sticky xl:top-20 xl:self-start"><Card className="!p-3 xl:max-h-[calc(100vh-110px)] xl:overflow-hidden">
          <div className="mb-2 flex items-center gap-2 rounded-xl bg-white/5 px-3 py-2 ring-1 ring-white/10">
            <Search size={15} className="text-zinc-500" />
            <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Filter by IP, protocol, mode…" className="w-full bg-transparent text-sm outline-none placeholder:text-zinc-600" />
          </div>
          <div className="space-y-1 overflow-y-auto pr-1 xl:max-h-[calc(100vh-180px)]">
            {list.map((s, i) => {
              const sh = s.tls?.serverHello;
              const w = worst(s.id);
              const m = mlBy.get(s.id)!;
              const on = s.id === sel;
              return (
                <motion.button key={s.id} onClick={() => openSession(s.id)} initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.02 }}
                  className={`relative w-full rounded-xl p-3 text-left transition ${on ? 'bg-accent/10 ring-1 ring-accent/40' : 'hover:bg-white/[0.04]'}`}>
                  <span className="absolute top-3 bottom-3 left-0 w-[3px] rounded-full" style={{ background: w ? SEV[w].color : '#3fb27f' }} />
                  <div className="flex items-center gap-2 pl-1.5">
                    <span className="font-mono text-xs font-bold text-white">{s.id}</span>
                    <ProtoBadge p={s.protocol} />
                    <span className="text-[11px] text-zinc-500">{s.mode === 'IMPLICIT_TLS' ? 'Implicit TLS' : s.mode === 'STARTTLS' ? 'STARTTLS' : 'Plaintext'}</span>
                    <span className="ml-auto font-mono text-[11px]" style={{ color: sh ? (sh.version >= 0x0303 ? '#3fb27f' : '#f08c3e') : '#f05252' }}>{sh ? versionName(sh.version) : s.tls ? 'aborted' : 'no TLS'}</span>
                  </div>
                  <div className="mt-1 pl-1.5 font-mono text-[11.5px] text-zinc-400">{s.stream.client} → {s.stream.server}:{s.stream.sport}</div>
                  <div className="mt-1.5 flex items-center gap-2 pl-1.5">
                    <span className="truncate text-[11px] text-zinc-500">{sh ? cipherInfo(sh.cipher).name.replace('TLS_', '') : s.plaintextAuth.length ? 'credentials in cleartext' : '—'}</span>
                    <span className="ml-auto flex shrink-0 items-center gap-1 text-[10px] text-zinc-500">AI
                      <span className="h-1.5 w-12 overflow-hidden rounded-full bg-white/5"><span className="block h-full rounded-full bg-zinc-400" style={{ width: `${m.anomaly * 100}%` }} /></span>
                    </span>
                  </div>
                </motion.button>
              );
            })}
          </div>
        </Card></div>
        {sel && <Investigation id={sel} key={sel} />}
      </div>
    </>
  );
}
