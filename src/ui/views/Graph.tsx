import { motion } from 'motion/react';
import { useMemo, useState } from 'react';
import { Share2 } from 'lucide-react';
import { useStore } from '../store.tsx';
import { PageTitle } from '../Shell.tsx';
import { Card, PROTO_COLOR, SEV, SEV_ORDER } from '../common.tsx';
import { cipherInfo, versionName } from '../../engine/catalog.ts';

interface GNode { id: string; col: number; label: string; sub?: string; color: string; onClick?: () => void }

const COLS = ['Client hosts', 'Email services', 'Sessions', 'TLS profile', 'Certificate lineage', 'Findings'];

export function Graph() {
  const { a, openSession, openFinding } = useStore();
  const [hover, setHover] = useState<string | null>(null);

  const { nodes, edges } = useMemo(() => {
    const nodes = new Map<string, GNode>();
    const edges: [string, string][] = [];
    const add = (n: GNode) => { if (!nodes.has(n.id)) nodes.set(n.id, n); };
    const link = (x: string, y: string) => { if (!edges.some(([p, q]) => p === x && q === y)) edges.push([x, y]); };
    const sevOfSession = (id: string) => SEV_ORDER.find((s) => a.findings.some((f) => f.severity === s && f.sessions.includes(id)));
    for (const s of a.sessions) {
      const h = `h:${s.stream.client}`, sv = `v:${s.stream.server}:${s.stream.sport}`, ss = `s:${s.id}`;
      add({ id: h, col: 0, label: s.stream.client, color: s.stream.client.startsWith('10.') ? '#5b8def' : '#d99ab8', sub: s.stream.client.startsWith('10.') ? 'internal' : 'external' });
      add({ id: sv, col: 1, label: `${s.protocol} :${s.stream.sport}`, sub: s.stream.server, color: PROTO_COLOR[s.protocol] });
      const sev = sevOfSession(s.id);
      add({ id: ss, col: 2, label: s.id, sub: s.mode === 'PLAINTEXT' ? 'plaintext' : s.mode === 'STARTTLS' ? 'STARTTLS' : 'implicit TLS', color: sev ? SEV[sev].color : '#3fb27f', onClick: () => openSession(s.id) });
      link(h, sv); link(sv, ss);
      const sh = s.tls?.serverHello;
      const tp = sh ? `t:${sh.version}:${sh.cipher}` : s.tls ? 't:aborted' : 't:plain';
      const ci = sh && cipherInfo(sh.cipher);
      add({ id: tp, col: 3, label: sh ? versionName(sh.version) : s.tls ? 'Handshake aborted' : 'No encryption', sub: ci ? ci.name.replace(/^TLS_/, '').slice(0, 30) : undefined,
        color: !sh ? (s.tls ? '#71717a' : '#f05252') : ci!.weak.length || sh.version < 0x0303 ? '#f08c3e' : ci!.kx === 'RSA' ? '#d9a92b' : '#3fb27f' });
      link(ss, tp);
      const leaf = s.tls?.certificates[0];
      if (leaf) {
        const cid = `c:${leaf.fingerprint}`;
        const bad = a.findings.some((f) => f.dimension === 'certificate' && f.sessions.includes(s.id) && (f.severity === 'critical' || f.severity === 'high'));
        add({ id: cid, col: 4, label: leaf.subjectCN, sub: `by ${leaf.issuerCN}`, color: bad ? '#f05252' : '#3fb27f' });
        link(tp, cid);
      } else if (sh?.version === 0x0304) { add({ id: 'c:hidden', col: 4, label: 'Encrypted (TLS 1.3)', sub: 'not observable', color: '#9b8cf0' }); link(tp, 'c:hidden'); }
    }
    for (const f of a.findings) {
      const fid = `f:${f.id}`;
      add({ id: fid, col: 5, label: f.title, sub: `${f.id} · ${SEV[f.severity].label}`, color: SEV[f.severity].color, onClick: () => openFinding(f.id) });
      for (const sid of f.sessions) {
        const s = a.sessions.find((x) => x.id === sid)!;
        const leaf = s.tls?.certificates[0];
        const from = f.dimension === 'certificate' && leaf ? `c:${leaf.fingerprint}` : ['tls', 'cipher', 'keyExchange'].includes(f.dimension) && s.tls ? (s.tls.serverHello ? `t:${s.tls.serverHello.version}:${s.tls.serverHello.cipher}` : 't:aborted') : `s:${sid}`;
        link(from, fid);
      }
    }
    return { nodes: [...nodes.values()], edges };
  }, [a, openSession, openFinding]);

  const cols = COLS.map((_, i) => nodes.filter((n) => n.col === i));
  const rowH = 32, W = 1290, top = 46;
  const H = top + Math.max(...cols.map((c) => c.length)) * rowH + 20;
  const colX = (i: number) => 10 + i * ((W - 214) / (COLS.length - 1));
  const pos = new Map<string, { x: number; y: number }>();
  cols.forEach((c, ci) => { const off = (H - top - c.length * rowH) / 2; c.forEach((n, i) => pos.set(n.id, { x: colX(ci), y: top + off + i * rowH + rowH / 2 })); });

  const lit = useMemo(() => {
    if (!hover) return null;
    const set = new Set([hover]);
    const walk = (dir: 0 | 1) => { let grow = true; while (grow) { grow = false; for (const e of edges) { if (set.has(e[dir]) && !set.has(e[1 - dir])) { const n = nodes.find((x) => x.id === e[1 - dir])!; const h = nodes.find((x) => x.id === e[dir])!; if (dir === 0 ? n.col > h.col : n.col < h.col) { set.add(e[1 - dir]); grow = true; } } } } };
    walk(0); walk(1);
    return set;
  }, [hover, edges, nodes]);

  return (
    <>
      <PageTitle kicker="Forensic intelligence layer" title="Cryptographic Security Graph"
        sub="Host → service → session → TLS profile → certificate → finding. Hover any node to trace its full causal path; click sessions or findings to drill in." />
      <Card title="Correlation graph" icon={<Share2 size={15} />}>
        <div className="overflow-x-auto">
          <svg viewBox={`0 0 ${W} ${H}`} className="w-full min-w-[1100px]">
            {COLS.map((c, i) => <text key={c} x={colX(i)} y={18} fill="#a1a1aa" fontSize="10.5" fontWeight={700} letterSpacing="2.5">{c.toUpperCase()}</text>)}
            {edges.map(([x, y], i) => {
              const p = pos.get(x)!, q = pos.get(y)!;
              const on = lit ? lit.has(x) && lit.has(y) : false;
              const n = nodes.find((k) => k.id === y)!;
              const sx = p.x + 196, mx = (sx + q.x) / 2;
              return (
                <motion.path key={i} d={`M${sx},${p.y} C${mx},${p.y} ${mx},${q.y} ${q.x - 4},${q.y}`} fill="none"
                  stroke={on ? n.color : '#3f3f46'} strokeOpacity={lit ? (on ? 0.95 : 0.06) : 0.35} strokeWidth={on ? 2 : 1}
                  initial={{ pathLength: 0 }} animate={{ pathLength: 1 }} transition={{ duration: 0.8, delay: 0.1 + (nodes.find((k) => k.id === x)!.col) * 0.12 }}
                  className={on ? 'flow-dash' : undefined} />
              );
            })}
            {nodes.map((n) => {
              const p = pos.get(n.id)!;
              const dim = lit && !lit.has(n.id);
              return (
                <motion.g key={n.id} initial={{ opacity: 0 }} animate={{ opacity: dim ? 0.18 : 1 }} transition={{ duration: 0.3 }}
                  onMouseEnter={() => setHover(n.id)} onMouseLeave={() => setHover(null)} onClick={n.onClick} className={n.onClick ? 'cursor-pointer' : 'cursor-default'}>
                  <rect x={p.x - 4} y={p.y - 13} width={200} height={26} rx={7} fill="#121215" stroke={n.color} strokeOpacity={hover === n.id ? 1 : 0.4} />
                  <circle cx={p.x + 7} cy={p.y} r={3.5} fill={n.color} />
                  <text x={p.x + 16} y={p.y - (n.sub ? 1 : -4)} fill="#e4e4e7" fontSize="11.5" fontFamily="JetBrains Mono" fontWeight={600}>{n.label.length > 25 ? n.label.slice(0, 24) + '…' : n.label}</text>
                  {n.sub && <text x={p.x + 16} y={p.y + 10} fill="#71717a" fontSize="9" fontFamily="JetBrains Mono">{n.sub.slice(0, 32)}</text>}
                </motion.g>
              );
            })}
          </svg>
        </div>
      </Card>
    </>
  );
}
