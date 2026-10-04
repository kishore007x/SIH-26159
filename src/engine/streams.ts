import type { Chunk, TcpSegment, TcpStream } from './types.ts';

export const EMAIL_PORTS: Record<number, { proto: 'SMTP' | 'IMAP' | 'POP3'; implicitTls: boolean }> = {
  25: { proto: 'SMTP', implicitTls: false },
  587: { proto: 'SMTP', implicitTls: false },
  2525: { proto: 'SMTP', implicitTls: false },
  465: { proto: 'SMTP', implicitTls: true },
  143: { proto: 'IMAP', implicitTls: false },
  993: { proto: 'IMAP', implicitTls: true },
  110: { proto: 'POP3', implicitTls: false },
  995: { proto: 'POP3', implicitTls: true },
};

const SYN = 2, ACK = 16, FIN = 1, RST = 4;

/** Groups TCP segments into bidirectional streams and reassembles each direction by sequence number. */
export function reassemble(segments: TcpSegment[]): TcpStream[] {
  const groups = new Map<string, TcpSegment[]>();
  for (const s of segments) {
    const a = `${s.src}:${s.sport}`, b = `${s.dst}:${s.dport}`;
    const key = a < b ? `${a}|${b}` : `${b}|${a}`;
    let g = groups.get(key);
    if (!g) groups.set(key, (g = []));
    g.push(s);
  }

  const streams: TcpStream[] = [];
  for (const segs of groups.values()) {
    // split on new SYN after FIN/RST (port reuse) — keep simple: one stream per 4-tuple
    const synSeg = segs.find((s) => (s.flags & SYN) && !(s.flags & ACK));
    let client: string, cport: number, server: string, sport: number;
    if (synSeg) {
      client = synSeg.src; cport = synSeg.sport; server = synSeg.dst; sport = synSeg.dport;
    } else {
      const f = segs[0];
      const fIsServer = EMAIL_PORTS[f.sport] && !EMAIL_PORTS[f.dport];
      if (fIsServer || (!EMAIL_PORTS[f.dport] && f.sport < f.dport)) {
        client = f.dst; cport = f.dport; server = f.src; sport = f.sport;
      } else { client = f.src; cport = f.sport; server = f.dst; sport = f.dport; }
    }

    const dirOf = (s: TcpSegment): 'c2s' | 's2c' => (s.src === client && s.sport === cport ? 'c2s' : 's2c');
    const accepted = new Map<number, Uint8Array>(); // frame -> trimmed payload
    for (const dir of ['c2s', 's2c'] as const) {
      const ds = segs.filter((s) => dirOf(s) === dir);
      const syn = ds.find((s) => s.flags & SYN);
      const withData = ds.filter((s) => s.payload.length > 0);
      if (!withData.length) continue;
      const isn = syn ? (syn.seq + 1) >>> 0 : Math.min(...withData.map((s) => s.seq));
      const rel = (s: TcpSegment) => (s.seq - isn) >>> 0;
      const ordered = [...withData].sort((x, y) => rel(x) - rel(y) || x.frame - y.frame);
      let next = 0;
      for (const s of ordered) {
        const r = rel(s);
        if (r > 0x7fffffff) continue; // before ISN — ignore
        const end = r + s.payload.length;
        if (end <= next) continue; // full retransmission
        const trim = Math.max(0, next - r);
        accepted.set(s.frame, s.payload.subarray(trim));
        next = end;
      }
    }

    const chunks: Chunk[] = [];
    const bytes = { c2s: 0, s2c: 0 };
    for (const s of [...segs].sort((a, b) => a.frame - b.frame)) {
      const data = accepted.get(s.frame);
      if (!data || !data.length) continue;
      const dir = dirOf(s);
      bytes[dir] += data.length;
      const last = chunks[chunks.length - 1];
      if (last && last.dir === dir) {
        const merged = new Uint8Array(last.data.length + data.length);
        merged.set(last.data); merged.set(data, last.data.length);
        last.frameOffsets.push({ frame: s.frame, offset: last.data.length });
        last.data = merged; last.frames.push(s.frame);
      } else {
        chunks.push({ dir, data, frames: [s.frame], frameOffsets: [{ frame: s.frame, offset: 0 }], ts: s.ts });
      }
    }

    const rst = segs.find((s) => s.flags & RST);
    streams.push({
      id: streams.length,
      client, cport, server, sport,
      start: Math.min(...segs.map((s) => s.ts)),
      end: Math.max(...segs.map((s) => s.ts)),
      frames: segs.map((s) => s.frame).sort((a, b) => a - b),
      chunks, bytes,
      sawSyn: !!synSeg,
      sawFin: segs.some((s) => s.flags & FIN),
      sawRst: !!rst,
      rstFrom: rst ? (dirOf(rst) === 'c2s' ? 'client' : 'server') : undefined,
    });
  }
  return streams.sort((a, b) => a.start - b.start).map((s, i) => ({ ...s, id: i }));
}

/** Maps a byte offset inside a chunk back to the frame that carried it. */
export function frameAt(chunk: Chunk, offset: number): number {
  let f = chunk.frameOffsets[0].frame;
  for (const fo of chunk.frameOffsets) { if (fo.offset <= offset) f = fo.frame; else break; }
  return f;
}
