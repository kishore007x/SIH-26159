import type { Chunk, ClientHelloInfo, ServerHelloInfo, TlsInfo } from './types.ts';
import { frameAt } from './streams.ts';
import { parseCertificate } from './x509.ts';
import { ALERTS, cipherInfo, groupName, versionName } from './catalog.ts';

const HS_NAMES: Record<number, string> = {
  1: 'ClientHello', 2: 'ServerHello', 4: 'NewSessionTicket', 8: 'EncryptedExtensions', 11: 'Certificate',
  12: 'ServerKeyExchange', 13: 'CertificateRequest', 14: 'ServerHelloDone', 15: 'CertificateVerify', 16: 'ClientKeyExchange', 20: 'Finished',
};

interface DirStream { data: Uint8Array; map: { offset: number; frame: number }[] }

function concatDir(chunks: Chunk[], dir: 'c2s' | 's2c'): DirStream {
  const parts = chunks.filter((c) => c.dir === dir);
  const total = parts.reduce((n, c) => n + c.data.length, 0);
  const data = new Uint8Array(total);
  const map: DirStream['map'] = [];
  let off = 0;
  for (const c of parts) {
    data.set(c.data, off);
    for (const fo of c.frameOffsets) map.push({ offset: off + fo.offset, frame: fo.frame });
    off += c.data.length;
  }
  return { data, map };
}
const frameOf = (s: DirStream, off: number) => {
  let f = s.map[0]?.frame ?? 0;
  for (const m of s.map) { if (m.offset <= off) f = m.frame; else break; }
  return f;
};

const rd16 = (d: Uint8Array, o: number) => (d[o] << 8) | d[o + 1];
const rd24 = (d: Uint8Array, o: number) => (d[o] << 16) | (d[o + 1] << 8) | d[o + 2];

export function looksLikeTls(d: Uint8Array): boolean {
  return d.length >= 5 && d[0] >= 20 && d[0] <= 23 && d[1] === 3 && d[2] <= 4;
}

/** Parses the TLS records of both directions and extracts handshake parameters. */
export function parseTls(chunks: Chunk[]): TlsInfo {
  const info: TlsInfo = { startFrame: chunks[0]?.frames[0] ?? 0, certificates: [], alerts: [], appRecords: 0, appBytes: 0, handshakeComplete: false, events: [] };
  let tls13 = false;
  for (const dir of ['c2s', 's2c'] as const) {
    const s = concatDir(chunks, dir);
    const d = s.data;
    let off = 0;
    let encrypted = false;
    let hsBuf = new Uint8Array(0);
    let hsFrame = 0;
    while (off + 5 <= d.length) {
      const type = d[off], ver = rd16(d, off + 1), len = rd16(d, off + 3);
      if (type < 20 || type > 24 || (ver >> 8) !== 3) break;
      const frame = frameOf(s, off);
      const frag = d.subarray(off + 5, Math.min(d.length, off + 5 + len));
      off += 5 + len;
      if (type === 20) {
        info.events.push({ frame, dir, label: 'ChangeCipherSpec' });
        if (!tls13) encrypted = true;
        continue;
      }
      if (type === 21) {
        if (encrypted || frag.length !== 2) { info.events.push({ frame, dir, label: 'Encrypted Alert', encrypted: true }); continue; }
        info.alerts.push({ frame, dir, level: frag[0], desc: frag[1] });
        info.events.push({ frame, dir, label: `Alert: ${ALERTS[frag[1]] ?? frag[1]}`, detail: frag[0] === 2 ? 'fatal' : 'warning' });
        continue;
      }
      if (type === 23) {
        info.appRecords++; info.appBytes += frag.length;
        const last = info.events[info.events.length - 1];
        if (last && last.label === 'Application Data' && last.dir === dir) last.detail = `${Number(last.detail ?? 1) + 1}`;
        else info.events.push({ frame, dir, label: 'Application Data', detail: '1', encrypted: true });
        if (info.serverHello) info.handshakeComplete = true;
        continue;
      }
      if (type === 22) {
        if (encrypted) { info.events.push({ frame, dir, label: 'Encrypted Handshake (Finished)', encrypted: true }); info.handshakeComplete = true; continue; }
        if (!hsBuf.length) hsFrame = frame;
        const nb = new Uint8Array(hsBuf.length + frag.length); nb.set(hsBuf); nb.set(frag, hsBuf.length); hsBuf = nb;
        let p = 0;
        while (p + 4 <= hsBuf.length) {
          const mt = hsBuf[p], ml = rd24(hsBuf, p + 1);
          if (p + 4 + ml > hsBuf.length) break;
          const msg = hsBuf.subarray(p + 4, p + 4 + ml);
          handleHandshake(info, mt, msg, hsFrame || frame, dir);
          if (mt === 2 && info.serverHello?.version === 0x0304) { tls13 = true; }
          p += 4 + ml;
        }
        hsBuf = hsBuf.slice(p);
        hsFrame = hsBuf.length ? frame : 0;
      }
    }
  }
  info.events.sort((a, b) => a.frame - b.frame);
  return info;
}

function handleHandshake(info: TlsInfo, type: number, m: Uint8Array, frame: number, dir: 'c2s' | 's2c') {
  const label = HS_NAMES[type] ?? `Handshake(${type})`;
  try {
    if (type === 1) {
      const ch: ClientHelloInfo = { frame, legacyVersion: rd16(m, 0), versions: [], ciphers: [], groups: [], keyShareGroups: [], fallbackScsv: false, ems: false };
      let p = 34; p += 1 + m[p];
      const cl = rd16(m, p); p += 2;
      for (let i = 0; i < cl; i += 2) { const c = rd16(m, p + i); if (c === 0x5600) ch.fallbackScsv = true; else if ((c & 0x0f0f) !== 0x0a0a) ch.ciphers.push(c); }
      p += cl; p += 1 + m[p];
      if (p + 2 <= m.length) {
        const end = p + 2 + rd16(m, p); p += 2;
        while (p + 4 <= end) {
          const et = rd16(m, p), el = rd16(m, p + 2); const e = m.subarray(p + 4, p + 4 + el); p += 4 + el;
          if (et === 0 && e.length > 5) ch.sni = new TextDecoder().decode(e.subarray(5, 5 + rd16(e, 3)));
          if (et === 10) for (let i = 2; i < 2 + rd16(e, 0); i += 2) ch.groups.push(rd16(e, i));
          if (et === 23) ch.ems = true;
          if (et === 43) for (let i = 1; i < 1 + e[0]; i += 2) { const v = rd16(e, i); if ((v & 0x0f0f) !== 0x0a0a) ch.versions.push(v); }
          if (et === 51) { let q = 2; while (q + 4 <= e.length) { ch.keyShareGroups.push(rd16(e, q)); q += 4 + rd16(e, q + 2); } }
        }
      }
      info.clientHello = ch;
      const maxV = ch.versions.length ? Math.max(...ch.versions) : ch.legacyVersion;
      info.events.push({ frame, dir, label, detail: `max ${versionName(maxV)} · ${ch.ciphers.length} suites${ch.sni ? ` · SNI ${ch.sni}` : ''}` });
    } else if (type === 2) {
      const sh: ServerHelloInfo = { frame, legacyVersion: rd16(m, 0), version: rd16(m, 0), cipher: 0 };
      let p = 34; p += 1 + m[p];
      sh.cipher = rd16(m, p); p += 3;
      if (p + 2 <= m.length) {
        const end = p + 2 + rd16(m, p); p += 2;
        while (p + 4 <= end) {
          const et = rd16(m, p), el = rd16(m, p + 2); const e = m.subarray(p + 4, p + 4 + el); p += 4 + el;
          if (et === 43 && el === 2) sh.version = rd16(e, 0);
          if (et === 51 && el >= 2) sh.keyShareGroup = rd16(e, 0);
        }
      }
      info.serverHello = sh;
      if (sh.keyShareGroup !== undefined) { info.kxGroup = sh.keyShareGroup; info.kxFrame = frame; }
      info.events.push({ frame, dir, label, detail: `${versionName(sh.version)} · ${cipherInfo(sh.cipher).name}` });
    } else if (type === 11) {
      const total = rd24(m, 0);
      let p = 3;
      while (p + 3 <= 3 + total && p + 3 <= m.length) {
        const cl = rd24(m, p); p += 3;
        try { info.certificates.push(parseCertificate(m.slice(p, p + cl))); } catch { /* unparsable cert */ }
        p += cl;
      }
      info.certFrame = frame;
      info.events.push({ frame, dir, label, detail: `${info.certificates.length} cert(s) · ${info.certificates[0]?.subjectCN ?? '?'}` });
    } else if (type === 12) {
      if (m[0] === 3) { info.kxGroup = rd16(m, 1); info.kxFrame = frame; info.events.push({ frame, dir, label, detail: `ECDHE ${groupName(info.kxGroup)}` }); }
      else { const pl = rd16(m, 0); info.dhBits = pl * 8; info.kxFrame = frame; info.events.push({ frame, dir, label, detail: `DHE ${pl * 8}-bit` }); }
    } else {
      info.events.push({ frame, dir, label });
    }
  } catch {
    info.events.push({ frame, dir, label: `${label} (malformed)` });
  }
}

export { frameAt };
