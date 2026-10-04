import type { CertInfo } from './types.ts';

interface Node { tag: number; cls: number; cons: boolean; start: number; hs: number; len: number; d: Uint8Array; kids?: Node[] }

function parseNode(d: Uint8Array, start: number): Node {
  let o = start;
  const t = d[o++];
  let len = d[o++];
  if (len & 0x80) {
    const n = len & 0x7f; len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + d[o++];
  }
  const node: Node = { tag: t & 0x1f, cls: t >> 6, cons: !!(t & 0x20), start, hs: o - start, len, d };
  if (node.cons) {
    node.kids = [];
    let p = o;
    while (p < o + len) { const k = parseNode(d, p); node.kids.push(k); p = k.start + k.hs + k.len; }
  }
  return node;
}
const body = (n: Node) => n.d.subarray(n.start + n.hs, n.start + n.hs + n.len);
const kid = (n: Node, i: number) => n.kids![i];

function oid(n: Node): string {
  const b = body(n);
  const out = [Math.floor(b[0] / 40), b[0] % 40];
  let v = 0;
  for (let i = 1; i < b.length; i++) { v = v * 128 + (b[i] & 0x7f); if (!(b[i] & 0x80)) { out.push(v); v = 0; } }
  return out.join('.');
}
const str = (n: Node) => new TextDecoder(n.tag === 30 ? 'utf-16be' : 'utf-8').decode(body(n));

const OIDS: Record<string, string> = {
  '2.5.4.3': 'CN', '2.5.4.6': 'C', '2.5.4.7': 'L', '2.5.4.8': 'ST', '2.5.4.10': 'O', '2.5.4.11': 'OU',
  '1.2.840.113549.1.1.1': 'RSA', '1.2.840.10045.2.1': 'EC', '1.3.101.112': 'Ed25519', '1.2.840.10040.4.1': 'DSA',
  '1.2.840.113549.1.1.4': 'md5WithRSAEncryption', '1.2.840.113549.1.1.5': 'sha1WithRSAEncryption',
  '1.2.840.113549.1.1.11': 'sha256WithRSAEncryption', '1.2.840.113549.1.1.12': 'sha384WithRSAEncryption',
  '1.2.840.113549.1.1.13': 'sha512WithRSAEncryption', '1.2.840.113549.1.1.10': 'RSASSA-PSS',
  '1.2.840.10045.4.1': 'ecdsa-with-SHA1', '1.2.840.10045.4.3.2': 'ecdsa-with-SHA256', '1.2.840.10045.4.3.3': 'ecdsa-with-SHA384',
  '1.2.840.10045.4.3.4': 'ecdsa-with-SHA512', '1.2.840.113549.1.1.2': 'md2WithRSAEncryption',
  '1.2.840.10045.3.1.7': 'P-256', '1.3.132.0.34': 'P-384', '1.3.132.0.35': 'P-521',
};
const CURVE_BITS: Record<string, number> = { 'P-256': 256, 'P-384': 384, 'P-521': 521 };

function name(n: Node): { text: string; cn: string } {
  const parts: string[] = [];
  let cn = '';
  for (const set of n.kids ?? []) for (const atv of set.kids ?? []) {
    const k = OIDS[oid(kid(atv, 0))] ?? oid(kid(atv, 0));
    const v = str(kid(atv, 1));
    if (k === 'CN') cn = v;
    parts.push(`${k}=${v}`);
  }
  return { text: parts.join(', '), cn };
}

function time(n: Node): string {
  const s = new TextDecoder().decode(body(n));
  const full = n.tag === 23 ? (Number(s.slice(0, 2)) >= 50 ? '19' : '20') + s : s;
  return `${full.slice(0, 4)}-${full.slice(4, 6)}-${full.slice(6, 8)}T${full.slice(8, 10)}:${full.slice(10, 12)}:${full.slice(12, 14)}Z`;
}

function intBits(b: Uint8Array): number {
  let i = 0;
  while (i < b.length && b[i] === 0) i++;
  if (i === b.length) return 0;
  return (b.length - i - 1) * 8 + (32 - Math.clz32(b[i]));
}

export function parseCertificate(der: Uint8Array): CertInfo {
  const cert = parseNode(der, 0);
  const tbs = kid(cert, 0);
  let i = 0;
  if (kid(tbs, 0).cls === 2 && kid(tbs, 0).tag === 0) i = 1;
  const serialB = body(kid(tbs, i));
  const issuer = name(kid(tbs, i + 2));
  const validity = kid(tbs, i + 3);
  const subject = name(kid(tbs, i + 4));
  const spki = kid(tbs, i + 5);
  const algId = kid(spki, 0);
  const keyAlg = OIDS[oid(kid(algId, 0))] ?? oid(kid(algId, 0));
  let keyBits = 0, curve: string | undefined;
  const keyBitString = body(kid(spki, 1)).subarray(1);
  if (keyAlg === 'RSA') {
    const seq = parseNode(keyBitString, 0);
    keyBits = intBits(body(kid(seq, 0)));
  } else if (keyAlg === 'EC') {
    const p = algId.kids?.[1];
    curve = p && p.tag === 6 ? OIDS[oid(p)] ?? oid(p) : 'explicit';
    keyBits = CURVE_BITS[curve] ?? (keyBitString.length - 1) * 4;
  } else if (keyAlg === 'Ed25519') { keyBits = 256; }

  const san: string[] = [];
  let isCA = false;
  const extWrap = tbs.kids!.find((k) => k.cls === 2 && k.tag === 3);
  if (extWrap) {
    for (const ext of kid(extWrap, 0).kids ?? []) {
      const id = oid(kid(ext, 0));
      const val = parseNode(body(ext.kids![ext.kids!.length - 1]), 0);
      if (id === '2.5.29.17') for (const g of val.kids ?? []) { if (g.cls === 2 && g.tag === 2) san.push(new TextDecoder().decode(body(g))); }
      if (id === '2.5.29.19') isCA = !!val.kids?.[0] && val.kids[0].tag === 1 && body(val.kids[0])[0] !== 0;
    }
  }
  const sigAlg = OIDS[oid(kid(kid(cert, 1), 0))] ?? oid(kid(kid(cert, 1), 0));
  return {
    subjectCN: subject.cn, subject: subject.text, issuerCN: issuer.cn, issuer: issuer.text,
    serial: [...serialB].map((b) => b.toString(16).padStart(2, '0')).join(':'),
    notBefore: time(kid(validity, 0)), notAfter: time(kid(validity, 1)),
    sigAlg, keyAlg, keyBits, curve, san, isCA,
    selfSigned: subject.text === issuer.text,
    fingerprint: sha256Hex(der), der,
  };
}

// Compact synchronous SHA-256 (fingerprints must be computed inside the synchronous parser)
const K = new Uint32Array([0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]);
export function sha256Hex(msg: Uint8Array): string {
  const l = msg.length, nb = ((l + 9 + 63) >> 6) << 6;
  const m = new Uint8Array(nb); m.set(msg); m[l] = 0x80;
  const dv = new DataView(m.buffer);
  dv.setUint32(nb - 4, (l * 8) >>> 0); dv.setUint32(nb - 8, Math.floor(l / 0x20000000));
  const H = new Uint32Array([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]);
  const W = new Uint32Array(64);
  const r = (x: number, n: number) => (x >>> n) | (x << (32 - n));
  for (let o = 0; o < nb; o += 64) {
    for (let t = 0; t < 16; t++) W[t] = dv.getUint32(o + t * 4);
    for (let t = 16; t < 64; t++) {
      const s0 = r(W[t - 15], 7) ^ r(W[t - 15], 18) ^ (W[t - 15] >>> 3);
      const s1 = r(W[t - 2], 17) ^ r(W[t - 2], 19) ^ (W[t - 2] >>> 10);
      W[t] = (W[t - 16] + s0 + W[t - 7] + s1) >>> 0;
    }
    let [a, b, c, d, e, f, g, h] = H;
    for (let t = 0; t < 64; t++) {
      const t1 = (h + (r(e, 6) ^ r(e, 11) ^ r(e, 25)) + ((e & f) ^ (~e & g)) + K[t] + W[t]) >>> 0;
      const t2 = ((r(a, 2) ^ r(a, 13) ^ r(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) >>> 0;
      h = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    H[0] += a; H[1] += b; H[2] += c; H[3] += d; H[4] += e; H[5] += f; H[6] += g; H[7] += h;
  }
  return [...H].map((x) => x.toString(16).padStart(8, '0')).join('');
}
