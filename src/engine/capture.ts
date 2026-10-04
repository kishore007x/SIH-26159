import type { CaptureInfo, RawPacket, TcpSegment } from './types.ts';

/** Parses classic libpcap (µs/ns, either endianness) and pcapng (SHB/IDB/EPB/SPB). */
export function parseCapture(buf: ArrayBuffer): { info: CaptureInfo; packets: RawPacket[] } {
  const dv = new DataView(buf);
  if (buf.byteLength < 24) throw new Error('File too small to be a capture');
  const magic = dv.getUint32(0, false);
  if (magic === 0x0a0d0d0a) return parsePcapng(buf);
  let le: boolean, nano: boolean;
  switch (magic) {
    case 0xa1b2c3d4: le = false; nano = false; break;
    case 0xd4c3b2a1: le = true; nano = false; break;
    case 0xa1b23c4d: le = false; nano = true; break;
    case 0x4d3cb2a1: le = true; nano = true; break;
    default: throw new Error('Not a PCAP or PCAPNG file (unknown magic number)');
  }
  const linkType = dv.getUint32(20, le) & 0x0fffffff;
  const packets: RawPacket[] = [];
  let off = 24;
  while (off + 16 <= buf.byteLength) {
    const sec = dv.getUint32(off, le), frac = dv.getUint32(off + 4, le), incl = dv.getUint32(off + 8, le);
    off += 16;
    if (off + incl > buf.byteLength) break;
    packets.push({ frame: packets.length + 1, ts: sec + frac / (nano ? 1e9 : 1e6), linkType, data: new Uint8Array(buf, off, incl) });
    off += incl;
  }
  return { info: info('pcap', [linkType], packets, buf.byteLength), packets };
}

function parsePcapng(buf: ArrayBuffer) {
  const dv = new DataView(buf);
  const packets: RawPacket[] = [];
  const ifaces: { linkType: number; tsres: number }[] = [];
  let le = true;
  let off = 0;
  while (off + 12 <= buf.byteLength) {
    let type = dv.getUint32(off, le);
    if (type === 0x0a0d0d0a) {
      const bom = dv.getUint32(off + 8, true);
      le = bom === 0x1a2b3c4d;
      ifaces.length = 0;
      type = 0x0a0d0d0a;
    }
    const len = dv.getUint32(off + 4, le);
    if (len < 12 || off + len > buf.byteLength) break;
    const body = off + 8;
    if (type === 1) {
      const linkType = dv.getUint16(body, le);
      let tsres = 1e6;
      // options
      let o = body + 8;
      while (o + 4 <= off + len - 4) {
        const code = dv.getUint16(o, le), olen = dv.getUint16(o + 2, le);
        if (code === 0) break;
        if (code === 9 && olen >= 1) {
          const v = dv.getUint8(o + 4);
          tsres = v & 0x80 ? 2 ** (v & 0x7f) : 10 ** (v & 0x7f);
        }
        o += 4 + Math.ceil(olen / 4) * 4;
      }
      ifaces.push({ linkType, tsres });
    } else if (type === 6) {
      const ifid = dv.getUint32(body, le);
      const hi = dv.getUint32(body + 4, le), lo = dv.getUint32(body + 8, le);
      const cap = dv.getUint32(body + 12, le);
      const iface = ifaces[ifid] ?? { linkType: 1, tsres: 1e6 };
      const ts = (hi * 4294967296 + lo) / iface.tsres;
      packets.push({ frame: packets.length + 1, ts, linkType: iface.linkType, data: new Uint8Array(buf, body + 20, cap) });
    } else if (type === 3) {
      const iface = ifaces[0] ?? { linkType: 1, tsres: 1e6 };
      const orig = dv.getUint32(body, le);
      const cap = Math.min(orig, len - 16);
      packets.push({ frame: packets.length + 1, ts: 0, linkType: iface.linkType, data: new Uint8Array(buf, body + 4, cap) });
    }
    off += len;
  }
  return { info: info('pcapng', [...new Set(ifaces.map((i) => i.linkType))], packets, buf.byteLength), packets };
}

function info(format: 'pcap' | 'pcapng', linkTypes: number[], packets: RawPacket[], bytes: number): CaptureInfo {
  const ts = packets.map((p) => p.ts).filter((t) => t > 0);
  return {
    format, linkTypes, packetCount: packets.length, bytes,
    start: ts.length ? Math.min(...ts) : 0, end: ts.length ? Math.max(...ts) : 0,
  };
}

const ipv4 = (d: Uint8Array, o: number) => `${d[o]}.${d[o + 1]}.${d[o + 2]}.${d[o + 3]}`;
const ipv6 = (d: Uint8Array, o: number) => {
  const parts: string[] = [];
  for (let i = 0; i < 16; i += 2) parts.push(((d[o + i] << 8) | d[o + i + 1]).toString(16));
  return parts.join(':').replace(/(^|:)0(:0)+(:|$)/, '::');
};

/** Decodes link → network → TCP. Returns null for anything that is not TCP. */
export function decodeTcp(p: RawPacket): TcpSegment | null {
  const d = p.data;
  let off = 0;
  let etherType = 0;
  switch (p.linkType) {
    case 1: // Ethernet
      if (d.length < 14) return null;
      etherType = (d[12] << 8) | d[13]; off = 14;
      while ((etherType === 0x8100 || etherType === 0x88a8) && off + 4 <= d.length) {
        etherType = (d[off + 2] << 8) | d[off + 3]; off += 4;
      }
      break;
    case 113: // Linux cooked
      etherType = (d[14] << 8) | d[15]; off = 16; break;
    case 276: // Linux cooked v2
      etherType = (d[0] << 8) | d[1]; off = 20; break;
    case 0: case 108: { // BSD loopback
      const fam = d[0] | (d[1] << 8);
      etherType = fam === 2 ? 0x0800 : 0x86dd; off = 4; break;
    }
    case 101: case 12: case 14: case 228: case 229:
      etherType = (d[0] >> 4) === 6 ? 0x86dd : 0x0800; break;
    default: return null;
  }
  let src: string, dst: string, proto: number, l4: number, l4end: number;
  if (etherType === 0x0800) {
    if (off + 20 > d.length) return null;
    const ihl = (d[off] & 0x0f) * 4;
    const total = (d[off + 2] << 8) | d[off + 3];
    proto = d[off + 9];
    src = ipv4(d, off + 12); dst = ipv4(d, off + 16);
    l4 = off + ihl; l4end = Math.min(d.length, off + (total || d.length - off));
  } else if (etherType === 0x86dd) {
    if (off + 40 > d.length) return null;
    proto = d[off + 6];
    const plen = (d[off + 4] << 8) | d[off + 5];
    src = ipv6(d, off + 8); dst = ipv6(d, off + 24);
    l4 = off + 40; l4end = Math.min(d.length, l4 + plen);
    // skip common extension headers
    while ([0, 43, 60].includes(proto) && l4 + 8 <= l4end) { proto = d[l4]; l4 += (d[l4 + 1] + 1) * 8; }
  } else return null;
  if (proto !== 6 || l4 + 20 > l4end) return null;
  const sport = (d[l4] << 8) | d[l4 + 1];
  const dport = (d[l4 + 2] << 8) | d[l4 + 3];
  const seq = ((d[l4 + 4] << 24) | (d[l4 + 5] << 16) | (d[l4 + 6] << 8) | d[l4 + 7]) >>> 0;
  const ack = ((d[l4 + 8] << 24) | (d[l4 + 9] << 16) | (d[l4 + 10] << 8) | d[l4 + 11]) >>> 0;
  const hl = (d[l4 + 12] >> 4) * 4;
  const flags = d[l4 + 13];
  return { frame: p.frame, ts: p.ts, src, dst, sport, dport, seq, ack, flags, payload: d.subarray(l4 + hl, l4end) };
}
