import { readFileSync } from 'node:fs';
import { analyze } from '../src/engine/analyze.ts';
import { versionName, cipherInfo } from '../src/engine/catalog.ts';
for (const f of ['acme-mail-incident.pcap', 'acme-mail-hardened.pcapng']) {
  const b = readFileSync(`public/samples/${f}`);
  const a = await analyze(b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength), f);
  console.log(`\n=== ${f}: ${a.capture.packetCount} pkts, ${a.streams} streams, ${a.sessions.length} sessions, score ${a.posture.overall} ${a.posture.grade} ${a.posture.label} conf ${a.posture.confidence}`);
  console.log(a.posture.dimensions);
  for (const s of a.sessions) {
    const m = a.ml.find(x => x.session === s.id)!;
    console.log(s.id, s.protocol, s.stream.client, '->', `${s.stream.server}:${s.stream.sport}`, s.mode, s.tls?.serverHello ? versionName(s.tls.serverHello.version) + ' ' + cipherInfo(s.tls.serverHello.cipher).name : '-', 'certs', s.tls?.certificates.map(c => c.subjectCN + '/' + c.keyAlg + c.keyBits).join(',') ?? '', 'caps', s.capabilities.join('|'), '| anomaly', m.anomaly.toFixed(2), m.riskClass);
  }
  for (const f of a.findings) console.log(f.id, f.severity.padEnd(8), f.source.padEnd(5), f.sessions.join(','), f.title, (f.mlScore ?? 0).toFixed(2));
}
