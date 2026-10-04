import type { Analysis, MlSession, TcpSegment } from './types.ts';
import { decodeTcp, parseCapture } from './capture.ts';
import { reassemble } from './streams.ts';
import { buildSession, isEmailStream } from './email.ts';
import { runRules } from './rules.ts';
import { aggregate, buildBaselines, classify, driftHits, features, isolationForest, posture } from './intel.ts';

export const STAGES = [
  { id: 'parse', label: 'Capture decoding', detail: 'PCAP / PCAPNG frames' },
  { id: 'tcp', label: 'TCP reassembly', detail: 'Stream reconstruction' },
  { id: 'email', label: 'Email sessions', detail: 'SMTP · IMAP · POP3' },
  { id: 'tls', label: 'STARTTLS & TLS', detail: 'Handshake + X.509' },
  { id: 'rules', label: 'Crypto checks', detail: 'Rule engine' },
  { id: 'drift', label: 'Drift & lineage', detail: 'Cross-session baseline' },
  { id: 'ml', label: 'AI risk model', detail: 'Isolation Forest + classifier' },
  { id: 'posture', label: 'Posture & priority', detail: 'Evidence-linked findings' },
] as const;
export type StageId = (typeof STAGES)[number]['id'];

export type Progress = (stage: StageId, metric: string) => void | Promise<void>;

export async function analyze(buf: ArrayBuffer, fileName: string, onStage: Progress = () => {}): Promise<Analysis> {
  const timings: Analysis['timings'] = [];
  let t = performance.now();
  const mark = async (stage: StageId, metric: string) => {
    const now = performance.now();
    timings.push({ stage, ms: now - t });
    await onStage(stage, metric);
    t = performance.now();
  };

  const { info, packets } = parseCapture(buf);
  await mark('parse', `${info.packetCount.toLocaleString()} frames`);

  const segs: TcpSegment[] = [];
  for (const p of packets) { const s = decodeTcp(p); if (s) segs.push(s); }
  const streams = reassemble(segs);
  await mark('tcp', `${streams.length} TCP streams`);

  const emailStreams = streams.filter(isEmailStream);
  const sessions = emailStreams.map((s, i) => buildSession(s, i));
  await mark('email', `${sessions.length} sessions`);

  const tlsCount = sessions.filter((s) => s.tls).length;
  const certCount = new Set(sessions.flatMap((s) => s.tls?.certificates.map((c) => c.fingerprint) ?? [])).size;
  await mark('tls', `${tlsCount} handshakes · ${certCount} certs`);

  const captureTime = info.end || Date.now() / 1000;
  const ruleHits = runRules(sessions, captureTime);
  await mark('rules', `${ruleHits.length} rule hits`);

  const baselines = buildBaselines(sessions);
  const { hits: dHits, deviations } = driftHits(sessions, baselines);
  await mark('drift', `${dHits.length} deviations`);

  const lineage = new Set(dHits.filter((h) => h.ruleId === 'SMS-DR-004').map((h) => h.session.id));
  const X = sessions.map((s) => features(s, { devs: deviations.get(s.id)?.length ?? 0, lineage: lineage.has(s.id) }, captureTime));
  const anomaly = isolationForest(X);
  const ml: MlSession[] = sessions.map((s, i) => {
    const c = classify(X[i], anomaly[i]);
    return { session: s.id, anomaly: anomaly[i], riskClass: c.riskClass, probs: c.probs, contributions: c.contributions, deviations: deviations.get(s.id) ?? [] };
  });
  // statistically isolated sessions not explained by any rule get an ML-sourced finding
  const explained = new Set([...ruleHits, ...dHits].map((h) => h.session.id));
  const mlHits = sessions.filter((s, i) => sessions.length >= 8 && anomaly[i] > 0.7 && !explained.has(s.id)).map((s) => ({
    key: `ML_OUTLIER_${s.id}`, ruleId: 'SMS-ML-001', title: 'Statistically anomalous TLS session', severity: 'medium' as const, dimension: 'anomaly' as const, session: s,
    confidence: 0.6, source: 'ml' as const,
    evidence: { frames: [s.stream.frames[0]], label: 'Isolation Forest', detail: `Anomaly score ${(ml[s.index].anomaly).toFixed(2)} — isolated faster than ${Math.round(anomaly.filter((a) => a < anomaly[s.index]).length / anomaly.length * 100)}% of sessions` },
    cause: 'Session feature vector diverges from the capture population.', exposure: 'Unusual behaviour that may indicate misconfiguration or tampering.', remediation: 'Review the session evidence chain manually.', references: [],
  }));
  await mark('ml', `${ml.filter((m) => m.anomaly > 0.6).length} outliers`);

  const findings = aggregate([...ruleHits, ...dHits, ...mlHits], ml);
  const p = posture(findings, sessions);
  await mark('posture', `Score ${p.overall} · ${findings.length} findings`);

  return {
    fileName, fileSize: buf.byteLength, capture: info, streams: streams.length, sessions, findings, ml, posture: p, baselines, timings,
    analyzedAt: new Date().toISOString(), rawPackets: packets,
  };
}
