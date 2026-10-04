import type { Baseline, Dimension, EmailSession, Finding, MlSession, Posture, Severity } from './types.ts';
import type { RuleHit } from './rules.ts';
import { serviceOf } from './rules.ts';
import { cipherInfo, groupName, versionName } from './catalog.ts';

// ---------------------------------------------------------------------------
// Cross-session cryptographic drift & certificate lineage
// ---------------------------------------------------------------------------
const fieldsOf = (s: EmailSession): Record<string, string> => {
  const sh = s.tls?.serverHello;
  return {
    'TLS version': sh ? versionName(sh.version) : s.tls ? 'aborted' : 'none',
    'Cipher suite': sh ? cipherInfo(sh.cipher).name : 'none',
    'Key exchange': sh ? (cipherInfo(sh.cipher).kx === 'RSA' ? 'RSA (static)' : groupName(s.tls?.kxGroup)) : 'none',
    'STARTTLS offered': s.mode === 'IMPLICIT_TLS' ? 'implicit' : s.starttlsAdvertised ? 'yes' : 'no',
    'Certificate issuer': s.tls?.certificates[0]?.issuerCN ?? (sh?.version === 0x0304 ? '(encrypted)' : 'none'),
  };
};

export function buildBaselines(sessions: EmailSession[]): Baseline[] {
  const by = new Map<string, EmailSession[]>();
  for (const s of sessions) { const k = `${s.stream.server}:${s.stream.sport}/${s.protocol}`; by.set(k, [...(by.get(k) ?? []), s]); }
  return [...by.entries()].map(([service, ss]) => {
    const fields: Baseline['fields'] = {};
    for (const s of ss) for (const [f, v] of Object.entries(fieldsOf(s))) {
      const arr = (fields[f] ??= []);
      const e = arr.find((x) => x.value === v);
      if (e) e.count++; else arr.push({ value: v, count: 1 });
    }
    for (const arr of Object.values(fields)) arr.sort((a, b) => b.count - a.count);
    return { service, sessions: ss.map((s) => s.id), fields };
  });
}

export function driftHits(sessions: EmailSession[], baselines: Baseline[]): { hits: RuleHit[]; deviations: Map<string, MlSession['deviations']> } {
  const hits: RuleHit[] = [];
  const deviations = new Map<string, MlSession['deviations']>();

  for (const b of baselines) {
    if (b.sessions.length < 3) continue;
    const ss = sessions.filter((s) => b.sessions.includes(s.id));
    for (const s of ss) {
      const f = fieldsOf(s);
      const devs: MlSession['deviations'] = [];
      for (const [field, dist] of Object.entries(b.fields)) {
        const mode = dist[0];
        if (mode.count / b.sessions.length >= 0.5 && f[field] !== mode.value && f[field] !== '(encrypted)' && mode.value !== '(encrypted)')
          devs.push({ field, observed: f[field], baseline: `${mode.value} (${mode.count}/${b.sessions.length})` });
      }
      if (devs.length) deviations.set(s.id, devs);
    }
    // TLS version downgrade relative to baseline
    const versions = ss.map((s) => s.tls?.serverHello?.version).filter((v): v is number => !!v);
    const top = Math.max(0, ...versions);
    const majority = versions.filter((v) => v === top).length / Math.max(1, versions.length);
    for (const s of ss) {
      const v = s.tls?.serverHello?.version;
      if (v && v < top && majority >= 0.5) hits.push({
        key: `DRIFT_DOWNGRADE_${b.service}`, ruleId: 'SMS-DR-001', title: `Protocol downgrade vs. service baseline (${b.service})`, severity: 'high', dimension: 'anomaly', session: s,
        confidence: Math.min(0.95, 0.55 + 0.08 * ss.length), source: 'drift',
        evidence: { frames: [s.tls!.serverHello!.frame], label: 'Baseline deviation', detail: `${versionName(v)} + ${cipherInfo(s.tls!.serverHello!.cipher).name} while ${Math.round(majority * 100)}% of sessions to this service negotiate ${versionName(top)}` },
        cause: 'Same server negotiated materially weaker parameters for this client than for its peers.',
        exposure: 'Indicates a downgrade (forced fallback or legacy client) — the weakest session defines the real-world posture.',
        remediation: 'Disable legacy protocol versions server-side so fallback is impossible; investigate the client and path.',
        references: ['RFC 7507', 'RFC 8996'],
      });
    }
    // STARTTLS capability disappearing
    const adv = ss.filter((s) => s.starttlsAdvertised).length;
    for (const s of ss) if (!s.starttlsAdvertised && s.mode !== 'IMPLICIT_TLS' && adv / ss.length >= 0.5) hits.push({
      key: `DRIFT_STARTTLS_${b.service}`, ruleId: 'SMS-DR-002', title: 'STARTTLS capability missing vs. service baseline', severity: 'critical', dimension: 'starttls', session: s,
      confidence: Math.min(0.97, 0.6 + 0.08 * ss.length), source: 'drift',
      evidence: { frames: [s.transcript.find((t) => t.dir === 's2c' && /^250 /.test(t.text))?.frame ?? s.stream.frames[0]], label: 'Capability drift', detail: `STARTTLS advertised in ${adv}/${ss.length} sessions to ${b.service} but absent here` },
      cause: 'The server capability set observed by this client differs from every other client.',
      exposure: 'Strong indicator of active STARTTLS stripping on this client\'s network path.',
      remediation: 'Trace the network path of the affected client; pin TLS requirement in the client.',
      references: ['Poddebniak et al., USENIX Sec 2021'],
    });
  }

  // Version-fallback dance: aborted high-version handshake then lower-version reconnect without SCSV
  for (const a of sessions) {
    const ch = a.tls?.clientHello;
    if (!ch || a.tls?.serverHello) continue;
    const maxA = Math.max(ch.legacyVersion, ...ch.versions);
    const b = sessions.find((x) => x !== a && x.stream.client === a.stream.client && x.stream.server === a.stream.server && x.stream.sport === a.stream.sport && x.stream.start >= a.stream.start && x.stream.start - a.stream.start < 10 && x.tls?.clientHello);
    if (!b) continue;
    const chB = b.tls!.clientHello!;
    const maxB = Math.max(chB.legacyVersion, ...chB.versions);
    if (maxB < maxA && !chB.fallbackScsv) for (const s of [a, b]) hits.push({
      key: `FALLBACK_DANCE_${a.id}`, ruleId: 'SMS-DR-003', title: 'Insecure version fallback without TLS_FALLBACK_SCSV', severity: 'high', dimension: 'tls', session: s,
      confidence: 0.93, source: 'drift',
      evidence: { frames: s === a ? [ch.frame, ...(a.tls!.alerts.map((x) => x.frame))] : [chB.frame], label: s === a ? 'Aborted attempt' : 'Fallback retry', detail: s === a ? `${a.id}: offered ${versionName(maxA)} → handshake_failure / reset` : `${b.id}: retried ${(b.stream.start - a.stream.start).toFixed(2)}s later offering only ${versionName(maxB)}, no FALLBACK_SCSV` },
      cause: 'Client retries with lower protocol versions after a failed handshake and does not signal the fallback.',
      exposure: 'Active attacker can inject failures to force weak crypto (POODLE-style downgrade dance).',
      remediation: 'Disable insecure client fallback; enable TLS_FALLBACK_SCSV / rely on TLS 1.3 downgrade sentinel; remove legacy versions server-side.',
      references: ['RFC 7507', 'RFC 8446 §4.1.3'],
    });
  }

  // Certificate lineage: same subject served with different issuers / keys
  const byCN = new Map<string, { s: EmailSession; issuer: string; fp: string }[]>();
  for (const s of sessions) for (const c of s.tls?.certificates.slice(0, 1) ?? []) {
    const arr = byCN.get(c.subjectCN) ?? [];
    arr.push({ s, issuer: c.issuerCN, fp: c.fingerprint }); byCN.set(c.subjectCN, arr);
  }
  for (const [cn, list] of byCN) {
    const issuers = new Map<string, number>();
    list.forEach((l) => issuers.set(l.issuer, (issuers.get(l.issuer) ?? 0) + 1));
    if (issuers.size < 2) continue;
    const [main] = [...issuers.entries()].sort((a, b) => b[1] - a[1]);
    for (const l of list) if (l.issuer !== main[0]) hits.push({
      key: `CERT_LINEAGE_${cn}_${l.fp}`, ruleId: 'SMS-DR-004', title: `Certificate lineage break for ${cn} — possible TLS interception`, severity: 'critical', dimension: 'certificate', session: l.s,
      confidence: Math.min(0.96, 0.6 + 0.09 * list.length), source: 'drift',
      evidence: { frames: [l.s.tls!.certFrame ?? 0], label: 'Certificate lineage', detail: `${cn} presented by "${l.issuer}" (SHA-256 ${l.fp.slice(0, 16)}…) while ${main[1]} other session(s) chain to "${main[0]}"` },
      cause: 'A different certificate authority vouched for the same mail hostname within the capture window.',
      exposure: 'Hallmark of a TLS-intercepting proxy or MITM: mailbox credentials and content are visible to the interceptor.',
      remediation: 'Identify the device presenting the foreign issuer, pin the expected CA in clients, and rotate credentials of affected users.',
      references: ['RFC 7469', 'RFC 6962'],
    });
  }
  return { hits, deviations };
}

// ---------------------------------------------------------------------------
// Feature extraction + Isolation Forest + explainable ordinal risk model
// ---------------------------------------------------------------------------
export const FEATURE_NAMES = [
  'TLS version', 'Cipher strength', 'Forward secrecy', 'AEAD', 'Cert key strength', 'Cert validity',
  'Encrypted transport', 'Cleartext credentials', 'Cleartext content', 'Handshake aborted', 'Fatal alerts', 'Baseline deviations',
  'Certificate lineage break', 'STARTTLS integrity violation',
];

export function features(s: EmailSession, ctx: { devs: number; lineage: boolean }, captureTime: number): number[] {
  const { devs } = ctx;
  const integrity = s.injectedAfterStarttls || s.strippingSignature || s.starttlsRefused ? 1 : 0;
  const extra = [ctx.lineage ? 1 : 0, integrity];
  const sh = s.tls?.serverHello;
  const ci = sh ? cipherInfo(sh.cipher) : undefined;
  const leaf = s.tls?.certificates[0];
  const vScore = sh ? Math.max(0, (sh.version - 0x0300) / 4) : 0;
  if (s.tls && !sh) {
    // aborted handshake: no data protected or exposed — protective properties are unknown, not absent
    return [0.6, 0.6, 0.6, 0.6, 0.6, 0.6, 0.6, Math.min(1, s.plaintextAuth.length), Math.min(1, s.plaintextMail.length), 1,
      Math.min(1, s.tls.alerts.filter((a) => a.level === 2).length), Math.min(1, devs / 3), ...extra];
  }
  return [
    vScore,
    ci ? (ci.weak.length ? 0.2 : Math.min(1, ci.bits / 256)) : 0,
    ci ? (ci.kx === 'RSA' ? 0 : 1) : 0,
    ci ? (ci.mode === 'AEAD' ? 1 : 0) : 0,
    leaf ? Math.min(1, leaf.keyAlg === 'EC' ? leaf.keyBits / 256 : leaf.keyBits / 3072) : sh ? 0.85 : 0.5,
    leaf ? (Date.parse(leaf.notAfter) / 1000 < captureTime ? 0 : 1) : sh ? 0.9 : 0.5,
    sh ? 1 : 0,
    Math.min(1, s.plaintextAuth.length),
    Math.min(1, s.plaintextMail.length),
    s.tls?.clientHello && !sh ? 1 : 0,
    Math.min(1, (s.tls?.alerts.filter((a) => a.level === 2).length ?? 0)),
    Math.min(1, devs / 3),
    ...extra,
  ];
}

function mulberry(seed: number) {
  return () => { seed |= 0; seed = (seed + 0x6d2b79f5) | 0; let t = Math.imul(seed ^ (seed >>> 15), 1 | seed); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
}
const cFactor = (n: number) => (n <= 1 ? 0 : 2 * (Math.log(n - 1) + 0.5772156649) - (2 * (n - 1)) / n);

type ITree = { f: number; v: number; l: ITree; r: ITree } | { size: number };
export function isolationForest(X: number[][], trees = 200, seed = 42): number[] {
  if (X.length < 3) return X.map(() => 0);
  const rnd = mulberry(seed);
  const psi = Math.min(64, X.length);
  const maxDepth = Math.ceil(Math.log2(psi));
  const build = (rows: number[][], depth: number): ITree => {
    if (depth >= maxDepth || rows.length <= 1) return { size: rows.length };
    const dims = X[0].map((_, i) => i).filter((i) => Math.min(...rows.map((r) => r[i])) < Math.max(...rows.map((r) => r[i])));
    if (!dims.length) return { size: rows.length };
    const f = dims[Math.floor(rnd() * dims.length)];
    const lo = Math.min(...rows.map((r) => r[f])), hi = Math.max(...rows.map((r) => r[f]));
    const v = lo + rnd() * (hi - lo);
    return { f, v, l: build(rows.filter((r) => r[f] < v), depth + 1), r: build(rows.filter((r) => r[f] >= v), depth + 1) };
  };
  const forest: ITree[] = [];
  for (let t = 0; t < trees; t++) {
    const sample = Array.from({ length: psi }, () => X[Math.floor(rnd() * X.length)]);
    forest.push(build(sample, 0));
  }
  const pathLen = (x: number[], node: ITree, d: number): number =>
    'size' in node ? d + cFactor(node.size) : pathLen(x, x[node.f] < node.v ? node.l : node.r, d + 1);
  const c = cFactor(psi);
  return X.map((x) => 2 ** (-(forest.reduce((a, t) => a + pathLen(x, t, 0), 0) / trees) / c));
}

// Expert-calibrated ordinal logistic model. Positive weight = increases risk.
export const RISK_WEIGHTS = [-1.6, -1.2, -1.1, -0.6, -1.0, -1.3, -1.4, 3.2, 2.1, 1.1, 0.8, 1.9, 3.4, 2.4];
const B = 3.05;
const THRESH = { medium: 0.8, high: 1.9, critical: 3.1 };
const sig = (z: number) => 1 / (1 + Math.exp(-z * 1.6));

export function classify(x: number[], anomaly: number) {
  // protective features (negative weight) add risk by their absence, risky ones by their presence
  const contrib = x.map((v, i) => ({ feature: FEATURE_NAMES[i], value: v, weight: RISK_WEIGHTS[i] < 0 ? -RISK_WEIGHTS[i] * (1 - v) : RISK_WEIGHTS[i] * v }));
  const z = contrib.reduce((a, c) => a + c.weight, 0) - B + Math.max(0, anomaly - 0.55) * 2.5;
  const pCrit = sig(z - THRESH.critical), pHigh = sig(z - THRESH.high), pMed = sig(z - THRESH.medium);
  const probs = { critical: pCrit, high: pHigh - pCrit, medium: pMed - pHigh, low: 1 - pMed };
  const riskClass = (Object.entries(probs).sort((a, b) => b[1] - a[1])[0][0]) as MlSession['riskClass'];
  const contributions = contrib.filter((c) => c.weight > 0.05).sort((a, b) => b.weight - a.weight).slice(0, 5);
  return { probs, riskClass, contributions, z };
}

// ---------------------------------------------------------------------------
// Aggregation, prioritisation, posture
// ---------------------------------------------------------------------------
const SEV_SCORE: Record<Severity, number> = { critical: 100, high: 60, medium: 30, low: 10, info: 0 };

export function aggregate(hits: RuleHit[], ml: MlSession[]): Finding[] {
  const map = new Map<string, Finding>();
  for (const h of hits) {
    let f = map.get(h.key);
    if (!f) {
      f = {
        id: '', ruleId: h.ruleId, title: h.title, severity: h.severity, dimension: h.dimension, sessions: [], evidence: [],
        cause: h.cause, exposure: h.exposure, remediation: h.remediation, references: h.references, confidence: h.confidence, source: h.source ?? 'rule',
      };
      map.set(h.key, f);
    }
    if (!f.sessions.includes(h.session.id)) f.sessions.push(h.session.id);
    f.evidence.push({ session: h.session.id, ...h.evidence });
    f.confidence = Math.max(f.confidence, h.confidence);
  }
  const findings = [...map.values()];
  const mlBy = new Map(ml.map((m) => [m.session, m]));
  for (const f of findings) {
    f.mlScore = Math.max(...f.sessions.map((s) => { const m = mlBy.get(s); return m ? m.probs.critical + m.probs.high : 0; }));
  }
  const score = (f: Finding) => SEV_SCORE[f.severity] * (0.5 + 0.5 * f.confidence) * (1 + 0.35 * (f.mlScore ?? 0)) + 2 * Math.log2(1 + f.sessions.length);
  findings.sort((a, b) => score(b) - score(a));
  findings.forEach((f, i) => { f.priority = i + 1; f.id = `F-${String(i + 1).padStart(3, '0')}`; });
  return findings;
}

const PENALTY: Record<Severity, number> = { critical: 55, high: 30, medium: 14, low: 5, info: 0 };
export const DIM_WEIGHTS: Record<Dimension, number> = { protocol: 0.13, tls: 0.15, cipher: 0.14, keyExchange: 0.1, certificate: 0.16, starttls: 0.2, anomaly: 0.12 };
export const DIM_LABEL: Record<Dimension, string> = { protocol: 'Protocol', tls: 'TLS Version', cipher: 'Cipher', keyExchange: 'Key Exchange / PFS', certificate: 'Certificate', starttls: 'STARTTLS', anomaly: 'Behavioural Anomaly' };

export function posture(findings: Finding[], sessions: EmailSession[], resolved: Set<string> = new Set()): Posture {
  const dims = Object.fromEntries(Object.keys(DIM_WEIGHTS).map((d) => [d, 100])) as Record<Dimension, number>;
  const active = findings.filter((f) => !resolved.has(f.id));
  const n = Math.max(1, sessions.length);
  for (const f of active) {
    const spread = 0.65 + 0.35 * Math.min(1, f.sessions.length / n * 3);
    dims[f.dimension] -= PENALTY[f.severity] * spread * (0.6 + 0.4 * f.confidence);
  }
  for (const d of Object.keys(dims) as Dimension[]) dims[d] = Math.max(0, Math.round(dims[d]));
  let overall = Object.entries(DIM_WEIGHTS).reduce((a, [d, w]) => a + dims[d as Dimension] * w, 0);
  const crit = active.filter((f) => f.severity === 'critical').length;
  const high = active.filter((f) => f.severity === 'high').length;
  if (crit) overall = Math.min(overall, 42 - Math.min(20, (crit - 1) * 5));
  else if (high) overall = Math.min(overall, 72 - Math.min(14, (high - 1) * 3));
  overall = Math.max(0, Math.round(overall));
  const grade = overall >= 90 ? 'A' : overall >= 80 ? 'B' : overall >= 65 ? 'C' : overall >= 50 ? 'D' : overall >= 30 ? 'E' : 'F';
  const label = overall >= 90 ? 'Hardened' : overall >= 75 ? 'Acceptable' : overall >= 55 ? 'Elevated Risk' : overall >= 35 ? 'High Risk' : 'Critical Risk';
  // evidence completeness: TLS 1.3 hides certificates, aborted sessions are partial
  const conf = sessions.reduce((a, s) => a + (s.tls?.serverHello ? (s.tls.certificates.length ? 1 : 0.86) : s.tls ? 0.72 : 1), 0) / n;
  return { overall, grade, label, dimensions: dims, confidence: Math.round(conf * 100) / 100 };
}

export { serviceOf };
