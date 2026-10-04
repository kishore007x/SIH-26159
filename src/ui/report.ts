import type { Analysis } from '../engine/types.ts';
import { cipherInfo, groupName, versionName } from '../engine/catalog.ts';
import { DIM_LABEL } from '../engine/intel.ts';

export function reportJson(a: Analysis) {
  return {
    tool: 'SecureMailScope',
    version: '1.0.0',
    generatedAt: new Date().toISOString(),
    capture: { file: a.fileName, sizeBytes: a.fileSize, ...a.capture, tcpStreams: a.streams },
    posture: a.posture,
    sessions: a.sessions.map((s) => {
      const sh = s.tls?.serverHello;
      const m = a.ml.find((x) => x.session === s.id)!;
      return {
        id: s.id, protocol: s.protocol, mode: s.mode,
        client: `${s.stream.client}:${s.stream.cport}`, server: `${s.stream.server}:${s.stream.sport}`, serverName: s.serverName,
        frames: [s.stream.frames[0], s.stream.frames[s.stream.frames.length - 1]],
        starttls: { advertised: s.starttlsAdvertised, commandFrame: s.starttlsCommandFrame, accepted: s.starttlsAccepted, refused: s.starttlsRefused, strippingSignature: s.strippingSignature, injection: s.injectedAfterStarttls },
        plaintextAuth: s.plaintextAuth.map((p) => ({ frame: p.frame, method: p.method, user: p.user })),
        tls: s.tls && {
          version: sh ? versionName(sh.version) : null, cipherSuite: sh ? cipherInfo(sh.cipher).name : null,
          keyExchange: sh ? (cipherInfo(sh.cipher).kx === 'RSA' ? 'RSA' : groupName(s.tls.kxGroup)) : null,
          forwardSecrecy: sh ? cipherInfo(sh.cipher).kx !== 'RSA' : null, sni: s.tls.clientHello?.sni,
          clientOffered: s.tls.clientHello && { versions: s.tls.clientHello.versions.map(versionName), cipherSuites: s.tls.clientHello.ciphers.map((c) => cipherInfo(c).name), fallbackScsv: s.tls.clientHello.fallbackScsv },
          alerts: s.tls.alerts,
          certificates: s.tls.certificates.map(({ der: _der, ...c }) => c),
        },
        ai: { riskClass: m.riskClass, probabilities: m.probs, anomalyScore: Number(m.anomaly.toFixed(4)), attributions: m.contributions, baselineDeviations: m.deviations },
      };
    }),
    findings: a.findings,
    baselines: a.baselines,
  };
}

const esc = (s: unknown) => String(s ?? '').replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]!));
const SC: Record<string, string> = { critical: '#e11d48', high: '#ea580c', medium: '#d97706', low: '#0284c7', info: '#64748b' };

export function reportHtml(a: Analysis) {
  const p = a.posture;
  const color = p.overall >= 85 ? '#059669' : p.overall >= 55 ? '#d97706' : '#e11d48';
  const sessRows = a.sessions.map((s) => {
    const sh = s.tls?.serverHello; const m = a.ml.find((x) => x.session === s.id)!;
    return `<tr><td class="m">${s.id}</td><td>${s.protocol}</td><td class="m">${esc(s.stream.client)} → ${esc(s.stream.server)}:${s.stream.sport}</td><td>${s.mode.replace('_', ' ')}</td><td class="m">${sh ? versionName(sh.version) : s.tls ? 'aborted' : '—'}</td><td class="m small">${sh ? cipherInfo(sh.cipher).name : '—'}</td><td><span class="sev" style="background:${SC[m.riskClass]}">${m.riskClass}</span></td><td class="m">${m.anomaly.toFixed(2)}</td></tr>`;
  }).join('');
  const findings = a.findings.map((f) => `
    <div class="finding" style="border-left-color:${SC[f.severity]}">
      <div class="fh"><span class="sev" style="background:${SC[f.severity]}">${f.severity}</span> <b>#${f.priority} ${esc(f.title)}</b> <span class="muted m">${f.id} · ${f.ruleId} · ${f.source} · confidence ${Math.round(f.confidence * 100)}%</span></div>
      <table class="kv"><tr><th>Cause</th><td>${esc(f.cause)}</td></tr><tr><th>Exposure</th><td>${esc(f.exposure)}</td></tr><tr><th>Remediation</th><td>${esc(f.remediation)}</td></tr></table>
      <div class="ev">${f.evidence.map((e) => `<div><span class="m">${e.session} · frames ${e.frames.map((x) => '#' + x).join(', ')}</span> — ${esc(e.detail)}</div>`).join('')}</div>
      ${f.references.length ? `<div class="muted small">References: ${f.references.map(esc).join(' · ')}</div>` : ''}
    </div>`).join('');
  const dims = Object.entries(p.dimensions).map(([d, v]) => `<div class="dim"><span>${DIM_LABEL[d as keyof typeof DIM_LABEL]}</span><div class="bar"><i style="width:${v}%;background:${v >= 85 ? '#059669' : v >= 55 ? '#d97706' : '#e11d48'}"></i></div><b>${v}</b></div>`).join('');
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SecureMailScope Report — ${esc(a.fileName)}</title>
<style>
body{font-family:Inter,system-ui,Segoe UI,sans-serif;color:#0f172a;max-width:1100px;margin:0 auto;padding:40px 24px;background:#fff;line-height:1.45}
h1{font-size:28px;margin:0}h2{font-size:18px;margin:36px 0 12px;padding-bottom:6px;border-bottom:2px solid #e2e8f0}
.m{font-family:"JetBrains Mono",Consolas,monospace;font-size:12px}.small{font-size:11px}.muted{color:#64748b}
.hdr{display:flex;justify-content:space-between;align-items:center;gap:24px;padding:24px;border-radius:16px;background:#f8fafc;border:1px solid #e2e8f0}
.score{flex-shrink:0;width:120px;height:120px;border-radius:50%;display:grid;place-items:center;border:10px solid ${color};font-size:36px;font-weight:800;color:${color}}
.dim{display:grid;grid-template-columns:180px 1fr 40px;gap:10px;align-items:center;margin:6px 0;font-size:13px}.bar{height:8px;background:#f1f5f9;border-radius:9px;overflow:hidden}.bar i{display:block;height:100%}
table{border-collapse:collapse;width:100%;font-size:13px}th,td{text-align:left;padding:7px 8px;border-bottom:1px solid #e2e8f0;vertical-align:top}th{background:#f8fafc;font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:#475569}
.sev{color:#fff;border-radius:5px;padding:1px 7px;font-size:10.5px;font-weight:700;text-transform:uppercase}
.finding{border:1px solid #e2e8f0;border-left:5px solid;border-radius:10px;padding:14px 16px;margin:12px 0;page-break-inside:avoid}
.fh{margin-bottom:8px}.kv th{width:110px;background:none}.ev{background:#f8fafc;border-radius:8px;padding:8px 10px;font-size:12.5px;margin:8px 0}
.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}.kpi{border:1px solid #e2e8f0;border-radius:12px;padding:12px}.kpi b{font-size:24px;display:block}
@media print{body{padding:0}.hdr{-webkit-print-color-adjust:exact;print-color-adjust:exact}.sev,.bar i{-webkit-print-color-adjust:exact;print-color-adjust:exact}}
</style></head><body>
<div class="hdr"><div><div class="muted small" style="letter-spacing:.2em;text-transform:uppercase">SecureMailScope · Cryptographic Security Posture Assessment</div>
<h1>Email Forensic Report</h1><div class="m muted">${esc(a.fileName)} · ${a.capture.format.toUpperCase()} · ${a.capture.packetCount} frames · ${new Date(a.capture.start * 1000).toISOString()} – ${new Date(a.capture.end * 1000).toISOString()}</div>
<div style="margin-top:8px;font-size:20px;font-weight:700;color:${color}">${p.label.toUpperCase()} · Grade ${p.grade}</div><div class="muted small">Evidence confidence ${Math.round(p.confidence * 100)}% · generated ${new Date().toISOString()}</div></div>
<div class="score">${p.overall}</div></div>
<h2>Summary</h2>
<div class="grid"><div class="kpi"><span class="muted small">Sessions</span><b>${a.sessions.length}</b></div><div class="kpi"><span class="muted small">Findings</span><b>${a.findings.length}</b></div>
<div class="kpi"><span class="muted small">Critical / High</span><b style="color:#e11d48">${a.findings.filter((f) => f.severity === 'critical').length} / ${a.findings.filter((f) => f.severity === 'high').length}</b></div>
<div class="kpi"><span class="muted small">TLS-protected sessions</span><b>${a.sessions.filter((s) => s.tls?.serverHello).length}</b></div></div>
<h2>Posture dimensions</h2>${dims}
<h2>Prioritised findings</h2>${findings}
<h2>Session inventory</h2><table><tr><th>ID</th><th>Proto</th><th>Endpoints</th><th>Mode</th><th>TLS</th><th>Cipher</th><th>AI risk</th><th>Anomaly</th></tr>${sessRows}</table>
<p class="muted small" style="margin-top:32px">Passive analysis — no traffic was generated and the capture never left the analyst's machine. Credentials observed in cleartext are masked in this report.</p>
</body></html>`;
}

export function download(name: string, content: string, type: string) {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const el = document.createElement('a');
  el.href = url; el.download = name; el.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
