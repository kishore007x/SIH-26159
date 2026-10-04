import type { Dimension, EmailSession, Evidence, Finding, Severity } from './types.ts';
import { cipherInfo, versionName } from './catalog.ts';

export interface RuleHit {
  key: string; ruleId: string; title: string; severity: Severity; dimension: Dimension;
  session: EmailSession; evidence: Omit<Evidence, 'session'>; confidence: number;
  cause: string; exposure: string; remediation: string; references: string[]; source?: Finding['source'];
}

export function serviceOf(s: EmailSession) {
  return `${s.stream.server}:${s.stream.sport}/${s.protocol}`;
}

export function runRules(sessions: EmailSession[], captureTime: number): RuleHit[] {
  const hits: RuleHit[] = [];
  const add = (h: RuleHit) => hits.push(h);

  for (const s of sessions) {
    const tls = s.tls;
    const enc = !!tls?.serverHello;

    // ---------- STARTTLS / plaintext behaviour ----------
    if (s.strippingSignature) add({
      key: 'STARTTLS_STRIPPED', ruleId: 'SMS-ST-001', title: 'STARTTLS capability stripped from server greeting', severity: 'critical', dimension: 'starttls', session: s, confidence: 0.96,
      evidence: { frames: [s.strippingSignature.frame], label: 'EHLO capability list', detail: `"${s.strippingSignature.text}" — STARTTLS overwritten by an in-path device (classic downgrade signature)` },
      cause: 'An in-path device rewrote the EHLO response, replacing STARTTLS with a filler token.',
      exposure: 'Client could not upgrade to TLS; the entire submission, including credentials, travelled in cleartext (active STARTTLS downgrade).',
      remediation: 'Remove the SMTP inspection/fixup feature on the middlebox, enforce TLS on submission (port 587 "smtpd_tls_security_level=encrypt") or migrate clients to implicit TLS on 465 (RFC 8314).',
      references: ['RFC 8314 §3', 'RFC 3207', 'Durumeric et al., IMC 2015'],
    });
    if (s.plaintextAuth.length && !enc) for (const a of s.plaintextAuth) add({
      key: 'PLAINTEXT_CREDENTIALS', ruleId: 'SMS-ST-002', title: 'Credentials transmitted without encryption', severity: 'critical', dimension: 'starttls', session: s, confidence: 0.99,
      evidence: { frames: [a.frame], label: a.method, detail: `User "${a.user ?? '?'}" authenticated with ${a.method} before any TLS negotiation (secret ${a.secretMasked ?? 'captured'})` },
      cause: `${s.protocol} authentication occurred on an unencrypted channel.`,
      exposure: 'Any passive observer on the path can harvest reusable mailbox credentials.',
      remediation: s.protocol === 'POP3' ? 'Disable cleartext USER/PASS on port 110 (e.g. Dovecot "disable_plaintext_auth=yes"), require STLS or POP3S on 995.' : 'Advertise AUTH only after TLS (Postfix "smtpd_tls_auth_only=yes"); reject AUTH on unencrypted sessions.',
      references: ['RFC 8314', 'RFC 2595 §2.2', 'RFC 4954 §4'],
    });
    if (s.plaintextMail.length && !enc) add({
      key: 'PLAINTEXT_CONTENT', ruleId: 'SMS-PR-001', title: 'Email content exposed in cleartext', severity: 'high', dimension: 'protocol', session: s, confidence: 0.98,
      evidence: { frames: s.plaintextMail.map((m) => m.frame), label: 'Message transfer', detail: s.plaintextMail.map((m) => `${m.from ?? ''} → ${m.to ?? ''}${m.subject ? ` · "${m.subject}"` : ''}`).join(' | ') },
      cause: 'Message envelope and body were transferred without transport encryption.',
      exposure: 'Confidential message content and metadata are readable and modifiable in transit (BEC / invoice-fraud vector).',
      remediation: 'Enforce TLS for this path (MTA-STS / DANE for inbound relays, encrypt-level TLS policy for known partners).',
      references: ['RFC 8461 (MTA-STS)', 'RFC 7672 (DANE SMTP)'],
    });
    if (s.mode === 'PLAINTEXT' && s.starttlsAdvertised && !s.starttlsCommandFrame && !s.strippingSignature) add({
      key: 'STARTTLS_NOT_USED', ruleId: 'SMS-ST-003', title: 'STARTTLS advertised but not negotiated', severity: 'high', dimension: 'starttls', session: s, confidence: 0.95,
      evidence: { frames: [s.transcript.find((t) => t.tag === 'cap')?.frame ?? s.stream.frames[0]], label: 'Capability', detail: `Server offered ${s.protocol === 'POP3' ? 'STLS' : 'STARTTLS'}, client continued in plaintext` },
      cause: 'Opportunistic TLS is optional on this service and the client did not request it.',
      exposure: 'Sessions silently remain unencrypted; trivial to downgrade.',
      remediation: 'Make TLS mandatory on the server (reject commands before STARTTLS) and configure clients with "require TLS".',
      references: ['RFC 8314 §4', 'Poddebniak et al., USENIX Sec 2021'],
    });
    if (s.starttlsRefused) add({
      key: 'STARTTLS_REFUSED', ruleId: 'SMS-ST-004', title: 'STARTTLS refused — session fell back to plaintext', severity: 'high', dimension: 'starttls', session: s, confidence: 0.97,
      evidence: { frames: [s.starttlsCommandFrame ?? 0, s.starttlsRefused.frame].filter(Boolean), label: 'STARTTLS response', detail: `"${s.starttlsRefused.text}" then transaction continued unencrypted` },
      cause: 'Server TLS stack unavailable (key/cert load failure or resource issue) and the peer accepted a cleartext fallback.',
      exposure: 'Inbound mail delivered in cleartext; failure mode can be induced deliberately by an attacker.',
      remediation: 'Investigate the TLS service failure on the MTA, alert on 454 responses and publish an MTA-STS "enforce" policy so senders refuse to fall back.',
      references: ['RFC 3207 §4', 'RFC 8461'],
    });
    if (s.injectedAfterStarttls) add({
      key: 'STARTTLS_INJECTION', ruleId: 'SMS-ST-005', title: 'Plaintext commands pipelined after STARTTLS', severity: 'high', dimension: 'starttls', session: s, confidence: 0.92,
      evidence: { frames: [s.injectedAfterStarttls.frame], label: 'Same TCP segment', detail: `After STARTTLS the peer sent: ${s.injectedAfterStarttls.text}` },
      cause: 'Unencrypted commands were buffered alongside STARTTLS; vulnerable servers execute them inside the TLS session.',
      exposure: 'STARTTLS command-injection (CVE-2011-0411 class) — attacker-controlled commands gain the integrity of the TLS session.',
      remediation: 'Verify the MTA discards the plaintext buffer at STARTTLS (patched Postfix ≥ 2.8.4); block the source relay and review its other sessions.',
      references: ['CVE-2011-0411', 'Poddebniak et al., USENIX Sec 2021'],
    });
    if (s.mode === 'PLAINTEXT' && !s.starttlsAdvertised && !s.strippingSignature && !s.plaintextAuth.length && !s.plaintextMail.length && !s.starttlsRefused) add({
      key: 'NO_TLS', ruleId: 'SMS-PR-002', title: 'Email session without any TLS', severity: 'medium', dimension: 'protocol', session: s, confidence: 0.8,
      evidence: { frames: [s.stream.frames[0]], label: 'Session', detail: `${s.protocol} session carried no TLS at all` },
      cause: 'Service does not offer STARTTLS.', exposure: 'Traffic exposed to passive interception.', remediation: 'Enable STARTTLS or implicit TLS on the service.', references: ['RFC 8314'],
    });

    if (!tls) continue;

    // ---------- TLS handshake ----------
    const sh = tls.serverHello, ch = tls.clientHello;
    const alert = tls.alerts.find((a) => a.level === 2);
    if (ch && !sh) add({
      key: 'HANDSHAKE_FAILED', ruleId: 'SMS-AN-001', title: 'TLS handshake aborted', severity: 'medium', dimension: 'anomaly', session: s, confidence: 0.9,
      evidence: { frames: [ch.frame, alert?.frame ?? 0].filter(Boolean), label: 'Handshake', detail: `ClientHello (max ${versionName(Math.max(ch.legacyVersion, ...ch.versions))}) answered by ${alert ? `fatal alert ${alert.desc}` : 'no ServerHello'}${s.stream.sawRst ? ', connection reset' : ''}` },
      cause: 'Handshake terminated before parameters were agreed.', exposure: 'Repeated aborts are a precursor to version-fallback (downgrade) attacks.',
      remediation: 'Correlate with subsequent connections from the same client; inspect middleboxes on the path.', references: ['RFC 7507'],
    });
    if (!sh) continue;
    const ci = cipherInfo(sh.cipher);
    if (sh.version < 0x0303) add({
      key: `DEPRECATED_TLS_${sh.version}`, ruleId: 'SMS-TL-001', title: `Deprecated protocol negotiated: ${versionName(sh.version)}`, severity: sh.version <= 0x0300 ? 'critical' : 'high', dimension: 'tls', session: s, confidence: 0.98,
      evidence: { frames: [sh.frame], label: 'ServerHello', detail: `Server selected ${versionName(sh.version)} (client offered max ${versionName(ch ? Math.max(ch.legacyVersion, ...ch.versions) : undefined)})` },
      cause: `Server still permits ${versionName(sh.version)}.`, exposure: 'Exposed to BEAST/POODLE-class weaknesses and lacks modern AEAD ciphers; formally deprecated by RFC 8996.',
      remediation: 'Set minimum protocol to TLS 1.2 (Postfix "smtpd_tls_protocols = >=TLSv1.2", Dovecot "ssl_min_protocol = TLSv1.2"); prefer TLS 1.3.',
      references: ['RFC 8996', 'NIST SP 800-52r2'],
    });
    if (ci.weak.length) add({
      key: `WEAK_CIPHER_${sh.cipher}`, ruleId: 'SMS-CI-001', title: `Weak cipher suite: ${ci.name}`, severity: ci.mode === 'NULL' || ci.bits < 64 ? 'critical' : 'high', dimension: 'cipher', session: s, confidence: 0.98,
      evidence: { frames: [sh.frame], label: 'ServerHello cipher', detail: `${ci.name} — ${ci.weak.join('; ')}` },
      cause: 'Server cipher policy allows legacy algorithms and selected one.', exposure: ci.weak.join('; ') + '.',
      remediation: 'Restrict ciphers to ECDHE + AEAD (e.g. "tls_high_cipherlist = ECDHE+AESGCM:ECDHE+CHACHA20", exclude RC4/3DES/NULL/EXPORT).',
      references: ['RFC 7465', 'CVE-2016-2183', 'RFC 9325'],
    });
    else if (ci.mode === 'CBC' && sh.version < 0x0304) add({
      key: 'CBC_MODE', ruleId: 'SMS-CI-002', title: 'CBC-mode cipher in use', severity: 'low', dimension: 'cipher', session: s, confidence: 0.9,
      evidence: { frames: [sh.frame], label: 'ServerHello cipher', detail: `${ci.name} (MAC-then-encrypt)` },
      cause: 'Non-AEAD cipher selected.', exposure: 'Historically exposed to padding-oracle attacks (Lucky13).', remediation: 'Prefer AES-GCM / ChaCha20-Poly1305 suites.', references: ['RFC 9325 §4.2'],
    });
    if (ci.kx === 'RSA') add({
      key: 'NO_PFS', ruleId: 'SMS-KX-001', title: 'No forward secrecy (static RSA key exchange)', severity: 'medium', dimension: 'keyExchange', session: s, confidence: 0.97,
      evidence: { frames: [sh.frame], label: 'Key exchange', detail: `${ci.name} uses RSA key transport` },
      cause: 'Cipher suite without ephemeral (EC)DHE.', exposure: 'Compromise of the server private key decrypts every recorded session retroactively.',
      remediation: 'Disable TLS_RSA_* suites; require ECDHE.', references: ['RFC 9325 §4.1'],
    });
    if (tls.dhBits && tls.dhBits < 2048) add({
      key: 'WEAK_DH', ruleId: 'SMS-KX-002', title: `Weak Diffie-Hellman group (${tls.dhBits}-bit)`, severity: 'high', dimension: 'keyExchange', session: s, confidence: 0.95,
      evidence: { frames: [tls.kxFrame ?? sh.frame], label: 'ServerKeyExchange', detail: `DH prime ${tls.dhBits} bits` },
      cause: 'Small finite-field DH parameters.', exposure: 'Logjam-class precomputation attacks.', remediation: 'Use ECDHE or ≥2048-bit DH groups (RFC 7919).', references: ['RFC 7919'],
    });
    if (ch && ch.ciphers.some((c) => cipherInfo(c).weak.length) && !ci.weak.length) add({
      key: 'CLIENT_WEAK_OFFER', ruleId: 'SMS-CI-003', title: 'Client offers legacy cipher suites', severity: 'low', dimension: 'cipher', session: s, confidence: 0.85,
      evidence: { frames: [ch.frame], label: 'ClientHello', detail: ch.ciphers.filter((c) => cipherInfo(c).weak.length).map((c) => cipherInfo(c).name).join(', ') },
      cause: 'Client TLS library still advertises legacy suites.', exposure: 'A permissive or impersonated server could select them.', remediation: 'Harden client TLS configuration.', references: ['RFC 9325'],
    });

    // ---------- certificates ----------
    const leaf = tls.certificates[0];
    if (leaf) {
      const cf = tls.certFrame ?? sh.frame;
      const exp = Date.parse(leaf.notAfter) / 1000;
      if (exp < captureTime) add({
        key: `CERT_EXPIRED_${leaf.fingerprint}`, ruleId: 'SMS-CE-001', title: `Expired certificate: ${leaf.subjectCN}`, severity: 'high', dimension: 'certificate', session: s, confidence: 0.99,
        evidence: { frames: [cf], label: 'Certificate', detail: `notAfter ${leaf.notAfter.slice(0, 10)} — expired ${Math.floor((captureTime - exp) / 86400)} days before capture` },
        cause: 'Certificate lifecycle not managed.', exposure: 'Clients must ignore validation errors to connect, normalising MITM acceptance.', remediation: 'Renew via automated ACME/internal PKI and monitor expiry.', references: ['RFC 5280 §4.1.2.5'],
      });
      if ((leaf.keyAlg === 'RSA' && leaf.keyBits < 2048) || (leaf.keyAlg === 'EC' && leaf.keyBits < 256)) add({
        key: `CERT_WEAK_KEY_${leaf.fingerprint}`, ruleId: 'SMS-CE-002', title: `Weak public key: ${leaf.keyAlg}-${leaf.keyBits}`, severity: 'high', dimension: 'certificate', session: s, confidence: 0.99,
        evidence: { frames: [cf], label: 'SubjectPublicKeyInfo', detail: `${leaf.subjectCN}: ${leaf.keyAlg} ${leaf.keyBits}-bit key` },
        cause: 'Legacy key size.', exposure: 'Below NIST minimum (112-bit security); factoring feasible for well-resourced adversaries.', remediation: 'Re-issue with RSA-3072 or ECDSA P-256.', references: ['NIST SP 800-57 Pt.1', 'NIST SP 800-131A'],
      });
      if (/sha1|md5|md2/i.test(leaf.sigAlg)) add({
        key: `CERT_WEAK_SIG_${leaf.fingerprint}`, ruleId: 'SMS-CE-003', title: `Deprecated signature algorithm: ${leaf.sigAlg}`, severity: 'high', dimension: 'certificate', session: s, confidence: 0.99,
        evidence: { frames: [cf], label: 'signatureAlgorithm', detail: `${leaf.subjectCN} signed with ${leaf.sigAlg}` },
        cause: 'Certificate issued with a collision-prone hash.', exposure: 'Chosen-prefix collisions (SHAttered/Shambles) allow forged certificates.', remediation: 'Re-issue with SHA-256 or stronger.', references: ['CA/B Forum BR §7.1.3', 'RFC 9155'],
      });
      if (leaf.selfSigned) add({
        key: `CERT_SELF_SIGNED_${leaf.fingerprint}`, ruleId: 'SMS-CE-004', title: `Self-signed certificate: ${leaf.subjectCN}`, severity: 'medium', dimension: 'certificate', session: s, confidence: 0.95,
        evidence: { frames: [cf], label: 'Issuer = Subject', detail: leaf.issuer },
        cause: 'No chain to a trusted CA.', exposure: 'Clients cannot distinguish the real server from an impersonator.', remediation: 'Issue from the enterprise PKI or a public CA.', references: ['RFC 5280'],
      });
      const sni = tls.clientHello?.sni;
      if (sni) {
        const names = [leaf.subjectCN, ...leaf.san].map((n) => n.toLowerCase());
        const match = names.some((n) => n === sni.toLowerCase() || (n.startsWith('*.') && sni.toLowerCase().endsWith(n.slice(1))));
        if (!match) add({
          key: `CERT_NAME_MISMATCH_${leaf.fingerprint}_${sni}`, ruleId: 'SMS-CE-005', title: `Certificate name mismatch for ${sni}`, severity: 'medium', dimension: 'certificate', session: s, confidence: 0.9,
          evidence: { frames: [cf, tls.clientHello!.frame], label: 'SNI vs SAN', detail: `Requested ${sni}; certificate covers ${names.join(', ')}` },
          cause: 'Certificate does not list the requested hostname.', exposure: 'Hostname validation fails; users trained to click through warnings.', remediation: `Add ${sni} to the certificate SAN.`, references: ['RFC 6125'],
        });
      }
    }
  }
  return hits;
}
