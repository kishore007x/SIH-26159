import type { Chunk, EmailProtocol, EmailSession, TcpStream, TranscriptLine } from './types.ts';
import { EMAIL_PORTS, frameAt } from './streams.ts';
import { looksLikeTls, parseTls } from './tls.ts';

const dec = new TextDecoder('latin1');

function detectProtocol(st: TcpStream): EmailProtocol {
  const p = EMAIL_PORTS[st.sport];
  if (p) return p.proto;
  const first = st.chunks.find((c) => c.dir === 's2c');
  if (!first) return 'UNKNOWN';
  const t = dec.decode(first.data.subarray(0, 64));
  if (/^220[ -].*(SMTP|ESMTP|mail)/i.test(t)) return 'SMTP';
  if (/^\* OK/.test(t)) return 'IMAP';
  if (/^\+OK/.test(t)) return 'POP3';
  return 'UNKNOWN';
}

export function isEmailStream(st: TcpStream): boolean {
  return detectProtocol(st) !== 'UNKNOWN';
}

function sliceChunk(c: Chunk, from: number): Chunk {
  return {
    ...c,
    data: c.data.subarray(from),
    frameOffsets: c.frameOffsets.filter((f, i, a) => (a[i + 1]?.offset ?? Infinity) > from)
      .map((f) => ({ frame: f.frame, offset: Math.max(0, f.offset - from) })),
    frames: c.frames,
  };
}

const b64 = (s: string) => { try { return atob(s.trim()); } catch { return undefined; } };
const mask = (s: string) => (s.length <= 2 ? '••' : `${s[0]}${'•'.repeat(Math.min(10, s.length - 2))}${s[s.length - 1]}`);

/** Reconstructs the application-layer email session and its STARTTLS / TLS state. */
export function buildSession(st: TcpStream, index: number): EmailSession {
  const protocol = detectProtocol(st);
  const implicit = EMAIL_PORTS[st.sport]?.implicitTls ?? false;
  const s: EmailSession = {
    id: `S${String(index + 1).padStart(2, '0')}`, index, stream: st, protocol,
    mode: 'PLAINTEXT', capabilities: [], starttlsAdvertised: false, starttlsAccepted: false,
    plaintextAuth: [], plaintextMail: [], transcript: [], aborted: st.sawRst,
  };

  // Implicit TLS (465/993/995) or TLS from the first byte
  const firstClient = st.chunks.find((c) => c.dir === 'c2s');
  if (implicit || (firstClient && st.chunks[0]?.dir === 'c2s' && looksLikeTls(firstClient.data))) {
    s.mode = 'IMPLICIT_TLS';
    s.tls = parseTls(st.chunks);
    s.serverName = s.tls.clientHello?.sni;
    return s;
  }

  let tlsStart: { chunk: number; offset: number } | null = null;
  let pendingStarttls = false;
  let pendingAuth: string | null = null;
  let authStep = 0;
  let inData = false;
  let dataBuf: { text: string; frame: number }[] = [];
  let pop3User: string | undefined;
  let ehloResp = false;
  let ehloFirst = false;

  outer: for (let ci = 0; ci < st.chunks.length; ci++) {
    const c = st.chunks[ci];
    if (pendingStarttls && s.starttlsAccepted && looksLikeTls(c.data)) { tlsStart = { chunk: ci, offset: 0 }; break; }
    const text = dec.decode(c.data);
    let pos = 0;
    const lines = text.split('\n');
    for (let li = 0; li < lines.length; li++) {
      const raw = lines[li];
      if (li === lines.length - 1 && raw === '') break;
      const line = raw.replace(/\r$/, '');
      const frame = frameAt(c, pos);
      const lineStart = pos;
      pos += raw.length + 1;
      const tl: TranscriptLine = { dir: c.dir, text: line, frame, ts: c.ts };

      if (c.dir === 's2c') {
        if (!s.banner && s.transcript.length === 0) s.banner = line;
        if (protocol === 'SMTP') {
          const m = /^250[ -](.*)$/.exec(line);
          if (m && ehloResp) {
            const cap = m[1].trim().toUpperCase();
            if (line[3] === ' ') ehloResp = false;
            if (ehloFirst) { s.serverName = m[1].split(' ')[0]; ehloFirst = false; }
            else s.capabilities.push(cap);
            if (cap === 'STARTTLS') { s.starttlsAdvertised = true; tl.tag = 'cap'; }
            if (/^X{4,}A$/.test(cap)) { s.strippingSignature = { frame, text: line }; tl.tag = 'error'; }
          }
          if (pendingStarttls && /^220[ -]/.test(line)) { s.starttlsAccepted = true; tl.tag = 'starttls'; }
          if (pendingStarttls && /^(454|501|502|503)[ -]/.test(line)) { s.starttlsRefused = { frame, text: line }; pendingStarttls = false; tl.tag = 'error'; }
          if (pendingAuth && /^334 /.test(line)) authStep++;
        } else if (protocol === 'IMAP') {
          const caps = /CAPABILITY ([^\]\r\n]*)/i.exec(line);
          if (caps) {
            const list = caps[1].trim().toUpperCase().split(/\s+/);
            for (const x of list) if (!s.capabilities.includes(x)) s.capabilities.push(x);
            if (list.includes('STARTTLS')) { s.starttlsAdvertised = true; tl.tag = 'cap'; }
          }
          if (pendingStarttls && /^\S+ OK/i.test(line)) { s.starttlsAccepted = true; tl.tag = 'starttls'; }
          if (pendingStarttls && /^\S+ (NO|BAD)/i.test(line)) { s.starttlsRefused = { frame, text: line }; pendingStarttls = false; tl.tag = 'error'; }
        } else if (protocol === 'POP3') {
          if (/^STLS$/i.test(line)) { s.starttlsAdvertised = true; s.capabilities.push('STLS'); tl.tag = 'cap'; }
          else if (s.transcript.some((t) => /^CAPA/i.test(t.text)) && /^[A-Z][A-Z0-9-]*( .*)?$/.test(line) && !line.startsWith('+OK')) s.capabilities.push(line.toUpperCase());
          if (pendingStarttls && /^\+OK/.test(line)) { s.starttlsAccepted = true; tl.tag = 'starttls'; }
          if (pendingStarttls && /^-ERR/.test(line)) { s.starttlsRefused = { frame, text: line }; pendingStarttls = false; tl.tag = 'error'; }
        }
        s.transcript.push(tl);
        if (s.starttlsAccepted) {
          // anything left in this server chunk after the acceptance line is already TLS
          const rest = lineStart + raw.length + 1;
          if (rest < c.data.length && looksLikeTls(c.data.subarray(rest))) { tlsStart = { chunk: ci, offset: rest }; break outer; }
          pendingStarttls = true;
        }
        continue;
      }

      // client → server
      if (inData) {
        if (line === '.') { inData = false; tl.tag = 'data'; }
        else {
          dataBuf.push({ text: line, frame });
          tl.tag = 'data';
          if (line.startsWith('Subject:') || line.startsWith('From:') || line.startsWith('To:')) {
            const cur = s.plaintextMail[s.plaintextMail.length - 1];
            if (cur) {
              if (line.startsWith('Subject:')) cur.subject = line.slice(8).trim();
              if (line.startsWith('From:')) cur.from = line.slice(5).trim();
              if (line.startsWith('To:')) cur.to = line.slice(3).trim();
            }
          }
        }
        s.transcript.push(tl);
        continue;
      }
      const up = line.toUpperCase();
      if (protocol === 'SMTP' && /^(EHLO|HELO) /.test(up)) { ehloResp = true; ehloFirst = true; }
      if ((protocol === 'SMTP' && up === 'STARTTLS') || (protocol === 'IMAP' && /^\S+ STARTTLS$/.test(up)) || (protocol === 'POP3' && up === 'STLS')) {
        pendingStarttls = true;
        s.starttlsCommandFrame = frame;
        tl.tag = 'starttls';
        // bytes pipelined in the same segment after STARTTLS → command injection (CVE-2011-0411 class)
        const after = text.slice(lineStart + raw.length + 1).trim();
        if (after.length) {
          s.injectedAfterStarttls = { frame, text: after.replace(/\r?\n/g, ' ⏎ ') };
          s.transcript.push(tl);
          for (const inj of after.split(/\r?\n/)) s.transcript.push({ dir: 'c2s', text: inj, frame, ts: c.ts, tag: 'inject' });
          continue outer;
        }
      } else if (pendingAuth && authStep > 0) {
        const decoded = b64(line);
        if (authStep === 1 && pendingAuth === 'LOGIN') {
          s.plaintextAuth.push({ frame, method: 'AUTH LOGIN', user: decoded });
          tl.redacted = `${line}   ⟶ base64("${decoded}")`;
        } else {
          const last = s.plaintextAuth[s.plaintextAuth.length - 1];
          if (last && decoded) last.secretMasked = mask(decoded);
          tl.redacted = `${'•'.repeat(Math.min(line.length, 18))}   ⟶ password ${decoded ? mask(decoded) : ''}`;
          pendingAuth = null; authStep = 0;
        }
        tl.tag = 'cred';
      } else if (protocol === 'SMTP' && /^AUTH (LOGIN|PLAIN)/.test(up)) {
        tl.tag = 'auth';
        if (up.startsWith('AUTH PLAIN ') && line.length > 11) {
          const d = b64(line.slice(11)) ?? '';
          const [, u, p] = d.split('\0');
          s.plaintextAuth.push({ frame, method: 'AUTH PLAIN', user: u, secretMasked: p ? mask(p) : undefined });
          tl.redacted = `AUTH PLAIN ${'•'.repeat(16)}   ⟶ ${u} / ${p ? mask(p) : ''}`;
          tl.tag = 'cred';
        } else { pendingAuth = up.includes('LOGIN') ? 'LOGIN' : 'PLAIN'; authStep = 0; }
      } else if (protocol === 'SMTP' && up === 'DATA') {
        inData = true; dataBuf = []; tl.tag = 'data';
      } else if (protocol === 'SMTP' && up.startsWith('MAIL FROM:')) {
        s.plaintextMail.push({ frame, from: line.slice(10).trim() });
        tl.tag = 'data';
      } else if (protocol === 'SMTP' && up.startsWith('RCPT TO:')) {
        const cur = s.plaintextMail[s.plaintextMail.length - 1];
        if (cur && !cur.to) cur.to = line.slice(8).trim();
        tl.tag = 'data';
      } else if (protocol === 'POP3' && up.startsWith('USER ')) {
        pop3User = line.slice(5); tl.tag = 'auth';
      } else if (protocol === 'POP3' && up.startsWith('PASS ')) {
        const pw = line.slice(5);
        s.plaintextAuth.push({ frame, method: 'POP3 USER/PASS', user: pop3User, secretMasked: mask(pw) });
        tl.redacted = `PASS ${mask(pw)}`; tl.tag = 'cred';
      } else if (protocol === 'POP3' && up.startsWith('RETR ')) {
        s.plaintextMail.push({ frame }); tl.tag = 'data';
      } else if (protocol === 'IMAP' && /^\S+ (LOGIN|AUTHENTICATE)\b/.test(up)) {
        const m = /^\S+ LOGIN (\S+) (\S+)/i.exec(line);
        s.plaintextAuth.push({ frame, method: 'IMAP LOGIN', user: m?.[1]?.replace(/"/g, ''), secretMasked: m?.[2] ? mask(m[2].replace(/"/g, '')) : undefined });
        tl.redacted = m ? `${line.split(' ')[0]} LOGIN ${m[1]} ${mask(m[2])}` : undefined;
        tl.tag = 'cred';
      }
      s.transcript.push(tl);
    }
  }

  // POP3: lines retrieved by RETR carry the mail headers on the server side
  if (protocol === 'POP3') {
    let cur = -1;
    s.transcript.forEach((t) => {
      if (t.dir === 'c2s' && /^RETR /i.test(t.text)) cur++;
      if (cur >= 0 && t.dir === 's2c' && s.plaintextMail[cur]) {
        if (t.text.startsWith('Subject:')) s.plaintextMail[cur].subject = t.text.slice(8).trim();
        if (t.text.startsWith('From:')) s.plaintextMail[cur].from = t.text.slice(5).trim();
        if (t.text.startsWith('Subject:') || t.text.startsWith('From:')) t.tag = 'data';
      }
    });
  }

  if (tlsStart) {
    s.mode = 'STARTTLS';
    const rest = [sliceChunk(st.chunks[tlsStart.chunk], tlsStart.offset), ...st.chunks.slice(tlsStart.chunk + 1)];
    s.tls = parseTls(rest);
    s.serverName = s.tls.clientHello?.sni ?? s.serverName;
  }
  return s;
}
