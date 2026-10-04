// Generates realistic, Wireshark-readable email captures for the SecureMailScope demo.
// Every frame is a real Ethernet/IPv4/TCP packet with valid checksums; TLS handshakes
// carry genuine ClientHello/ServerHello/Certificate/ServerKeyExchange structures and the
// X.509 certificates produced by scripts/gen-certs.sh.
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { createHash } from 'node:crypto';

let seed = 0x5eC0de;
const rand = () => ((seed = (seed * 1103515245 + 12345) >>> 0) / 2 ** 32);
const randomBytes = (n) => {
  // deterministic pseudo-random so the captures are reproducible
  const out = Buffer.alloc(n);
  let off = 0, ctr = 0;
  while (off < n) {
    const b = createHash('sha256').update(String(seed) + ':' + ctr++).digest();
    b.copy(out, off, 0, Math.min(32, n - off));
    off += 32;
  }
  rand();
  return out;
};

const cert = (n) => readFileSync(new URL(`./certs/${n}.der`, import.meta.url));
const CERTS = {
  ca: cert('ca'), mail: cert('mail'), imap: cert('imap'), legacy: cert('legacy'),
  rogue: cert('rogue'), rogueCa: cert('rogue-ca'),
};

// ---------- low level packet builders ----------
const u16 = (v) => Buffer.from([(v >> 8) & 255, v & 255]);
const u24 = (v) => Buffer.from([(v >> 16) & 255, (v >> 8) & 255, v & 255]);
const u32 = (v) => { const b = Buffer.alloc(4); b.writeUInt32BE(v >>> 0); return b; };
const ip = (s) => Buffer.from(s.split('.').map(Number));
const csum = (buf) => {
  let s = 0;
  for (let i = 0; i < buf.length; i += 2) s += (buf[i] << 8) + (i + 1 < buf.length ? buf[i + 1] : 0);
  while (s >> 16) s = (s & 0xffff) + (s >> 16);
  return ~s & 0xffff;
};
const macFor = (addr) => Buffer.from([0x02, 0x42, ...ip(addr)]);

function frame(src, dst, sport, dport, seq, ack, flags, payload) {
  const tcp = Buffer.concat([u16(sport), u16(dport), u32(seq), u32(ack),
    Buffer.from([0x50, flags]), u16(64240), u16(0), u16(0), payload]);
  const pseudo = Buffer.concat([ip(src), ip(dst), Buffer.from([0, 6]), u16(tcp.length), tcp]);
  tcp.writeUInt16BE(csum(pseudo), 16);
  const iph = Buffer.concat([Buffer.from([0x45, 0]), u16(20 + tcp.length), u16(Math.floor(rand() * 65535)),
    u16(0x4000), Buffer.from([64, 6]), u16(0), ip(src), ip(dst)]);
  iph.writeUInt16BE(csum(iph), 10);
  return Buffer.concat([macFor(dst), macFor(src), u16(0x0800), iph, tcp]);
}

const F = { FIN: 1, SYN: 2, RST: 4, PSH: 8, ACK: 16 };

class Capture {
  constructor(t0) { this.t = t0; this.packets = []; }
  push(data, dt = 0.0004) { this.t += dt; this.packets.push({ t: this.t, data }); }
}

class Conn {
  constructor(cap, cli, cport, srv, sport) {
    Object.assign(this, { cap, cli, cport, srv, sport });
    this.cseq = Math.floor(rand() * 2 ** 31); this.sseq = Math.floor(rand() * 2 ** 31);
    const { cap: c } = this;
    c.push(frame(cli, srv, cport, sport, this.cseq, 0, F.SYN, Buffer.alloc(0)), 0.002);
    c.push(frame(srv, cli, sport, cport, this.sseq, this.cseq + 1, F.SYN | F.ACK, Buffer.alloc(0)), 0.011);
    this.cseq++; this.sseq++;
    c.push(frame(cli, srv, cport, sport, this.cseq, this.sseq, F.ACK, Buffer.alloc(0)), 0.0003);
  }
  send(fromClient, data, dt) {
    data = Buffer.isBuffer(data) ? data : Buffer.from(data, 'latin1');
    const MSS = 1448;
    for (let off = 0; off < data.length; off += MSS) {
      const seg = data.subarray(off, off + MSS);
      if (fromClient) {
        this.cap.push(frame(this.cli, this.srv, this.cport, this.sport, this.cseq, this.sseq, F.PSH | F.ACK, seg), off ? 0.0002 : dt);
        this.cseq += seg.length;
      } else {
        this.cap.push(frame(this.srv, this.cli, this.sport, this.cport, this.sseq, this.cseq, F.PSH | F.ACK, seg), off ? 0.0002 : dt);
        this.sseq += seg.length;
      }
    }
    // pure ACK from the other side
    if (fromClient) this.cap.push(frame(this.srv, this.cli, this.sport, this.cport, this.sseq, this.cseq, F.ACK, Buffer.alloc(0)), 0.0004);
    else this.cap.push(frame(this.cli, this.srv, this.cport, this.sport, this.cseq, this.sseq, F.ACK, Buffer.alloc(0)), 0.0004);
    return this;
  }
  c(data, dt = 0.004) { return this.send(true, data, dt); }
  s(data, dt = 0.012) { return this.send(false, data, dt); }
  close() {
    const c = this.cap;
    c.push(frame(this.cli, this.srv, this.cport, this.sport, this.cseq, this.sseq, F.FIN | F.ACK, Buffer.alloc(0)), 0.003);
    c.push(frame(this.srv, this.cli, this.sport, this.cport, this.sseq, this.cseq + 1, F.FIN | F.ACK, Buffer.alloc(0)), 0.002);
    c.push(frame(this.cli, this.srv, this.cport, this.sport, this.cseq + 1, this.sseq + 1, F.ACK, Buffer.alloc(0)), 0.0003);
  }
}

// ---------- TLS builders ----------
const V = { SSL3: 0x0300, TLS10: 0x0301, TLS11: 0x0302, TLS12: 0x0303, TLS13: 0x0304 };
const record = (type, ver, body) => Buffer.concat([Buffer.from([type]), u16(ver), u16(body.length), body]);
const hs = (type, body) => Buffer.concat([Buffer.from([type]), u24(body.length), body]);
const vec8 = (b) => Buffer.concat([Buffer.from([b.length]), b]);
const vec16 = (b) => Buffer.concat([u16(b.length), b]);
const ext = (type, body) => Buffer.concat([u16(type), vec16(body)]);
const list16 = (arr) => Buffer.concat(arr.map(u16));

function clientHello({ ver = V.TLS12, ciphers, sni, versions, groups = [0x001d, 0x0017, 0x0018], keyShare, fallbackScsv = false, ems = true }) {
  const exts = [];
  if (sni) { const n = Buffer.from(sni); exts.push(ext(0, vec16(Buffer.concat([Buffer.from([0]), vec16(n)])))); }
  exts.push(ext(10, vec16(list16(groups))));
  exts.push(ext(11, vec8(Buffer.from([0]))));
  exts.push(ext(13, vec16(list16([0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0601]))));
  if (ems) exts.push(ext(23, Buffer.alloc(0)));
  exts.push(ext(0xff01, Buffer.from([0])));
  if (versions) exts.push(ext(43, vec8(list16(versions))));
  if (keyShare) exts.push(ext(51, vec16(Buffer.concat([u16(keyShare), vec16(randomBytes(32))]))));
  const cs = fallbackScsv ? [...ciphers, 0x5600] : ciphers;
  const body = Buffer.concat([u16(ver), randomBytes(32), vec8(randomBytes(32)), vec16(list16(cs)), vec8(Buffer.from([0])), vec16(Buffer.concat(exts))]);
  return record(22, ver === V.TLS13 ? V.TLS12 : V.TLS10, hs(1, body));
}

function serverHello({ ver, cipher, tls13 = false, group = 0x001d }) {
  const exts = [];
  if (tls13) {
    exts.push(ext(43, u16(V.TLS13)));
    exts.push(ext(51, Buffer.concat([u16(group), vec16(randomBytes(32))])));
  } else {
    exts.push(ext(0xff01, Buffer.from([0])));
    if (ver >= V.TLS10) exts.push(ext(23, Buffer.alloc(0)));
  }
  const body = Buffer.concat([u16(tls13 ? V.TLS12 : ver), randomBytes(32), vec8(randomBytes(32)), u16(cipher), Buffer.from([0]), vec16(Buffer.concat(exts))]);
  return hs(2, body);
}
const certificateMsg = (chain) => hs(11, (() => { const l = Buffer.concat(chain.map((c) => Buffer.concat([u24(c.length), c]))); return Buffer.concat([u24(l.length), l]); })());
const ske = (curve) => hs(12, Buffer.concat([Buffer.from([3]), u16(curve), vec8(Buffer.concat([Buffer.from([4]), randomBytes(64)])), u16(0x0804), vec16(randomBytes(256))]));
const shd = () => hs(14, Buffer.alloc(0));

/** Full TLS ≤1.2 handshake + some encrypted application data. */
function tls12(conn, { ver, cipher, chain, curve, offered, sni, appRecords = 4, clientVer, fallbackScsv }) {
  conn.c(clientHello({ ver: clientVer ?? ver, ciphers: offered, sni, versions: (clientVer ?? ver) >= V.TLS12 ? [V.TLS12] : undefined, fallbackScsv }));
  const msgs = [serverHello({ ver, cipher }), certificateMsg(chain)];
  if (curve) msgs.push(ske(curve));
  msgs.push(shd());
  conn.s(record(22, ver, Buffer.concat(msgs)), 0.018);
  const cke = curve ? hs(16, vec8(Buffer.concat([Buffer.from([4]), randomBytes(64)]))) : hs(16, vec16(randomBytes(chain[0].length > 700 ? 256 : 128)));
  conn.c(Buffer.concat([record(22, ver, cke), record(20, ver, Buffer.from([1])), record(22, ver, randomBytes(40))]));
  conn.s(Buffer.concat([record(20, ver, Buffer.from([1])), record(22, ver, randomBytes(40))]), 0.006);
  appData(conn, ver, appRecords);
}

function tls13(conn, { cipher = 0x1302, sni, appRecords = 4, group = 0x001d }) {
  conn.c(clientHello({ ver: V.TLS12, ciphers: [0x1302, 0x1303, 0x1301, 0xc02c, 0xc02b, 0xc030, 0xc02f], sni, versions: [V.TLS13, V.TLS12], keyShare: group }));
  conn.s(Buffer.concat([record(22, V.TLS12, serverHello({ ver: V.TLS12, cipher, tls13: true, group })), record(20, V.TLS12, Buffer.from([1])),
    record(23, V.TLS12, randomBytes(2400)), record(23, V.TLS12, randomBytes(90))]), 0.016);
  conn.c(Buffer.concat([record(20, V.TLS12, Buffer.from([1])), record(23, V.TLS12, randomBytes(74))]));
  appData(conn, V.TLS12, appRecords);
}

function appData(conn, ver, n) {
  for (let i = 0; i < n; i++) {
    if (i % 2 === 0) conn.c(record(23, ver, randomBytes(60 + Math.floor(rand() * 900))), 0.02);
    else conn.s(record(23, ver, randomBytes(40 + Math.floor(rand() * 300))), 0.015);
  }
}

// ---------- the scenario ----------
const MAIL = '10.20.0.25', POP = '10.20.0.110';
const MODERN = [0x1302, 0x1303, 0x1301, 0xc02c, 0xc02b, 0xc030, 0xc02f, 0xcca9, 0xcca8];
const T12_OFFER = [0xc02c, 0xc030, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0x009f, 0x009e];
const LEGACY_OFFER = [0x0005, 0x0004, 0x000a, 0x002f, 0x0035, 0xc013, 0xc014];
const ehlo = (starttls = true, host = 'mail.acme-corp.in') =>
  `250-${host} Hello\r\n250-SIZE 52428800\r\n250-8BITMIME\r\n250-PIPELINING\r\n${starttls ? '250-STARTTLS\r\n' : ''}250-AUTH PLAIN LOGIN\r\n250 SMTPUTF8\r\n`;
const ehloPostTls = `250-mail.acme-corp.in Hello\r\n250-SIZE 52428800\r\n250-AUTH PLAIN LOGIN\r\n250 SMTPUTF8\r\n`;

function smtpStarttls13(cap, cli, cport, sport = 587, name = 'ws') {
  const k = new Conn(cap, cli, cport, MAIL, sport);
  k.s('220 mail.acme-corp.in ESMTP Postfix (Acme Mail Gateway)\r\n', 0.03);
  k.c(`EHLO ${name}.acme-corp.in\r\n`).s(ehlo());
  k.c('STARTTLS\r\n').s('220 2.0.0 Ready to start TLS\r\n');
  tls13(k, { sni: 'smtp.acme-corp.in', appRecords: 6 });
  k.close();
}

function buildIncident() {
  const cap = new Capture(Date.UTC(2026, 8, 28, 9, 0, 0) / 1000);
  // Baseline: healthy submissions over TLS 1.3
  smtpStarttls13(cap, '10.10.1.11', 51012, 587, 'ws-finance-01');
  cap.t += 12.3;
  smtpStarttls13(cap, '10.10.1.12', 51877, 587, 'ws-hr-04');
  cap.t += 7.9;

  // IMAP STARTTLS with TLS1.2 ECDHE + full chain (visible certificate)
  { const k = new Conn(cap, '10.10.1.15', 49233, MAIL, 143);
    k.s('* OK [CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE STARTTLS LOGINDISABLED] Dovecot ready.\r\n', 0.02);
    k.c('a1 CAPABILITY\r\n').s('* CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE STARTTLS LOGINDISABLED\r\na1 OK Pre-login capabilities listed, post-login capabilities have more.\r\n');
    k.c('a2 STARTTLS\r\n').s('a2 OK Begin TLS negotiation now.\r\n');
    tls12(k, { ver: V.TLS12, cipher: 0xc030, chain: [CERTS.mail, CERTS.ca], curve: 0x001d, offered: T12_OFFER, sni: 'imap.acme-corp.in', appRecords: 8 });
    k.close(); }
  cap.t += 4.2;

  // IMAPS 993, ECDSA cert
  { const k = new Conn(cap, '10.10.1.16', 50111, MAIL, 993);
    tls12(k, { ver: V.TLS12, cipher: 0xc02c, chain: [CERTS.imap, CERTS.ca], curve: 0x0017, offered: T12_OFFER, sni: 'imap.acme-corp.in', appRecords: 10 });
    k.close(); }
  cap.t += 6.1;

  // Inbound relay from partner MTA on 25
  { const k = new Conn(cap, '203.0.113.45', 38821, MAIL, 25);
    k.s('220 mail.acme-corp.in ESMTP Postfix (Acme Mail Gateway)\r\n', 0.03);
    k.c('EHLO mx1.partner-bank.co.in\r\n').s(ehlo());
    k.c('STARTTLS\r\n').s('220 2.0.0 Ready to start TLS\r\n');
    tls12(k, { ver: V.TLS12, cipher: 0xc030, chain: [CERTS.mail, CERTS.ca], curve: 0x0017, offered: T12_OFFER, sni: 'mail.acme-corp.in', appRecords: 6 });
    k.close(); }
  cap.t += 9.4;
  smtpStarttls13(cap, '10.10.1.21', 52300, 587, 'ws-legal-02');
  cap.t += 3.3;

  // Downgrade: TLS 1.3 attempt aborted, client retries with TLS 1.0 / RC4 and no FALLBACK_SCSV
  { const k = new Conn(cap, '10.10.1.33', 53001, MAIL, 587);
    k.s('220 mail.acme-corp.in ESMTP Postfix (Acme Mail Gateway)\r\n', 0.03);
    k.c('EHLO ws-ops-07.acme-corp.in\r\n').s(ehlo());
    k.c('STARTTLS\r\n').s('220 2.0.0 Ready to start TLS\r\n');
    k.c(clientHello({ ver: V.TLS12, ciphers: MODERN, sni: 'smtp.acme-corp.in', versions: [V.TLS13, V.TLS12], keyShare: 0x001d }));
    // injected handshake_failure alert (in-path middlebox)
    k.s(record(21, V.TLS12, Buffer.from([2, 40])), 0.004);
    cap.push(frame(MAIL, '10.10.1.33', 587, 53001, k.sseq, k.cseq, F.RST | F.ACK, Buffer.alloc(0)), 0.001); }
  cap.t += 0.4;
  { const k = new Conn(cap, '10.10.1.33', 53002, MAIL, 587);
    k.s('220 mail.acme-corp.in ESMTP Postfix (Acme Mail Gateway)\r\n', 0.03);
    k.c('EHLO ws-ops-07.acme-corp.in\r\n').s(ehlo());
    k.c('STARTTLS\r\n').s('220 2.0.0 Ready to start TLS\r\n');
    tls12(k, { ver: V.TLS10, clientVer: V.TLS10, cipher: 0x0005, chain: [CERTS.mail, CERTS.ca], offered: LEGACY_OFFER, sni: 'smtp.acme-corp.in', appRecords: 6 });
    k.close(); }
  cap.t += 11.0;

  // STARTTLS stripping: capability removed from EHLO, client authenticates in clear
  { const k = new Conn(cap, '10.10.1.40', 54410, MAIL, 587);
    k.s('220 mail.acme-corp.in ESMTP Postfix (Acme Mail Gateway)\r\n', 0.03);
    k.c('EHLO ws-exec-01.acme-corp.in\r\n').s(ehlo().replace('250-STARTTLS', '250-XXXXXXXA'));
    k.c('AUTH LOGIN\r\n').s('334 VXNlcm5hbWU6\r\n');
    k.c(Buffer.from('cmeena@acme-corp.in').toString('base64') + '\r\n').s('334 UGFzc3dvcmQ6\r\n');
    k.c(Buffer.from('Monsoon@2026!').toString('base64') + '\r\n').s('235 2.7.0 Authentication successful\r\n');
    k.c('MAIL FROM:<cmeena@acme-corp.in>\r\n').s('250 2.1.0 Ok\r\n');
    k.c('RCPT TO:<board@acme-corp.in>\r\n').s('250 2.1.5 Ok\r\n');
    k.c('DATA\r\n').s('354 End data with <CR><LF>.<CR><LF>\r\n');
    k.c('From: C. Meena <cmeena@acme-corp.in>\r\nTo: board@acme-corp.in\r\nSubject: Q3 acquisition term sheet - CONFIDENTIAL\r\n\r\nPlease find the revised valuation attached.\r\n.\r\n').s('250 2.0.0 Ok: queued as 4QX9K2\r\n');
    k.c('QUIT\r\n').s('221 2.0.0 Bye\r\n');
    k.close(); }
  cap.t += 5.5;

  // IMAP STARTTLS answered by an interception certificate (same CN, foreign issuer)
  { const k = new Conn(cap, '10.10.1.52', 49870, MAIL, 143);
    k.s('* OK [CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE STARTTLS LOGINDISABLED] Dovecot ready.\r\n', 0.02);
    k.c('a1 STARTTLS\r\n').s('a1 OK Begin TLS negotiation now.\r\n');
    tls12(k, { ver: V.TLS12, cipher: 0xc02f, chain: [CERTS.rogue, CERTS.rogueCa], curve: 0x0017, offered: T12_OFFER, sni: 'imap.acme-corp.in', appRecords: 8 });
    k.close(); }
  cap.t += 8.8;

  // POP3 cleartext: STLS advertised but never used
  { const k = new Conn(cap, '10.10.1.61', 50500, POP, 110);
    k.s('+OK Acme Legacy POP3 server ready <1896.697170952@pop.legacy.acme-corp.in>\r\n', 0.02);
    k.c('CAPA\r\n').s('+OK Capability list follows\r\nTOP\r\nUSER\r\nUIDL\r\nSTLS\r\nSASL PLAIN\r\n.\r\n');
    k.c('USER rkumar\r\n').s('+OK\r\n');
    k.c('PASS Welcome123\r\n').s('+OK Logged in.\r\n');
    k.c('STAT\r\n').s('+OK 3 18234\r\n');
    k.c('RETR 1\r\n').s('+OK 6080 octets\r\nFrom: payroll@acme-corp.in\r\nSubject: Salary revision letter - Sept 2026\r\n\r\nDear Rakesh, your revised CTC is attached.\r\n.\r\n');
    k.c('QUIT\r\n').s('+OK Logging out.\r\n');
    k.close(); }
  cap.t += 2.7;

  // POP3S 995 with legacy server: TLS1.0 / 3DES / expired RSA-1024 SHA-1 self-signed cert
  { const k = new Conn(cap, '10.10.1.61', 50512, POP, 995);
    tls12(k, { ver: V.TLS10, clientVer: V.TLS12, cipher: 0x000a, chain: [CERTS.legacy], offered: [...T12_OFFER, 0x000a, 0x002f], sni: 'pop.legacy.acme-corp.in', appRecords: 6 });
    k.close(); }
  cap.t += 6.6;

  // SMTPS 465 — static RSA key exchange, CBC
  { const k = new Conn(cap, '10.10.1.72', 55021, MAIL, 465);
    tls12(k, { ver: V.TLS12, cipher: 0x002f, chain: [CERTS.mail, CERTS.ca], offered: [0x002f, 0x0035, 0x003c, 0xc02f], sni: 'smtp.acme-corp.in', appRecords: 6 });
    k.close(); }
  cap.t += 4.4;

  // STARTTLS command injection: plaintext command pipelined after STARTTLS
  { const k = new Conn(cap, '198.51.100.77', 41188, MAIL, 25);
    k.s('220 mail.acme-corp.in ESMTP Postfix (Acme Mail Gateway)\r\n', 0.03);
    k.c('EHLO relay.unknown-sender.net\r\n').s(ehlo());
    k.c('STARTTLS\r\nRSET\r\nMAIL FROM:<ceo@acme-corp.in>\r\n').s('220 2.0.0 Ready to start TLS\r\n');
    tls12(k, { ver: V.TLS12, cipher: 0xc030, chain: [CERTS.mail, CERTS.ca], curve: 0x0017, offered: T12_OFFER, sni: 'mail.acme-corp.in', appRecords: 4 });
    k.close(); }
  cap.t += 3.9;

  // TLS unavailable → plaintext fallback with message body exposed
  { const k = new Conn(cap, '203.0.113.90', 40222, MAIL, 25);
    k.s('220 mail.acme-corp.in ESMTP Postfix (Acme Mail Gateway)\r\n', 0.03);
    k.c('EHLO mx2.vendor-logistics.in\r\n').s(ehlo());
    k.c('STARTTLS\r\n').s('454 4.7.0 TLS not available due to local problem\r\n');
    k.c('MAIL FROM:<invoices@vendor-logistics.in>\r\n').s('250 2.1.0 Ok\r\n');
    k.c('RCPT TO:<ap@acme-corp.in>\r\n').s('250 2.1.5 Ok\r\n');
    k.c('DATA\r\n').s('354 End data with <CR><LF>.<CR><LF>\r\n');
    k.c('From: invoices@vendor-logistics.in\r\nTo: ap@acme-corp.in\r\nSubject: Updated bank details for invoice #INV-88213\r\n\r\nPlease remit to the new account below.\r\n.\r\n').s('250 2.0.0 Ok: queued as 7HBQ1Z\r\n');
    k.c('QUIT\r\n').s('221 2.0.0 Bye\r\n');
    k.close(); }
  cap.t += 5.2;
  smtpStarttls13(cap, '10.10.1.12', 51990, 587, 'ws-hr-04');
  cap.t += 6.0;
  smtpStarttls13(cap, '10.10.1.80', 56001, 587, 'ws-eng-12');
  return cap;
}

function buildHardened() {
  const cap = new Capture(Date.UTC(2026, 9, 2, 14, 30, 0) / 1000);
  const clients = ['10.10.1.11', '10.10.1.12', '10.10.1.21', '10.10.1.33', '10.10.1.40', '10.10.1.80'];
  clients.forEach((c, i) => { smtpStarttls13(cap, c, 51000 + i * 37, 587, `ws-${i}`); cap.t += 3 + i; });
  { const k = new Conn(cap, '10.10.1.15', 49233, MAIL, 993);
    tls13(k, { sni: 'imap.acme-corp.in', appRecords: 8 }); k.close(); }
  cap.t += 2;
  { const k = new Conn(cap, '203.0.113.45', 38821, MAIL, 25);
    k.s('220 mail.acme-corp.in ESMTP Postfix (Acme Mail Gateway)\r\n', 0.03);
    k.c('EHLO mx1.partner-bank.co.in\r\n').s(ehlo());
    k.c('STARTTLS\r\n').s('220 2.0.0 Ready to start TLS\r\n');
    tls12(k, { ver: V.TLS12, cipher: 0xc030, chain: [CERTS.mail, CERTS.ca], curve: 0x001d, offered: T12_OFFER, sni: 'mail.acme-corp.in', appRecords: 6 });
    k.close(); }
  cap.t += 2;
  { const k = new Conn(cap, '10.10.1.61', 50512, MAIL, 995);
    tls13(k, { sni: 'pop.acme-corp.in', appRecords: 6 }); k.close(); }
  return cap;
}

// ---------- writers ----------
function writePcap(cap) {
  const parts = [Buffer.from('d4c3b2a1020004000000000000000000ffff000001000000', 'hex')];
  for (const p of cap.packets) {
    const h = Buffer.alloc(16);
    const sec = Math.floor(p.t), us = Math.round((p.t - sec) * 1e6);
    h.writeUInt32LE(sec, 0); h.writeUInt32LE(us, 4); h.writeUInt32LE(p.data.length, 8); h.writeUInt32LE(p.data.length, 12);
    parts.push(h, p.data);
  }
  return Buffer.concat(parts);
}

function writePcapng(cap) {
  const block = (type, body) => {
    const pad = (4 - (body.length % 4)) % 4;
    const len = 12 + body.length + pad;
    const b = Buffer.alloc(len);
    b.writeUInt32LE(type, 0); b.writeUInt32LE(len, 4); body.copy(b, 8); b.writeUInt32LE(len, len - 4);
    return b;
  };
  const shb = Buffer.alloc(16); shb.writeUInt32LE(0x1a2b3c4d, 0); shb.writeUInt16LE(1, 4); shb.writeUInt16LE(0, 6); shb.writeInt32LE(-1, 8); shb.writeInt32LE(-1, 12);
  const idb = Buffer.alloc(8); idb.writeUInt16LE(1, 0); idb.writeUInt32LE(65535, 4);
  const parts = [block(0x0a0d0d0a, shb), block(1, idb)];
  for (const p of cap.packets) {
    const ts = BigInt(Math.round(p.t * 1e6));
    const h = Buffer.alloc(20);
    h.writeUInt32LE(0, 0); h.writeUInt32LE(Number(ts >> 32n), 4); h.writeUInt32LE(Number(ts & 0xffffffffn), 8);
    h.writeUInt32LE(p.data.length, 12); h.writeUInt32LE(p.data.length, 16);
    parts.push(block(6, Buffer.concat([h, p.data])));
  }
  return Buffer.concat(parts);
}

mkdirSync(new URL('../public/samples/', import.meta.url), { recursive: true });
const inc = buildIncident();
writeFileSync(new URL('../public/samples/acme-mail-incident.pcap', import.meta.url), writePcap(inc));
const hard = buildHardened();
writeFileSync(new URL('../public/samples/acme-mail-hardened.pcapng', import.meta.url), writePcapng(hard));
console.log(`incident: ${inc.packets.length} frames, hardened: ${hard.packets.length} frames`);
