export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type EmailProtocol = 'SMTP' | 'IMAP' | 'POP3' | 'UNKNOWN';
export type Dimension =
  | 'protocol' | 'tls' | 'cipher' | 'keyExchange' | 'certificate' | 'starttls' | 'anomaly';

export interface RawPacket {
  frame: number;          // 1-based frame number (Wireshark compatible)
  ts: number;             // epoch seconds (float)
  linkType: number;
  data: Uint8Array;
}

export interface CaptureInfo {
  format: 'pcap' | 'pcapng';
  linkTypes: number[];
  packetCount: number;
  bytes: number;
  start: number;
  end: number;
}

export interface TcpSegment {
  frame: number;
  ts: number;
  src: string; dst: string;
  sport: number; dport: number;
  seq: number; ack: number;
  flags: number;
  payload: Uint8Array;
}

export interface Chunk {
  dir: 'c2s' | 's2c';
  data: Uint8Array;
  frames: number[];       // frames contributing to this chunk
  frameOffsets: { frame: number; offset: number }[]; // offset in chunk where frame data starts
  ts: number;
}

export interface TcpStream {
  id: number;
  client: string; cport: number;
  server: string; sport: number;
  start: number; end: number;
  frames: number[];
  chunks: Chunk[];
  bytes: { c2s: number; s2c: number };
  sawSyn: boolean; sawFin: boolean; sawRst: boolean;
  rstFrom?: 'client' | 'server';
}

export interface TranscriptLine {
  dir: 'c2s' | 's2c';
  text: string;
  frame: number;
  ts: number;
  redacted?: string;
  tag?: 'starttls' | 'auth' | 'data' | 'cap' | 'error' | 'cred' | 'inject';
}

export interface CipherInfo {
  id: number;
  name: string;
  kx: 'RSA' | 'ECDHE' | 'DHE' | 'TLS13' | 'PSK' | 'NULL';
  auth: string;
  enc: string;
  bits: number;
  mode: 'AEAD' | 'CBC' | 'STREAM' | 'NULL';
  mac: string;
  weak: string[];   // reasons
}

export interface CertInfo {
  subjectCN: string;
  subject: string;
  issuerCN: string;
  issuer: string;
  serial: string;
  notBefore: string;
  notAfter: string;
  sigAlg: string;
  keyAlg: string;
  keyBits: number;
  curve?: string;
  san: string[];
  isCA: boolean;
  selfSigned: boolean;
  fingerprint: string;   // sha-256 hex
  der: Uint8Array;
}

export interface ClientHelloInfo {
  frame: number;
  legacyVersion: number;
  versions: number[];
  ciphers: number[];
  sni?: string;
  groups: number[];
  keyShareGroups: number[];
  fallbackScsv: boolean;
  ems: boolean;
}

export interface ServerHelloInfo {
  frame: number;
  legacyVersion: number;
  version: number;     // effective
  cipher: number;
  keyShareGroup?: number;
}

export interface TlsInfo {
  startFrame: number;
  clientHello?: ClientHelloInfo;
  serverHello?: ServerHelloInfo;
  certificates: CertInfo[];
  certFrame?: number;
  kxGroup?: number;
  kxFrame?: number;
  dhBits?: number;
  alerts: { frame: number; level: number; desc: number; dir: 'c2s' | 's2c' }[];
  appRecords: number;
  appBytes: number;
  handshakeComplete: boolean;
  events: { frame: number; dir: 'c2s' | 's2c'; label: string; detail?: string; encrypted?: boolean }[];
}

export interface EmailSession {
  id: string;
  index: number;
  stream: TcpStream;
  protocol: EmailProtocol;
  mode: 'STARTTLS' | 'IMPLICIT_TLS' | 'PLAINTEXT';
  serverName?: string;
  banner?: string;
  capabilities: string[];
  starttlsAdvertised: boolean;
  starttlsCommandFrame?: number;
  starttlsAccepted: boolean;
  starttlsRefused?: { frame: number; text: string };
  strippingSignature?: { frame: number; text: string };
  injectedAfterStarttls?: { frame: number; text: string };
  plaintextAuth: { frame: number; method: string; user?: string; secretMasked?: string }[];
  plaintextMail: { frame: number; subject?: string; from?: string; to?: string }[];
  transcript: TranscriptLine[];
  tls?: TlsInfo;
  aborted: boolean;
}

export interface Evidence {
  session: string;
  frames: number[];
  label: string;
  detail: string;
}

export interface Finding {
  id: string;
  ruleId: string;
  title: string;
  severity: Severity;
  dimension: Dimension;
  sessions: string[];
  evidence: Evidence[];
  cause: string;
  exposure: string;
  remediation: string;
  references: string[];
  confidence: number;     // 0..1
  source: 'rule' | 'ml' | 'drift';
  mlScore?: number;       // classifier probability of high-impact
  priority?: number;      // 1 = fix first
}

export interface SessionFeatures {
  session: string;
  vector: number[];
  names: string[];
}

export interface MlSession {
  session: string;
  anomaly: number;               // isolation forest score 0..1
  riskClass: Severity;
  probs: Record<'critical' | 'high' | 'medium' | 'low', number>;
  contributions: { feature: string; value: number; weight: number }[];
  deviations: { field: string; observed: string; baseline: string }[];
}

export interface Posture {
  overall: number;
  grade: string;
  label: string;
  dimensions: Record<Dimension, number>;
  confidence: number;
}

export interface Analysis {
  fileName: string;
  fileSize: number;
  capture: CaptureInfo;
  streams: number;
  sessions: EmailSession[];
  findings: Finding[];
  ml: MlSession[];
  posture: Posture;
  baselines: Baseline[];
  timings: { stage: string; ms: number }[];
  analyzedAt: string;
  rawPackets: RawPacket[];
}

export interface Baseline {
  service: string;              // server:port/proto
  sessions: string[];
  fields: Record<string, { value: string; count: number }[]>;
}
