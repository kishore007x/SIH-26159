import type { CipherInfo } from './types.ts';

type Row = [number, string, CipherInfo['kx'], string, string, number, CipherInfo['mode'], string];
const ROWS: Row[] = [
  [0x1301, 'TLS_AES_128_GCM_SHA256', 'TLS13', 'any', 'AES-128-GCM', 128, 'AEAD', 'AEAD'],
  [0x1302, 'TLS_AES_256_GCM_SHA384', 'TLS13', 'any', 'AES-256-GCM', 256, 'AEAD', 'AEAD'],
  [0x1303, 'TLS_CHACHA20_POLY1305_SHA256', 'TLS13', 'any', 'CHACHA20-POLY1305', 256, 'AEAD', 'AEAD'],
  [0xc02b, 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256', 'ECDHE', 'ECDSA', 'AES-128-GCM', 128, 'AEAD', 'AEAD'],
  [0xc02c, 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384', 'ECDHE', 'ECDSA', 'AES-256-GCM', 256, 'AEAD', 'AEAD'],
  [0xc02f, 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', 'ECDHE', 'RSA', 'AES-128-GCM', 128, 'AEAD', 'AEAD'],
  [0xc030, 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384', 'ECDHE', 'RSA', 'AES-256-GCM', 256, 'AEAD', 'AEAD'],
  [0xcca8, 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256', 'ECDHE', 'RSA', 'CHACHA20-POLY1305', 256, 'AEAD', 'AEAD'],
  [0xcca9, 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256', 'ECDHE', 'ECDSA', 'CHACHA20-POLY1305', 256, 'AEAD', 'AEAD'],
  [0x009e, 'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256', 'DHE', 'RSA', 'AES-128-GCM', 128, 'AEAD', 'AEAD'],
  [0x009f, 'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384', 'DHE', 'RSA', 'AES-256-GCM', 256, 'AEAD', 'AEAD'],
  [0xc013, 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA', 'ECDHE', 'RSA', 'AES-128-CBC', 128, 'CBC', 'SHA1'],
  [0xc014, 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA', 'ECDHE', 'RSA', 'AES-256-CBC', 256, 'CBC', 'SHA1'],
  [0xc009, 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA', 'ECDHE', 'ECDSA', 'AES-128-CBC', 128, 'CBC', 'SHA1'],
  [0xc00a, 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA', 'ECDHE', 'ECDSA', 'AES-256-CBC', 256, 'CBC', 'SHA1'],
  [0xc027, 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256', 'ECDHE', 'RSA', 'AES-128-CBC', 128, 'CBC', 'SHA256'],
  [0xc028, 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384', 'ECDHE', 'RSA', 'AES-256-CBC', 256, 'CBC', 'SHA384'],
  [0x0033, 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA', 'DHE', 'RSA', 'AES-128-CBC', 128, 'CBC', 'SHA1'],
  [0x0039, 'TLS_DHE_RSA_WITH_AES_256_CBC_SHA', 'DHE', 'RSA', 'AES-256-CBC', 256, 'CBC', 'SHA1'],
  [0x002f, 'TLS_RSA_WITH_AES_128_CBC_SHA', 'RSA', 'RSA', 'AES-128-CBC', 128, 'CBC', 'SHA1'],
  [0x0035, 'TLS_RSA_WITH_AES_256_CBC_SHA', 'RSA', 'RSA', 'AES-256-CBC', 256, 'CBC', 'SHA1'],
  [0x003c, 'TLS_RSA_WITH_AES_128_CBC_SHA256', 'RSA', 'RSA', 'AES-128-CBC', 128, 'CBC', 'SHA256'],
  [0x003d, 'TLS_RSA_WITH_AES_256_CBC_SHA256', 'RSA', 'RSA', 'AES-256-CBC', 256, 'CBC', 'SHA256'],
  [0x009c, 'TLS_RSA_WITH_AES_128_GCM_SHA256', 'RSA', 'RSA', 'AES-128-GCM', 128, 'AEAD', 'AEAD'],
  [0x009d, 'TLS_RSA_WITH_AES_256_GCM_SHA384', 'RSA', 'RSA', 'AES-256-GCM', 256, 'AEAD', 'AEAD'],
  [0x000a, 'TLS_RSA_WITH_3DES_EDE_CBC_SHA', 'RSA', 'RSA', '3DES-EDE-CBC', 112, 'CBC', 'SHA1'],
  [0x0016, 'TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA', 'DHE', 'RSA', '3DES-EDE-CBC', 112, 'CBC', 'SHA1'],
  [0xc012, 'TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA', 'ECDHE', 'RSA', '3DES-EDE-CBC', 112, 'CBC', 'SHA1'],
  [0x0004, 'TLS_RSA_WITH_RC4_128_MD5', 'RSA', 'RSA', 'RC4-128', 128, 'STREAM', 'MD5'],
  [0x0005, 'TLS_RSA_WITH_RC4_128_SHA', 'RSA', 'RSA', 'RC4-128', 128, 'STREAM', 'SHA1'],
  [0xc011, 'TLS_ECDHE_RSA_WITH_RC4_128_SHA', 'ECDHE', 'RSA', 'RC4-128', 128, 'STREAM', 'SHA1'],
  [0x0009, 'TLS_RSA_WITH_DES_CBC_SHA', 'RSA', 'RSA', 'DES-CBC', 56, 'CBC', 'SHA1'],
  [0x0003, 'TLS_RSA_EXPORT_WITH_RC4_40_MD5', 'RSA', 'RSA', 'RC4-40 (EXPORT)', 40, 'STREAM', 'MD5'],
  [0x0008, 'TLS_RSA_EXPORT_WITH_DES40_CBC_SHA', 'RSA', 'RSA', 'DES40 (EXPORT)', 40, 'CBC', 'SHA1'],
  [0x0001, 'TLS_RSA_WITH_NULL_MD5', 'RSA', 'RSA', 'NULL', 0, 'NULL', 'MD5'],
  [0x0002, 'TLS_RSA_WITH_NULL_SHA', 'RSA', 'RSA', 'NULL', 0, 'NULL', 'SHA1'],
  [0x003b, 'TLS_RSA_WITH_NULL_SHA256', 'RSA', 'RSA', 'NULL', 0, 'NULL', 'SHA256'],
  [0x0018, 'TLS_DH_anon_WITH_RC4_128_MD5', 'DHE', 'anon', 'RC4-128', 128, 'STREAM', 'MD5'],
  [0x0034, 'TLS_DH_anon_WITH_AES_128_CBC_SHA', 'DHE', 'anon', 'AES-128-CBC', 128, 'CBC', 'SHA1'],
];

export const CIPHERS = new Map<number, CipherInfo>(
  ROWS.map(([id, name, kx, auth, enc, bits, mode, mac]) => {
    const weak: string[] = [];
    if (mode === 'NULL') weak.push('No encryption (NULL cipher)');
    if (enc.startsWith('RC4')) weak.push('RC4 stream cipher is broken (RFC 7465)');
    if (enc.includes('3DES')) weak.push('3DES 64-bit block — SWEET32 birthday attack (CVE-2016-2183)');
    if (enc.startsWith('DES')) weak.push('Single DES — 56-bit key, trivially brute-forced');
    if (enc.includes('EXPORT')) weak.push('EXPORT-grade cipher (FREAK/Logjam class)');
    if (auth === 'anon') weak.push('Anonymous key exchange — no server authentication');
    if (mac === 'MD5') weak.push('MD5-based MAC');
    return [id, { id, name, kx, auth, enc, bits, mode, mac, weak }];
  }),
);

export function cipherInfo(id: number): CipherInfo {
  return CIPHERS.get(id) ?? {
    id, name: `UNKNOWN_0x${id.toString(16).padStart(4, '0')}`, kx: 'RSA', auth: '?', enc: '?', bits: 0, mode: 'CBC', mac: '?', weak: [],
  };
}

export const versionName = (v?: number) => ({
  0x0002: 'SSL 2.0', 0x0300: 'SSL 3.0', 0x0301: 'TLS 1.0', 0x0302: 'TLS 1.1', 0x0303: 'TLS 1.2', 0x0304: 'TLS 1.3',
} as Record<number, string>)[v ?? -1] ?? (v ? `0x${v.toString(16)}` : '—');

export const GROUPS: Record<number, string> = {
  0x0017: 'secp256r1', 0x0018: 'secp384r1', 0x0019: 'secp521r1', 0x001d: 'X25519', 0x001e: 'X448',
  0x0100: 'ffdhe2048', 0x0101: 'ffdhe3072', 0x0102: 'ffdhe4096', 0x11ec: 'X25519MLKEM768', 0x0015: 'secp224r1', 0x0013: 'secp192r1',
};
export const groupName = (g?: number) => (g === undefined ? '—' : GROUPS[g] ?? `0x${g.toString(16)}`);

export const ALERTS: Record<number, string> = {
  0: 'close_notify', 10: 'unexpected_message', 20: 'bad_record_mac', 40: 'handshake_failure', 42: 'bad_certificate',
  43: 'unsupported_certificate', 44: 'certificate_revoked', 45: 'certificate_expired', 46: 'certificate_unknown',
  47: 'illegal_parameter', 48: 'unknown_ca', 50: 'decode_error', 51: 'decrypt_error', 70: 'protocol_version',
  71: 'insufficient_security', 80: 'internal_error', 86: 'inappropriate_fallback', 90: 'user_canceled', 112: 'unrecognized_name',
};
