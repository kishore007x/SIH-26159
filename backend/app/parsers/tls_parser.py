import logging
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass, field
from collections import defaultdict

logger = logging.getLogger(__name__)


@dataclass
class TlsHandshake:
    stream_id: int
    frame_number: int
    timestamp: float
    version: Optional[str] = None
    cipher_suite: Optional[str] = None
    key_exchange: Optional[str] = None
    signature_algorithm: Optional[str] = None
    supported_groups: List[str] = field(default_factory=list)
    sni: Optional[str] = None
    handshake_type: Optional[int] = None
    is_client_hello: bool = False
    is_server_hello: bool = False
    is_certificate: bool = False
    is_finished: bool = False
    complete: bool = False


@dataclass
class TlsSession:
    stream_id: int
    handshakes: List[TlsHandshake] = field(default_factory=list)
    negotiated_version: Optional[str] = None
    negotiated_cipher: Optional[str] = None
    negotiated_key_exchange: Optional[str] = None
    negotiated_signature_alg: Optional[str] = None
    sni: Optional[str] = None
    handshake_complete: bool = False
    evidence_frames: List[int] = field(default_factory=list)
    certificate_frame: Optional[int] = None


CIPHER_SUITE_MAP = {
    0xC02F: ("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "ECDHE", "RSA", "AEAD"),
    0xC030: ("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "ECDHE", "RSA", "AEAD"),
    0xCCA9: ("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", "ECDHE", "RSA", "AEAD"),
    0xCCA8: ("TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", "ECDHE", "ECDSA", "AEAD"),
    0xC02B: ("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "ECDHE", "ECDSA", "AEAD"),
    0xC02C: ("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "ECDHE", "ECDSA", "AEAD"),
    0x1301: ("TLS_AES_128_GCM_SHA256", "ECDHE/X25519", "RSA/ECDSA", "AEAD"),
    0x1302: ("TLS_AES_256_GCM_SHA384", "ECDHE/X25519", "RSA/ECDSA", "AEAD"),
    0x1303: ("TLS_CHACHA20_POLY1305_SHA256", "ECDHE/X25519", "RSA/ECDSA", "AEAD"),
    0xC009: ("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", "ECDHE", "ECDSA", "CBC"),
    0xC00A: ("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", "ECDHE", "ECDSA", "CBC"),
    0xC013: ("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "ECDHE", "RSA", "CBC"),
    0xC014: ("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", "ECDHE", "RSA", "CBC"),
    0x0033: ("TLS_DHE_RSA_WITH_AES_128_CBC_SHA", "DHE", "RSA", "CBC"),
    0x0039: ("TLS_DHE_RSA_WITH_AES_256_CBC_SHA", "DHE", "RSA", "CBC"),
    0x0067: ("TLS_DHE_RSA_WITH_AES_128_CBC_SHA256", "DHE", "RSA", "CBC"),
    0x006B: ("TLS_DHE_RSA_WITH_AES_256_CBC_SHA256", "DHE", "RSA", "CBC"),
    0x0005: ("TLS_RSA_WITH_RC4_128_SHA", "RSA", "RSA", "RC4"),
    0x0004: ("TLS_RSA_WITH_RC4_128_MD5", "RSA", "RSA", "RC4"),
    0x000A: ("TLS_RSA_WITH_3DES_EDE_CBC_SHA", "RSA", "RSA", "3DES"),
    0x002F: ("TLS_RSA_WITH_AES_128_CBC_SHA", "RSA", "RSA", "CBC"),
    0x0035: ("TLS_RSA_WITH_AES_256_CBC_SHA", "RSA", "RSA", "CBC"),
    0x003C: ("TLS_RSA_WITH_AES_128_CBC_SHA256", "RSA", "RSA", "CBC"),
    0x003D: ("TLS_RSA_WITH_AES_256_CBC_SHA256", "RSA", "RSA", "CBC"),
    0x00FF: ("TLS_EMPTY_RENEGOTIATION_INFO_SCSV", None, None, None),
}


WEAK_CIPHER_PATTERNS = [
    "RC4", "DES", "3DES", "EXPORT", "NULL", "ANON", "MD5",
]


class TlsParser:
    def __init__(self):
        self.sessions: Dict[int, TlsSession] = {}
    
    def parse(self, stream_id: int, tls_packets: List[Dict]) -> TlsSession:
        if stream_id not in self.sessions:
            self.sessions[stream_id] = TlsSession(stream_id=stream_id)
        
        session = self.sessions[stream_id]
        
        for packet in tls_packets:
            frame_num = packet.get("frame_number")
            if frame_num:
                session.evidence_frames.append(frame_num)
            
            handshake = self._parse_handshake(packet, stream_id)
            if handshake:
                session.handshakes.append(handshake)
                self._update_session_from_handshake(session, handshake)
        
        self._finalize_session(session)
        return session
    
    def _parse_handshake(self, packet: Dict, stream_id: int) -> Optional[TlsHandshake]:
        handshake_type = packet.get("tls_handshake_type")
        if handshake_type is None:
            return None
        
        handshake_type = int(handshake_type)
        version = packet.get("tls_handshake_version") or packet.get("tls_record_version")
        cipher_suite_raw = packet.get("tls_handshake_ciphersuite")
        sni = packet.get("tls_handshake_extensions_server_name")
        
        supported_groups = []
        sg_raw = packet.get("tls_handshake_extensions_supported_group")
        if sg_raw:
            if isinstance(sg_raw, list):
                supported_groups = [str(g) for g in sg_raw]
            else:
                supported_groups = [str(sg_raw)]
        
        sig_alg_raw = packet.get("tls_handshake_extensions_signature_algorithm")
        signature_algorithm = None
        if sig_alg_raw:
            if isinstance(sig_alg_raw, list):
                signature_algorithm = str(sig_alg_raw[0])
            else:
                signature_algorithm = str(sig_alg_raw)
        
        cipher_suite = None
        key_exchange = None
        sig_alg = None
        cipher_type = None
        
        if cipher_suite_raw:
            try:
                cs_val = int(cipher_suite_raw) if isinstance(cipher_suite_raw, str) else cipher_suite_raw
                if cs_val in CIPHER_SUITE_MAP:
                    cipher_suite, key_exchange, sig_alg, cipher_type = CIPHER_SUITE_MAP[cs_val]
                else:
                    cipher_suite = f"0x{cs_val:04X}"
            except (ValueError, TypeError):
                cipher_suite = str(cipher_suite_raw)
        
        return TlsHandshake(
            stream_id=stream_id,
            frame_number=packet.get("frame_number", 0),
            timestamp=packet.get("frame_time", 0.0),
            version=version,
            cipher_suite=cipher_suite,
            key_exchange=key_exchange,
            signature_algorithm=signature_algorithm or sig_alg,
            supported_groups=supported_groups,
            sni=sni,
            handshake_type=handshake_type,
            is_client_hello=(handshake_type == 1),
            is_server_hello=(handshake_type == 2),
            is_certificate=(handshake_type == 11),
            is_finished=(handshake_type == 20),
        )
    
    def _update_session_from_handshake(self, session: TlsSession, handshake: TlsHandshake):
        if handshake.is_server_hello:
            session.negotiated_version = handshake.version
            session.negotiated_cipher = handshake.cipher_suite
            session.negotiated_key_exchange = handshake.key_exchange
            session.negotiated_signature_alg = handshake.signature_algorithm
            if handshake.sni:
                session.sni = handshake.sni
        
        if handshake.is_certificate:
            session.certificate_frame = handshake.frame_number
        
        if handshake.is_finished:
            session.handshake_complete = True
    
    def _finalize_session(self, session: TlsSession):
        if not session.negotiated_version and session.handshakes:
            for h in session.handshakes:
                if h.version:
                    session.negotiated_version = h.version
                    break
        
        if not session.negotiated_cipher and session.handshakes:
            for h in reversed(session.handshakes):
                if h.cipher_suite:
                    session.negotiated_cipher = h.cipher_suite
                    session.negotiated_key_exchange = h.key_exchange
                    session.negotiated_signature_alg = h.signature_algorithm
                    break
    
    def get_session(self, stream_id: int) -> Optional[TlsSession]:
        return self.sessions.get(stream_id)
    
    def get_all_sessions(self) -> Dict[int, TlsSession]:
        return self.sessions
    
    @staticmethod
    def is_weak_cipher(cipher_suite: Optional[str]) -> bool:
        if not cipher_suite:
            return False
        cipher_upper = cipher_suite.upper()
        return any(pattern in cipher_upper for pattern in WEAK_CIPHER_PATTERNS)
    
    @staticmethod
    def get_cipher_strength(cipher_suite: Optional[str]) -> float:
        if not cipher_suite:
            return 0.0
        
        cipher_upper = cipher_suite.upper()
        
        if any(p in cipher_upper for p in ["AES_128_GCM", "AES_256_GCM", "CHACHA20_POLY1305"]):
            return 1.0
        elif any(p in cipher_upper for p in ["AES_128_CBC", "AES_256_CBC"]):
            return 0.6
        elif "3DES" in cipher_upper or "DES" in cipher_upper:
            return 0.2
        elif "RC4" in cipher_upper:
            return 0.1
        elif "EXPORT" in cipher_upper or "NULL" in cipher_upper:
            return 0.0
        else:
            return 0.5
    
    @staticmethod
    def get_key_exchange_strength(key_exchange: Optional[str]) -> float:
        if not key_exchange:
            return 0.0
        
        kex_upper = key_exchange.upper()
        
        if any(p in kex_upper for p in ["ECDHE", "X25519", "DHE"]):
            return 1.0
        elif "ECDH" in kex_upper and "ECDHE" not in kex_upper:
            return 0.5
        elif "RSA" in kex_upper and "ECDHE" not in kex_upper and "DHE" not in kex_upper:
            return 0.2
        else:
            return 0.5
    
    @staticmethod
    def has_forward_secrecy(key_exchange: Optional[str]) -> bool:
        if not key_exchange:
            return False
        kex_upper = key_exchange.upper()
        return "ECDHE" in kex_upper or "DHE" in kex_upper or "X25519" in kex_upper
    
    @staticmethod
    def is_deprecated_version(version: Optional[str]) -> bool:
        if not version:
            return False
        return version in ["TLS 1.0", "TLS 1.1", "SSL 3.0", "SSL 2.0"]
    
    @staticmethod
    def parse_version(version_str: Optional[str]) -> Optional[str]:
        if not version_str:
            return None
        
        version_map = {
            "0x0300": "SSL 3.0",
            "0x0301": "TLS 1.0",
            "0x0302": "TLS 1.1",
            "0x0303": "TLS 1.2",
            "0x0304": "TLS 1.3",
            "768": "SSL 3.0",
            "769": "TLS 1.0",
            "770": "TLS 1.1",
            "771": "TLS 1.2",
            "772": "TLS 1.3",
        }
        
        return version_map.get(version_str, version_str)