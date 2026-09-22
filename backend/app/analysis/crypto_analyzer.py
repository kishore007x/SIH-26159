import logging
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime

from backend.app.parsers.tls_parser import TlsParser
from backend.app.parsers.certificate_parser import CertificateParser
from backend.app.parsers.smtp_parser import SmtpParser, SmtpSession, SmtpState
from backend.app.parsers.imap_parser import ImapParser, ImapSession, ImapState
from backend.app.parsers.pop3_parser import Pop3Parser, Pop3Session, Pop3State
from backend.app.parsers.protocol_detector import ProtocolDetector, DetectedProtocol, EmailPort
from backend.app.models.schemas import (
    ProtocolType, TLSVersion, FindingSeverity, FindingCategory
)

logger = logging.getLogger(__name__)


@dataclass
class SessionAnalysis:
    stream_id: int
    protocol: ProtocolType
    client_ip: str
    server_ip: str
    client_port: int
    server_port: int
    start_time: Optional[datetime]
    end_time: Optional[datetime]
    duration: float
    packet_count: int
    byte_count: int
    
    starttls_offered: bool = False
    starttls_requested: bool = False
    tls_started: bool = False
    upgrade_successful: bool = False
    plaintext_after_offer: bool = False
    auth_before_tls: bool = False
    
    tls_version: Optional[TLSVersion] = None
    cipher_suite: Optional[str] = None
    key_exchange: Optional[str] = None
    signature_algorithm: Optional[str] = None
    supported_groups: List[str] = field(default_factory=list)
    sni: Optional[str] = None
    handshake_complete: bool = False
    
    certificate_id: Optional[int] = None
    
    cipher_strength: float = 0.0
    key_exchange_strength: float = 0.0
    forward_secrecy: bool = False
    
    evidence_frames: List[int] = field(default_factory=list)
    confidence: float = 1.0


class CryptoAnalyzer:
    def __init__(self):
        self.tls_parser = TlsParser()
        self.cert_parser = CertificateParser()
        self.smtp_parser = SmtpParser()
        self.imap_parser = ImapParser()
        self.pop3_parser = Pop3Parser()
        self.protocol_detector = ProtocolDetector()
    
    def analyze(
        self,
        tcp_streams: Dict,
        smtp_packets: List[Dict],
        imap_packets: List[Dict],
        pop3_packets: List[Dict],
        tls_handshakes: List[Dict],
        certificates: List[Dict],
        detected_protocols: Dict[int, DetectedProtocol],
    ) -> Dict[str, Any]:
        
        sessions = []
        cert_map = {}
        
        parsed_certs = self.cert_parser.parse_from_tshark(certificates)
        for i, cert in enumerate(parsed_certs):
            cert_map[cert.fingerprint_sha256] = cert
        
        for stream_id, stream in tcp_streams.items():
            protocol_info = detected_protocols.get(stream_id)
            if not protocol_info:
                continue
            
            session = self._analyze_stream(
                stream_id, stream, protocol_info,
                smtp_packets, imap_packets, pop3_packets,
                tls_handshakes, cert_map
            )
            if session:
                sessions.append(session)
        
        return {
            "sessions": sessions,
            "certificates": parsed_certs,
        }
    
    def _analyze_stream(
        self,
        stream_id: int,
        stream: Any,
        protocol_info: DetectedProtocol,
        smtp_packets: List[Dict],
        imap_packets: List[Dict],
        pop3_packets: List[Dict],
        tls_handshakes: List[Dict],
        cert_map: Dict,
    ) -> Optional[SessionAnalysis]:
        
        stream_packets = []
        if isinstance(stream, list):
            stream_packets = stream
        elif hasattr(stream, "packets"):
            stream_packets = list(stream.packets)
        
        tls_packets = [p for p in tls_handshakes if p.get("tcp_stream") == stream_id]
        tls_session = self.tls_parser.parse(stream_id, tls_packets) if tls_packets else None
        
        protocol_packets = []
        if protocol_info.protocol == ProtocolType.SMTP:
            protocol_packets = [p for p in smtp_packets if p.get("tcp_stream") == stream_id]
            self.smtp_parser.parse(stream_id, protocol_packets)
        elif protocol_info.protocol == ProtocolType.IMAP:
            protocol_packets = [p for p in imap_packets if p.get("tcp_stream") == stream_id]
            self.imap_parser.parse(stream_id, protocol_packets)
        elif protocol_info.protocol == ProtocolType.POP3:
            protocol_packets = [p for p in pop3_packets if p.get("tcp_stream") == stream_id]
            self.pop3_parser.parse(stream_id, protocol_packets)
        
        starttls_info = self._get_starttls_info(stream_id, protocol_info.protocol)
        
        cert_id = None
        if tls_session and tls_session.certificate_frame:
            for fp, cert in cert_map.items():
                cert_id = hash(fp) % 1000000
                break
        
        evidence_frames = []
        if hasattr(stream, 'frame_numbers'):
            evidence_frames = stream.frame_numbers
        elif isinstance(stream, dict) and 'frame_numbers' in stream:
            evidence_frames = stream['frame_numbers']
        
        tls_version = None
        if tls_session and tls_session.negotiated_version:
            tls_version = TLSVersion(tls_session.negotiated_version)
        
        cipher_strength = 0.0
        key_exchange_strength = 0.0
        forward_secrecy = False
        
        if tls_session:
            cipher_strength = TlsParser.get_cipher_strength(tls_session.negotiated_cipher)
            key_exchange_strength = TlsParser.get_key_exchange_strength(tls_session.negotiated_key_exchange)
            forward_secrecy = TlsParser.has_forward_secrecy(tls_session.negotiated_key_exchange)
        
        confidence = 1.0
        if tls_session:
            if not tls_session.handshake_complete:
                confidence *= 0.6
            if not tls_session.certificate_frame:
                confidence *= 0.8
        
        return SessionAnalysis(
            stream_id=stream_id,
            protocol=protocol_info.protocol,
            client_ip=protocol_info.client_ip,
            server_ip=protocol_info.server_ip,
            client_port=protocol_info.client_port,
            server_port=protocol_info.server_port,
            start_time=getattr(stream, 'start_time', None) if not isinstance(stream, dict) else stream.get('start_time'),
            end_time=getattr(stream, 'end_time', None) if not isinstance(stream, dict) else stream.get('end_time'),
            duration=getattr(stream, 'duration', 0.0) if not isinstance(stream, dict) else stream.get('duration', 0.0),
            packet_count=getattr(stream, 'packet_count', 0) if not isinstance(stream, dict) else stream.get('packet_count', 0),
            byte_count=getattr(stream, 'byte_count', 0) if not isinstance(stream, dict) else stream.get('byte_count', 0),
            
            starttls_offered=starttls_info.get('offered', False),
            starttls_requested=starttls_info.get('requested', False),
            tls_started=starttls_info.get('started', False),
            upgrade_successful=starttls_info.get('successful', False),
            plaintext_after_offer=starttls_info.get('plaintext_after', False),
            auth_before_tls=starttls_info.get('auth_before', False),
            
            tls_version=tls_version,
            cipher_suite=tls_session.negotiated_cipher if tls_session else None,
            key_exchange=tls_session.negotiated_key_exchange if tls_session else None,
            signature_algorithm=tls_session.negotiated_signature_alg if tls_session else None,
            supported_groups=tls_session.handshakes[0].supported_groups if tls_session and tls_session.handshakes else [],
            sni=tls_session.sni if tls_session else None,
            handshake_complete=tls_session.handshake_complete if tls_session else False,
            
            certificate_id=cert_id,
            
            cipher_strength=cipher_strength,
            key_exchange_strength=key_exchange_strength,
            forward_secrecy=forward_secrecy,
            
            evidence_frames=evidence_frames,
            confidence=confidence,
        )
    
    def _get_starttls_info(self, stream_id: int, protocol: ProtocolType) -> Dict[str, bool]:
        info = {
            'offered': False,
            'requested': False,
            'started': False,
            'successful': False,
            'plaintext_after': False,
            'auth_before': False,
        }
        
        if protocol == ProtocolType.SMTP:
            session = self.smtp_parser.get_session(stream_id)
            if session:
                info['offered'] = session.starttls_advertised
                info['requested'] = session.starttls_requested
                info['started'] = session.tls_started
                info['successful'] = session.upgrade_successful
                info['plaintext_after'] = session.plaintext_after_offer
                info['auth_before'] = session.auth_before_tls
        
        elif protocol == ProtocolType.IMAP:
            session = self.imap_parser.get_session(stream_id)
            if session:
                info['offered'] = session.starttls_advertised
                info['requested'] = session.starttls_requested
                info['started'] = session.tls_started
                info['successful'] = session.upgrade_successful
                info['plaintext_after'] = session.plaintext_after_offer
                info['auth_before'] = session.auth_before_tls
        
        elif protocol == ProtocolType.POP3:
            session = self.pop3_parser.get_session(stream_id)
            if session:
                info['offered'] = session.stls_advertised
                info['requested'] = session.stls_requested
                info['started'] = session.tls_started
                info['successful'] = session.upgrade_successful
                info['plaintext_after'] = session.plaintext_after_offer
                info['auth_before'] = session.auth_before_tls
        
        return info
    
    def get_feature_vector(self, session: SessionAnalysis) -> Dict[str, Any]:
        version_map = {
            "SSL 3.0": 0.0,
            "TLS 1.0": 0.25,
            "TLS 1.1": 0.5,
            "TLS 1.2": 0.75,
            "TLS 1.3": 1.0,
        }
        
        tls_version_num = 0.0
        if session.tls_version:
            tls_version_num = version_map.get(session.tls_version.value, 0.0)
        
        return {
            "tls_version": tls_version_num,
            "cipher_strength": session.cipher_strength,
            "key_exchange_strength": session.key_exchange_strength,
            "forward_secrecy": 1.0 if session.forward_secrecy else 0.0,
            "certificate_valid": 1.0,
            "certificate_expired": 0.0,
            "public_key_strength": 1.0,
            "signature_strength": 1.0,
            "starttls_success": 1.0 if session.upgrade_successful else 0.0,
            "handshake_complete": 1.0 if session.handshake_complete else 0.0,
            "auth_before_tls": 1.0 if session.auth_before_tls else 0.0,
            "plaintext_after_offer": 1.0 if session.plaintext_after_offer else 0.0,
            "protocol_smtp": 1.0 if session.protocol == ProtocolType.SMTP else 0.0,
            "protocol_imap": 1.0 if session.protocol == ProtocolType.IMAP else 0.0,
            "protocol_pop3": 1.0 if session.protocol == ProtocolType.POP3 else 0.0,
            "implicit_tls": 1.0 if EmailPort.is_implicit_tls_port(session.server_port) else 0.0,
        }