import logging
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass
from enum import Enum

from backend.app.models.schemas import ProtocolType

logger = logging.getLogger(__name__)


class EmailPort(Enum):
    SMTP_25 = 25
    SMTP_465 = 465
    SMTP_587 = 587
    IMAP_143 = 143
    IMAP_993 = 993
    POP3_110 = 110
    POP3_995 = 995
    
    @classmethod
    def get_protocol_for_port(cls, port: int) -> Optional[ProtocolType]:
        if port in [cls.SMTP_25.value, cls.SMTP_465.value, cls.SMTP_587.value]:
            return ProtocolType.SMTP
        elif port in [cls.IMAP_143.value, cls.IMAP_993.value]:
            return ProtocolType.IMAP
        elif port in [cls.POP3_110.value, cls.POP3_995.value]:
            return ProtocolType.POP3
        return None
    
    @classmethod
    def is_implicit_tls_port(cls, port: int) -> bool:
        return port in [cls.SMTP_465.value, cls.IMAP_993.value, cls.POP3_995.value]
    
    @classmethod
    def is_starttls_port(cls, port: int) -> bool:
        return port in [cls.SMTP_25.value, cls.SMTP_587.value, cls.IMAP_143.value, cls.POP3_110.value]


@dataclass
class DetectedProtocol:
    protocol: ProtocolType
    confidence: float
    evidence: Dict[str, Any]
    server_ip: str
    server_port: int
    client_ip: str
    client_port: int
    tcp_stream: int


class ProtocolDetector:
    SMTP_COMMANDS = {"EHLO", "HELO", "MAIL", "RCPT", "DATA", "QUIT", "RSET", "VRFY", "EXPN", "STARTTLS", "AUTH"}
    IMAP_COMMANDS = {"CAPABILITY", "LOGIN", "SELECT", "EXAMINE", "CREATE", "DELETE", "RENAME", "SUBSCRIBE", "UNSUBSCRIBE", "LIST", "LSUB", "STATUS", "APPEND", "CHECK", "CLOSE", "EXPUNGE", "SEARCH", "FETCH", "STORE", "COPY", "UID", "IDLE", "STARTTLS", "AUTHENTICATE"}
    POP3_COMMANDS = {"USER", "PASS", "APOP", "STAT", "LIST", "RETR", "DELE", "NOOP", "RSET", "QUIT", "TOP", "UIDL", "STLS", "AUTH"}
    
    def __init__(self):
        self.stream_protocols: Dict[int, DetectedProtocol] = {}
    
    def detect_from_packets(
        self,
        tcp_streams: List[Dict],
        smtp_packets: List[Dict],
        imap_packets: List[Dict],
        pop3_packets: List[Dict],
    ) -> Dict[int, DetectedProtocol]:
        stream_info = self._build_stream_info(tcp_streams)
        
        smtp_streams = self._get_streams_with_protocol_packets(smtp_packets)
        imap_streams = self._get_streams_with_protocol_packets(imap_packets)
        pop3_streams = self._get_streams_with_protocol_packets(pop3_packets)
        
        all_streams = set(stream_info.keys()) | smtp_streams | imap_streams | pop3_streams
        
        for stream_id in all_streams:
            info = stream_info.get(stream_id, {})
            protocol = self._determine_protocol(
                stream_id,
                info,
                stream_id in smtp_streams,
                stream_id in imap_streams,
                stream_id in pop3_streams,
                smtp_packets,
                imap_packets,
                pop3_packets,
            )
            
            if protocol:
                self.stream_protocols[stream_id] = protocol
        
        return self.stream_protocols
    
    def _build_stream_info(self, tcp_streams: List[Dict]) -> Dict[int, Dict]:
        info = {}
        for packet in tcp_streams:
            stream_id = packet.get("tcp_stream")
            if stream_id is None:
                continue
            stream_id = int(stream_id)
            if stream_id not in info:
                source_port = int(packet.get("tcp_srcport", 0) or 0)
                destination_port = int(packet.get("tcp_dstport", 0) or 0)
                email_server_ports = {25, 110, 143, 465, 587, 993, 995}
                server_first = source_port in email_server_ports and destination_port not in email_server_ports
                info[stream_id] = {
                    "client_ip": packet.get("ip_dst") if server_first else packet.get("ip_src"),
                    "server_ip": packet.get("ip_src") if server_first else packet.get("ip_dst"),
                    "client_port": destination_port if server_first else source_port,
                    "server_port": source_port if server_first else destination_port,
                    "packets": [],
                }
            info[stream_id]["packets"].append(packet)
        return info
    
    def _get_streams_with_protocol_packets(self, packets: List[Dict]) -> Set[int]:
        streams = set()
        for packet in packets:
            stream_id = packet.get("tcp_stream")
            if stream_id is not None:
                streams.add(int(stream_id))
        return streams
    
    def _determine_protocol(
        self,
        stream_id: int,
        info: Dict,
        has_smtp: bool,
        has_imap: bool,
        has_pop3: bool,
        smtp_packets: List[Dict],
        imap_packets: List[Dict],
        pop3_packets: List[Dict],
    ) -> Optional[DetectedProtocol]:
        
        server_port = info.get("server_port")
        port_protocol = EmailPort.get_protocol_for_port(int(server_port)) if server_port else None
        
        protocol_scores = {
            ProtocolType.SMTP: 0.0,
            ProtocolType.IMAP: 0.0,
            ProtocolType.POP3: 0.0,
        }
        
        if port_protocol:
            protocol_scores[port_protocol] += 0.3
        
        if has_smtp:
            protocol_scores[ProtocolType.SMTP] += 0.5
        if has_imap:
            protocol_scores[ProtocolType.IMAP] += 0.5
        if has_pop3:
            protocol_scores[ProtocolType.POP3] += 0.5
        
        smtp_cmds = self._extract_commands(stream_id, smtp_packets, "smtp_command")
        imap_cmds = self._extract_commands(stream_id, imap_packets, "imap_command")
        pop3_cmds = self._extract_commands(stream_id, pop3_packets, "pop3_command")
        
        if smtp_cmds & self.SMTP_COMMANDS:
            protocol_scores[ProtocolType.SMTP] += 0.4
        if imap_cmds & self.IMAP_COMMANDS:
            protocol_scores[ProtocolType.IMAP] += 0.4
        if pop3_cmds & self.POP3_COMMANDS:
            protocol_scores[ProtocolType.POP3] += 0.4
        
        best_protocol = max(protocol_scores, key=protocol_scores.get)
        confidence = protocol_scores[best_protocol]
        
        if confidence < 0.3:
            return None
        
        return DetectedProtocol(
            protocol=best_protocol,
            confidence=confidence,
            evidence={
                "port_protocol": port_protocol.value if port_protocol else None,
                "has_smtp_packets": has_smtp,
                "has_imap_packets": has_imap,
                "has_pop3_packets": has_pop3,
                "smtp_commands": list(smtp_cmds),
                "imap_commands": list(imap_cmds),
                "pop3_commands": list(pop3_cmds),
                "protocol_scores": protocol_scores,
            },
            server_ip=info.get("server_ip", ""),
            server_port=int(server_port) if server_port else 0,
            client_ip=info.get("client_ip", ""),
            client_port=int(info.get("client_port", 0)) if info.get("client_port") else 0,
            tcp_stream=stream_id,
        )
    
    def _extract_commands(self, stream_id: int, packets: List[Dict], command_field: str) -> Set[str]:
        commands = set()
        for packet in packets:
            if packet.get("tcp_stream") == stream_id:
                cmd = packet.get(command_field)
                if cmd:
                    commands.add(str(cmd).upper())
        return commands