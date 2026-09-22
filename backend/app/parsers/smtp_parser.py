import logging
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class SmtpState(Enum):
    CONNECTED = "CONNECTED"
    EHLO_SENT = "EHLO_SENT"
    HELO_SENT = "HELO_SENT"
    STARTTLS_ADVERTISED = "STARTTLS_ADVERTISED"
    STARTTLS_REQUESTED = "STARTTLS_REQUESTED"
    TLS_HANDSHAKE = "TLS_HANDSHAKE"
    ENCRYPTED = "ENCRYPTED"
    AUTHENTICATING = "AUTHENTICATING"
    MAIL_TRANSACTION = "MAIL_TRANSACTION"
    CLOSED = "CLOSED"
    ERROR = "ERROR"


@dataclass
class SmtpSession:
    stream_id: int
    state: SmtpState = SmtpState.CONNECTED
    ehlo_received: bool = False
    helo_received: bool = False
    starttls_advertised: bool = False
    starttls_requested: bool = False
    tls_started: bool = False
    upgrade_successful: bool = False
    plaintext_after_offer: bool = False
    auth_before_tls: bool = False
    commands: List[Dict] = field(default_factory=list)
    responses: List[Dict] = field(default_factory=list)
    evidence_frames: List[int] = field(default_factory=list)


class SmtpParser:
    def __init__(self):
        self.sessions: Dict[int, SmtpSession] = {}
    
    def parse(self, stream_id: int, packets: List[Dict]) -> SmtpSession:
        if stream_id not in self.sessions:
            self.sessions[stream_id] = SmtpSession(stream_id=stream_id)
        
        session = self.sessions[stream_id]
        
        for packet in packets:
            frame_num = packet.get("frame_number")
            if frame_num:
                session.evidence_frames.append(frame_num)
            
            command = packet.get("smtp_command")
            response = packet.get("smtp_response")
            reply_code = packet.get("smtp_reply_code")
            
            if command:
                session.commands.append({
                    "frame": frame_num,
                    "command": command,
                    "parameter": packet.get("smtp_parameter"),
                })
                self._process_command(session, command.upper())
            
            if response and reply_code:
                session.responses.append({
                    "frame": frame_num,
                    "code": reply_code,
                    "response": response,
                })
                self._process_response(session, int(reply_code))
        
        return session
    
    def _process_command(self, session: SmtpSession, command: str):
        if command in ("EHLO", "HELO"):
            session.ehlo_received = True
            session.state = SmtpState.EHLO_SENT if command == "EHLO" else SmtpState.HELO_SENT
        
        elif command == "STARTTLS":
            session.starttls_requested = True
            session.state = SmtpState.STARTTLS_REQUESTED
            if session.starttls_advertised and not session.tls_started:
                session.plaintext_after_offer = True
        
        elif command == "AUTH":
            if not session.tls_started and not session.upgrade_successful:
                session.auth_before_tls = True
            session.state = SmtpState.AUTHENTICATING
        
        elif command in ("MAIL", "RCPT", "DATA"):
            if not session.tls_started and not session.upgrade_successful:
                session.plaintext_after_offer = True
            session.state = SmtpState.MAIL_TRANSACTION
        
        elif command == "QUIT":
            session.state = SmtpState.CLOSED
    
    def _process_response(self, session: SmtpSession, code: int):
        if code == 220 and "STARTTLS" in str(session.responses[-1].get("response", "")).upper():
            session.starttls_advertised = True
            session.state = SmtpState.STARTTLS_ADVERTISED
        
        elif code == 220 and session.state == SmtpState.STARTTLS_REQUESTED:
            session.tls_started = True
            session.state = SmtpState.TLS_HANDSHAKE
        
        elif code == 250 and session.state == SmtpState.TLS_HANDSHAKE:
            session.upgrade_successful = True
            session.state = SmtpState.ENCRYPTED
        
        elif code >= 400 and session.state == SmtpState.STARTTLS_REQUESTED:
            session.state = SmtpState.ERROR
    
    def get_session(self, stream_id: int) -> Optional[SmtpSession]:
        return self.sessions.get(stream_id)
    
    def get_all_sessions(self) -> Dict[int, SmtpSession]:
        return self.sessions