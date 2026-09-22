import logging
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class ImapState(Enum):
    CONNECTED = "CONNECTED"
    CAPABILITY_SENT = "CAPABILITY_SENT"
    STARTTLS_ADVERTISED = "STARTTLS_ADVERTISED"
    STARTTLS_REQUESTED = "STARTTLS_REQUESTED"
    TLS_HANDSHAKE = "TLS_HANDSHAKE"
    ENCRYPTED = "ENCRYPTED"
    AUTHENTICATING = "AUTHENTICATING"
    AUTHENTICATED = "AUTHENTICATED"
    SELECTED = "SELECTED"
    CLOSED = "CLOSED"
    ERROR = "ERROR"


@dataclass
class ImapSession:
    stream_id: int
    state: ImapState = ImapState.CONNECTED
    capability_received: bool = False
    starttls_advertised: bool = False
    starttls_requested: bool = False
    tls_started: bool = False
    upgrade_successful: bool = False
    plaintext_after_offer: bool = False
    auth_before_tls: bool = False
    commands: List[Dict] = field(default_factory=list)
    responses: List[Dict] = field(default_factory=list)
    evidence_frames: List[int] = field(default_factory=list)


class ImapParser:
    def __init__(self):
        self.sessions: Dict[int, ImapSession] = {}
    
    def parse(self, stream_id: int, packets: List[Dict]) -> ImapSession:
        if stream_id not in self.sessions:
            self.sessions[stream_id] = ImapSession(stream_id=stream_id)
        
        session = self.sessions[stream_id]
        
        for packet in packets:
            frame_num = packet.get("frame_number")
            if frame_num:
                session.evidence_frames.append(frame_num)
            
            command = packet.get("imap_command")
            response = packet.get("imap_response")
            
            if command:
                session.commands.append({
                    "frame": frame_num,
                    "command": command,
                })
                self._process_command(session, command.upper())
            
            if response:
                session.responses.append({
                    "frame": frame_num,
                    "response": response,
                })
                self._process_response(session, response)
        
        return session
    
    def _process_command(self, session: ImapSession, command: str):
        if command == "CAPABILITY":
            session.state = ImapState.CAPABILITY_SENT
        
        elif command == "STARTTLS":
            session.starttls_requested = True
            session.state = ImapState.STARTTLS_REQUESTED
            if session.starttls_advertised and not session.tls_started:
                session.plaintext_after_offer = True
        
        elif command == "AUTHENTICATE" or command == "LOGIN":
            if not session.tls_started and not session.upgrade_successful:
                session.auth_before_tls = True
            session.state = ImapState.AUTHENTICATING
        
        elif command in ("SELECT", "EXAMINE"):
            session.state = ImapState.SELECTED
        
        elif command == "LOGOUT":
            session.state = ImapState.CLOSED
    
    def _process_response(self, session: ImapSession, response: str):
        response_upper = response.upper()
        
        if "STARTTLS" in response_upper and "OK" in response_upper:
            if session.state == ImapState.CAPABILITY_SENT:
                session.starttls_advertised = True
                session.state = ImapState.STARTTLS_ADVERTISED
        
        elif "OK" in response_upper and session.state == ImapState.STARTTLS_REQUESTED:
            session.tls_started = True
            session.state = ImapState.TLS_HANDSHAKE
        
        elif "OK" in response_upper and session.state == ImapState.TLS_HANDSHAKE:
            session.upgrade_successful = True
            session.state = ImapState.ENCRYPTED
        
        elif "OK" in response_upper and session.state == ImapState.AUTHENTICATING:
            session.state = ImapState.AUTHENTICATED
        
        elif "BAD" in response_upper or "NO" in response_upper:
            if session.state in (ImapState.STARTTLS_REQUESTED, ImapState.AUTHENTICATING):
                session.state = ImapState.ERROR
    
    def get_session(self, stream_id: int) -> Optional[ImapSession]:
        return self.sessions.get(stream_id)
    
    def get_all_sessions(self) -> Dict[int, ImapSession]:
        return self.sessions