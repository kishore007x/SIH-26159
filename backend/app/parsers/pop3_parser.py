import logging
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class Pop3State(Enum):
    CONNECTED = "CONNECTED"
    AUTHORIZATION = "AUTHORIZATION"
    STLS_ADVERTISED = "STLS_ADVERTISED"
    STLS_REQUESTED = "STLS_REQUESTED"
    TLS_HANDSHAKE = "TLS_HANDSHAKE"
    ENCRYPTED = "ENCRYPTED"
    TRANSACTION = "TRANSACTION"
    UPDATE = "UPDATE"
    CLOSED = "CLOSED"
    ERROR = "ERROR"


@dataclass
class Pop3Session:
    stream_id: int
    state: Pop3State = Pop3State.CONNECTED
    stls_advertised: bool = False
    stls_requested: bool = False
    tls_started: bool = False
    upgrade_successful: bool = False
    plaintext_after_offer: bool = False
    auth_before_tls: bool = False
    commands: List[Dict] = field(default_factory=list)
    responses: List[Dict] = field(default_factory=list)
    evidence_frames: List[int] = field(default_factory=list)


class Pop3Parser:
    def __init__(self):
        self.sessions: Dict[int, Pop3Session] = {}
    
    def parse(self, stream_id: int, packets: List[Dict]) -> Pop3Session:
        if stream_id not in self.sessions:
            self.sessions[stream_id] = Pop3Session(stream_id=stream_id)
        
        session = self.sessions[stream_id]
        
        for packet in packets:
            frame_num = packet.get("frame_number")
            if frame_num:
                session.evidence_frames.append(frame_num)
            
            command = packet.get("pop3_command")
            response = packet.get("pop3_response")
            
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
    
    def _process_command(self, session: Pop3Session, command: str):
        if command == "STLS":
            session.stls_requested = True
            session.state = Pop3State.STLS_REQUESTED
            if session.stls_advertised and not session.tls_started:
                session.plaintext_after_offer = True
        
        elif command in ("USER", "PASS", "APOP", "AUTH"):
            if not session.tls_started and not session.upgrade_successful:
                session.auth_before_tls = True
            session.state = Pop3State.AUTHORIZATION
        
        elif command in ("STAT", "LIST", "RETR", "DELE", "NOOP", "RSET", "TOP", "UIDL"):
            if not session.tls_started and not session.upgrade_successful:
                session.plaintext_after_offer = True
            session.state = Pop3State.TRANSACTION
        
        elif command == "QUIT":
            session.state = Pop3State.UPDATE
    
    def _process_response(self, session: Pop3Session, response: str):
        response_upper = response.upper()
        
        if "+OK" in response_upper and "STLS" in response_upper:
            if session.state == Pop3State.AUTHORIZATION:
                session.stls_advertised = True
                session.state = Pop3State.STLS_ADVERTISED
        
        elif "+OK" in response_upper and session.state == Pop3State.STLS_REQUESTED:
            session.tls_started = True
            session.state = Pop3State.TLS_HANDSHAKE
        
        elif "+OK" in response_upper and session.state == Pop3State.TLS_HANDSHAKE:
            session.upgrade_successful = True
            session.state = Pop3State.ENCRYPTED
        
        elif "+OK" in response_upper and session.state == Pop3State.AUTHORIZATION:
            session.state = Pop3State.TRANSACTION
        
        elif "-ERR" in response_upper:
            if session.state in (Pop3State.STLS_REQUESTED, Pop3State.AUTHORIZATION):
                session.state = Pop3State.ERROR
    
    def get_session(self, stream_id: int) -> Optional[Pop3Session]:
        return self.sessions.get(stream_id)
    
    def get_all_sessions(self) -> Dict[int, Pop3Session]:
        return self.sessions