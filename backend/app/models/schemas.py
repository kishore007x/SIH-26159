from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum


class AnalysisStatus(str, Enum):
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"


class ProtocolType(str, Enum):
    SMTP = "SMTP"
    IMAP = "IMAP"
    POP3 = "POP3"
    UNKNOWN = "UNKNOWN"


class TLSVersion(str, Enum):
    TLS_1_0 = "TLS 1.0"
    TLS_1_1 = "TLS 1.1"
    TLS_1_2 = "TLS 1.2"
    TLS_1_3 = "TLS 1.3"
    SSL_3_0 = "SSL 3.0"
    UNKNOWN = "UNKNOWN"


class FindingSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class FindingCategory(str, Enum):
    TLS_VERSION = "TLS_VERSION"
    CIPHER = "CIPHER"
    KEY_EXCHANGE = "KEY_EXCHANGE"
    CERTIFICATE = "CERTIFICATE"
    STARTTLS = "STARTTLS"
    ANOMALY = "ANOMALY"
    DRIFT = "DRIFT"
    FORWARD_SECRECY = "FORWARD_SECRECY"


class DriftType(str, Enum):
    TLS_VERSION = "TLS_VERSION"
    CIPHER = "CIPHER"
    KEY_EXCHANGE = "KEY_EXCHANGE"
    CERTIFICATE = "CERTIFICATE"
    STARTTLS = "STARTTLS"


class AnalysisCreate(BaseModel):
    filename: str
    file_size: int
    file_hash: Optional[str] = None


class AnalysisResponse(BaseModel):
    id: int
    filename: str
    file_size: int
    file_hash: Optional[str]
    status: AnalysisStatus
    created_at: datetime
    completed_at: Optional[datetime]
    error_message: Optional[str]
    
    class Config:
        from_attributes = True


class SessionResponse(BaseModel):
    id: int
    analysis_id: int
    protocol: ProtocolType
    client_ip: Optional[str]
    server_ip: Optional[str]
    client_port: Optional[int]
    server_port: Optional[int]
    tcp_stream: int
    start_time: Optional[datetime]
    end_time: Optional[datetime]
    duration: Optional[float]
    packet_count: int
    byte_count: int
    
    starttls_offered: bool
    starttls_requested: bool
    tls_started: bool
    upgrade_successful: bool
    plaintext_after_offer: bool
    auth_before_tls: bool
    
    tls_version: Optional[TLSVersion]
    cipher_suite: Optional[str]
    key_exchange: Optional[str]
    signature_algorithm: Optional[str]
    supported_groups: Optional[List[str]]
    sni: Optional[str]
    handshake_complete: bool
    
    certificate_id: Optional[int]
    
    cipher_strength: Optional[float]
    key_exchange_strength: Optional[float]
    forward_secrecy: Optional[bool]
    
    anomaly_score: Optional[float]
    is_anomalous: bool
    
    risk_score: Optional[float]
    risk_level: Optional[str]
    
    confidence: Optional[float]
    evidence_frames: Optional[List[int]]
    
    class Config:
        from_attributes = True


class CertificateResponse(BaseModel):
    id: int
    analysis_id: int
    subject: Optional[str]
    issuer: Optional[str]
    serial_number: Optional[str]
    not_before: Optional[datetime]
    not_after: Optional[datetime]
    is_expired: bool
    is_not_yet_valid: bool
    public_key_algorithm: Optional[str]
    public_key_size: Optional[int]
    signature_algorithm: Optional[str]
    san: Optional[List[str]]
    is_self_signed: bool
    chain_info: Optional[Dict[str, Any]]
    pem_data: Optional[str]
    
    class Config:
        from_attributes = True


class FindingResponse(BaseModel):
    id: int
    analysis_id: int
    session_id: Optional[int]
    finding_id: str
    title: str
    severity: FindingSeverity
    category: FindingCategory
    description: str
    impact: str
    recommendation: str
    confidence: float
    observed_value: Optional[str]
    baseline_value: Optional[str]
    evidence_frames: Optional[List[int]]
    technical_evidence: Optional[Dict[str, Any]]
    affected_server: Optional[str]
    created_at: datetime
    
    class Config:
        from_attributes = True


class DriftFindingResponse(BaseModel):
    id: int
    analysis_id: int
    baseline_id: Optional[int]
    session_id: Optional[int]
    drift_type: DriftType
    title: str
    severity: FindingSeverity
    description: str
    baseline_value: str
    observed_value: str
    confidence: float
    evidence_frames: Optional[List[int]]
    created_at: datetime
    
    class Config:
        from_attributes = True


class BaselineResponse(BaseModel):
    id: int
    analysis_id: int
    server_ip: str
    server_port: int
    protocol: ProtocolType
    total_sessions: int
    tls_version_dist: Dict[str, int]
    cipher_dist: Dict[str, int]
    key_exchange_dist: Dict[str, int]
    certificate_fingerprint_dist: Dict[str, int]
    starttls_success_rate: float
    dominant_tls_version: str
    dominant_cipher: str
    dominant_key_exchange: str
    
    class Config:
        from_attributes = True


class AnalysisSummary(BaseModel):
    total_sessions: int
    smtp_sessions: int
    imap_sessions: int
    pop3_sessions: int
    tls_sessions: int
    starttls_sessions: int
    weak_crypto_findings: int
    certificate_findings: int
    anomalous_sessions: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    overall_risk_score: float
    overall_risk_level: str


class ReportRequest(BaseModel):
    format: str = "json"


class RemediationSimulationRequest(BaseModel):
    session_ids: List[int]
    simulated_changes: Dict[str, Any]


class RemediationSimulationResponse(BaseModel):
    current_risk_score: float
    current_risk_level: str
    projected_risk_score: float
    projected_risk_level: str
    changes_applied: Dict[str, Any]
    findings_resolved: List[str]


class HealthResponse(BaseModel):
    status: str
    version: str
    tshark_available: bool
    ollama_available: bool