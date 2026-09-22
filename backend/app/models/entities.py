from sqlalchemy import (
    Column, Integer, String, Float, Boolean, DateTime, Text, ForeignKey, Enum as SQLEnum, JSON
)
from sqlalchemy.orm import relationship, declarative_base
from datetime import datetime
import enum

Base = declarative_base()


class AnalysisStatus(str, enum.Enum):
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"


class ProtocolType(str, enum.Enum):
    SMTP = "SMTP"
    IMAP = "IMAP"
    POP3 = "POP3"
    UNKNOWN = "UNKNOWN"


class TLSVersion(str, enum.Enum):
    TLS_1_0 = "TLS 1.0"
    TLS_1_1 = "TLS 1.1"
    TLS_1_2 = "TLS 1.2"
    TLS_1_3 = "TLS 1.3"
    SSL_3_0 = "SSL 3.0"
    UNKNOWN = "UNKNOWN"


class FindingSeverity(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class FindingCategory(str, enum.Enum):
    TLS_VERSION = "TLS_VERSION"
    CIPHER = "CIPHER"
    KEY_EXCHANGE = "KEY_EXCHANGE"
    CERTIFICATE = "CERTIFICATE"
    STARTTLS = "STARTTLS"
    ANOMALY = "ANOMALY"
    DRIFT = "DRIFT"
    FORWARD_SECRECY = "FORWARD_SECRECY"


class Analysis(Base):
    __tablename__ = "analyses"
    
    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String(255), nullable=False)
    file_size = Column(Integer)
    file_hash = Column(String(64))
    status = Column(SQLEnum(AnalysisStatus), default=AnalysisStatus.PENDING)
    created_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    error_message = Column(Text, nullable=True)
    
    sessions = relationship("Session", back_populates="analysis", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="analysis", cascade="all, delete-orphan")
    certificates = relationship("Certificate", back_populates="analysis", cascade="all, delete-orphan")
    baselines = relationship("Baseline", back_populates="analysis", cascade="all, delete-orphan")
    drift_findings = relationship("DriftFinding", back_populates="analysis", cascade="all, delete-orphan")


class Session(Base):
    __tablename__ = "sessions"
    
    id = Column(Integer, primary_key=True, index=True)
    analysis_id = Column(Integer, ForeignKey("analyses.id"), nullable=False)
    protocol = Column(SQLEnum(ProtocolType), nullable=False)
    client_ip = Column(String(45))
    server_ip = Column(String(45))
    client_port = Column(Integer)
    server_port = Column(Integer)
    tcp_stream = Column(Integer)
    start_time = Column(DateTime)
    end_time = Column(DateTime)
    duration = Column(Float)
    packet_count = Column(Integer)
    byte_count = Column(Integer)
    
    starttls_offered = Column(Boolean, default=False)
    starttls_requested = Column(Boolean, default=False)
    tls_started = Column(Boolean, default=False)
    upgrade_successful = Column(Boolean, default=False)
    plaintext_after_offer = Column(Boolean, default=False)
    auth_before_tls = Column(Boolean, default=False)
    
    tls_version = Column(SQLEnum(TLSVersion), nullable=True)
    cipher_suite = Column(String(100), nullable=True)
    key_exchange = Column(String(100), nullable=True)
    signature_algorithm = Column(String(100), nullable=True)
    supported_groups = Column(JSON, nullable=True)
    sni = Column(String(255), nullable=True)
    handshake_complete = Column(Boolean, default=False)
    
    certificate_id = Column(Integer, ForeignKey("certificates.id"), nullable=True)
    
    cipher_strength = Column(Float, nullable=True)
    key_exchange_strength = Column(Float, nullable=True)
    forward_secrecy = Column(Boolean, nullable=True)
    
    anomaly_score = Column(Float, nullable=True)
    is_anomalous = Column(Boolean, default=False)
    
    risk_score = Column(Float, nullable=True)
    risk_level = Column(String(20), nullable=True)
    
    confidence = Column(Float, nullable=True)
    evidence_frames = Column(JSON, nullable=True)
    
    analysis = relationship("Analysis", back_populates="sessions")
    certificate = relationship("Certificate", back_populates="sessions")
    findings = relationship("Finding", back_populates="session")


class Certificate(Base):
    __tablename__ = "certificates"
    
    id = Column(Integer, primary_key=True, index=True)
    analysis_id = Column(Integer, ForeignKey("analyses.id"), nullable=False)
    subject = Column(Text)
    issuer = Column(Text)
    serial_number = Column(String(100))
    not_before = Column(DateTime)
    not_after = Column(DateTime)
    is_expired = Column(Boolean, default=False)
    is_not_yet_valid = Column(Boolean, default=False)
    public_key_algorithm = Column(String(100))
    public_key_size = Column(Integer)
    signature_algorithm = Column(String(100))
    san = Column(JSON, nullable=True)
    is_self_signed = Column(Boolean, default=False)
    chain_info = Column(JSON, nullable=True)
    pem_data = Column(Text, nullable=True)
    
    analysis = relationship("Analysis", back_populates="certificates")
    sessions = relationship("Session", back_populates="certificate")


class Finding(Base):
    __tablename__ = "findings"
    
    id = Column(Integer, primary_key=True, index=True)
    analysis_id = Column(Integer, ForeignKey("analyses.id"), nullable=False)
    session_id = Column(Integer, ForeignKey("sessions.id"), nullable=True)
    finding_id = Column(String(50), nullable=False)
    title = Column(String(255), nullable=False)
    severity = Column(SQLEnum(FindingSeverity), nullable=False)
    category = Column(SQLEnum(FindingCategory), nullable=False)
    description = Column(Text)
    impact = Column(Text)
    recommendation = Column(Text)
    confidence = Column(Float)
    observed_value = Column(String(255), nullable=True)
    baseline_value = Column(String(255), nullable=True)
    evidence_frames = Column(JSON, nullable=True)
    technical_evidence = Column(JSON, nullable=True)
    affected_server = Column(String(45), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    analysis = relationship("Analysis", back_populates="findings")
    session = relationship("Session", back_populates="findings")


class Baseline(Base):
    __tablename__ = "baselines"
    
    id = Column(Integer, primary_key=True, index=True)
    analysis_id = Column(Integer, ForeignKey("analyses.id"), nullable=False)
    server_ip = Column(String(45), nullable=False)
    server_port = Column(Integer, nullable=False)
    protocol = Column(SQLEnum(ProtocolType), nullable=False)
    total_sessions = Column(Integer)
    
    tls_version_dist = Column(JSON)
    cipher_dist = Column(JSON)
    key_exchange_dist = Column(JSON)
    certificate_fingerprint_dist = Column(JSON)
    starttls_success_rate = Column(Float)
    
    dominant_tls_version = Column(String(20))
    dominant_cipher = Column(String(100))
    dominant_key_exchange = Column(String(100))
    
    analysis = relationship("Analysis", back_populates="baselines")


class DriftFinding(Base):
    __tablename__ = "drift_findings"
    
    id = Column(Integer, primary_key=True, index=True)
    analysis_id = Column(Integer, ForeignKey("analyses.id"), nullable=False)
    baseline_id = Column(Integer, ForeignKey("baselines.id"), nullable=True)
    session_id = Column(Integer, ForeignKey("sessions.id"), nullable=True)
    drift_type = Column(String(50))
    title = Column(String(255))
    severity = Column(SQLEnum(FindingSeverity))
    description = Column(Text)
    baseline_value = Column(String(255))
    observed_value = Column(String(255))
    confidence = Column(Float)
    evidence_frames = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    analysis = relationship("Analysis", back_populates="drift_findings")