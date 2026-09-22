import logging
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from enum import Enum

from backend.app.analysis.baseline_engine import BaselineEngine, ServerBaseline
from backend.app.analysis.crypto_analyzer import SessionAnalysis
from backend.app.models.schemas import FindingSeverity, ProtocolType

logger = logging.getLogger(__name__)


class DriftType(Enum):
    TLS_VERSION = "TLS_VERSION"
    CIPHER = "CIPHER"
    KEY_EXCHANGE = "KEY_EXCHANGE"
    CERTIFICATE = "CERTIFICATE"
    STARTTLS = "STARTTLS"


@dataclass
class DriftFinding:
    drift_type: DriftType
    title: str
    severity: FindingSeverity
    description: str
    baseline_value: str
    observed_value: str
    confidence: float
    server_ip: str
    server_port: int
    protocol: ProtocolType
    stream_id: int
    evidence_frames: List[int] = field(default_factory=list)


class DriftDetector:
    def __init__(self, baseline_engine: BaselineEngine, threshold: float = 0.1):
        self.baseline_engine = baseline_engine
        self.threshold = threshold
        self.drift_findings: List[DriftFinding] = []
    
    def detect_drift(self, sessions: List[SessionAnalysis]) -> List[DriftFinding]:
        self.drift_findings = []
        
        for session in sessions:
            baseline = self.baseline_engine.get_baseline(
                session.server_ip, session.server_port, session.protocol
            )
            
            if not baseline:
                continue
            
            self._check_tls_version_drift(session, baseline)
            self._check_cipher_drift(session, baseline)
            self._check_key_exchange_drift(session, baseline)
            self._check_starttls_drift(session, baseline)
        
        return self.drift_findings
    
    def _check_tls_version_drift(self, session: SessionAnalysis, baseline: ServerBaseline):
        if not session.tls_version:
            return
        
        observed = session.tls_version.value
        dominant = baseline.dominant_tls_version
        
        if observed == dominant:
            return
        
        baseline_ratio = baseline.tls_version_dist.get(observed, 0) / baseline.total_sessions
        
        if baseline_ratio < self.threshold:
            is_downgrade = self._is_tls_downgrade(observed, dominant)
            
            severity = FindingSeverity.HIGH if is_downgrade else FindingSeverity.MEDIUM
            confidence = 1.0 - baseline_ratio
            
            self.drift_findings.append(DriftFinding(
                drift_type=DriftType.TLS_VERSION,
                title="Unexpected TLS Version Drift",
                severity=severity,
                description=(
                    f"Session used {observed} while baseline shows {dominant} "
                    f"({baseline.tls_version_dist.get(dominant, 0)}/{baseline.total_sessions} sessions). "
                    f"This session's TLS version ({observed}) represents only "
                    f"{baseline_ratio:.1%} of baseline sessions."
                ),
                baseline_value=dominant,
                observed_value=observed,
                confidence=confidence,
                server_ip=session.server_ip,
                server_port=session.server_port,
                protocol=session.protocol,
                stream_id=session.stream_id,
                evidence_frames=session.evidence_frames,
            ))
    
    def _check_cipher_drift(self, session: SessionAnalysis, baseline: ServerBaseline):
        if not session.cipher_suite:
            return
        
        observed = session.cipher_suite
        dominant = baseline.dominant_cipher
        
        if observed == dominant:
            return
        
        baseline_ratio = baseline.cipher_dist.get(observed, 0) / baseline.total_sessions
        
        if baseline_ratio < self.threshold:
            is_weak = self._is_weak_cipher(observed)
            is_downgrade = self._is_cipher_downgrade(observed, dominant)
            
            severity = FindingSeverity.HIGH if (is_weak or is_downgrade) else FindingSeverity.MEDIUM
            confidence = 1.0 - baseline_ratio
            
            self.drift_findings.append(DriftFinding(
                drift_type=DriftType.CIPHER,
                title="Unexpected Cipher Suite Drift",
                severity=severity,
                description=(
                    f"Session negotiated cipher '{observed}' while baseline shows '{dominant}' "
                    f"({baseline.cipher_dist.get(dominant, 0)}/{baseline.total_sessions} sessions). "
                    f"This cipher represents only {baseline_ratio:.1%} of baseline sessions."
                ),
                baseline_value=dominant,
                observed_value=observed,
                confidence=confidence,
                server_ip=session.server_ip,
                server_port=session.server_port,
                protocol=session.protocol,
                stream_id=session.stream_id,
                evidence_frames=session.evidence_frames,
            ))
    
    def _check_key_exchange_drift(self, session: SessionAnalysis, baseline: ServerBaseline):
        if not session.key_exchange:
            return
        
        observed = session.key_exchange
        dominant = baseline.dominant_key_exchange
        
        if observed == dominant:
            return
        
        baseline_ratio = baseline.key_exchange_dist.get(observed, 0) / baseline.total_sessions
        
        if baseline_ratio < self.threshold:
            has_fs = session.forward_secrecy
            dominant_has_fs = "ECDHE" in dominant or "DHE" in dominant or "X25519" in dominant
            is_downgrade = dominant_has_fs and not has_fs
            
            severity = FindingSeverity.HIGH if is_downgrade else FindingSeverity.MEDIUM
            confidence = 1.0 - baseline_ratio
            
            self.drift_findings.append(DriftFinding(
                drift_type=DriftType.KEY_EXCHANGE,
                title="Unexpected Key Exchange Drift",
                severity=severity,
                description=(
                    f"Session used key exchange '{observed}' while baseline shows '{dominant}' "
                    f"({baseline.key_exchange_dist.get(dominant, 0)}/{baseline.total_sessions} sessions). "
                    f"{'Loss of forward secrecy detected.' if is_downgrade else ''}"
                ),
                baseline_value=dominant,
                observed_value=observed,
                confidence=confidence,
                server_ip=session.server_ip,
                server_port=session.server_port,
                protocol=session.protocol,
                stream_id=session.stream_id,
                evidence_frames=session.evidence_frames,
            ))
    
    def _check_starttls_drift(self, session: SessionAnalysis, baseline: ServerBaseline):
        if baseline.starttls_total == 0:
            return
        
        if session.starttls_offered and not session.upgrade_successful:
            baseline_rate = baseline.starttls_success_rate
            
            if baseline_rate > 0.9:
                self.drift_findings.append(DriftFinding(
                    drift_type=DriftType.STARTTLS,
                    title="STARTTLS Upgrade Failure Drift",
                    severity=FindingSeverity.HIGH,
                    description=(
                        f"STARTTLS was offered but upgrade failed. Baseline shows "
                        f"{baseline.starttls_success_rate:.1%} success rate "
                        f"({baseline.starttls_success_count}/{baseline.starttls_total} sessions)."
                    ),
                    baseline_value=f"Success rate: {baseline_rate:.1%}",
                    observed_value="STARTTLS offered but upgrade failed",
                    confidence=0.9,
                    server_ip=session.server_ip,
                    server_port=session.server_port,
                    protocol=session.protocol,
                    stream_id=session.stream_id,
                    evidence_frames=session.evidence_frames,
                ))
    
    def _is_tls_downgrade(self, observed: str, baseline: str) -> bool:
        version_order = {
            "SSL 3.0": 0,
            "TLS 1.0": 1,
            "TLS 1.1": 2,
            "TLS 1.2": 3,
            "TLS 1.3": 4,
        }
        return version_order.get(observed, 0) < version_order.get(baseline, 0)
    
    def _is_weak_cipher(self, cipher: str) -> bool:
        weak_patterns = ["RC4", "DES", "3DES", "EXPORT", "NULL", "ANON", "MD5"]
        return any(p in cipher.upper() for p in weak_patterns)
    
    def _is_cipher_downgrade(self, observed: str, baseline: str) -> bool:
        if self._is_weak_cipher(observed) and not self._is_weak_cipher(baseline):
            return True
        if "CBC" in observed.upper() and "GCM" in baseline.upper():
            return True
        return False