import logging
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from enum import Enum

from backend.app.analysis.crypto_analyzer import SessionAnalysis
from backend.app.analysis.baseline_engine import ServerBaseline
from backend.app.analysis.drift_detector import DriftFinding
from backend.app.analysis.anomaly_detector import AnomalyResult
from backend.app.parsers.certificate_parser import ParsedCertificate
from backend.app.models.schemas import FindingSeverity, FindingCategory, ProtocolType, TLSVersion

logger = logging.getLogger(__name__)


@dataclass
class RiskComponent:
    name: str
    score: float
    max_score: float
    findings: List[str] = field(default_factory=list)


@dataclass
class RiskAssessment:
    overall_score: float
    risk_level: str
    components: Dict[str, RiskComponent]
    session_id: int


class RiskEngine:
    DEFAULT_WEIGHTS = {
        "protocol": 5,
        "tls_version": 20,
        "cipher": 20,
        "key_exchange": 15,
        "certificate": 15,
        "starttls": 15,
        "anomaly": 10,
    }
    
    RISK_THRESHOLDS = {
        "LOW": 24,
        "MEDIUM": 49,
        "HIGH": 74,
        "CRITICAL": 100,
    }
    
    def __init__(self, weights: Optional[Dict[str, float]] = None):
        self.weights = weights or self.DEFAULT_WEIGHTS.copy()
    
    def assess_session(
        self,
        session: SessionAnalysis,
        baseline: Optional[ServerBaseline] = None,
        drift_findings: Optional[List[DriftFinding]] = None,
        anomaly_result: Optional[AnomalyResult] = None,
        certificate: Optional[ParsedCertificate] = None,
    ) -> RiskAssessment:
        
        components = {}
        
        components["protocol"] = self._assess_protocol(session)
        components["tls_version"] = self._assess_tls_version(session, baseline, drift_findings)
        components["cipher"] = self._assess_cipher(session, baseline, drift_findings)
        components["key_exchange"] = self._assess_key_exchange(session, baseline, drift_findings)
        components["certificate"] = self._assess_certificate(session, certificate)
        components["starttls"] = self._assess_starttls(session, baseline, drift_findings)
        components["anomaly"] = self._assess_anomaly(anomaly_result)
        
        total_score = 0.0
        max_total = 0.0
        
        for name, component in components.items():
            weight = self.weights.get(name, 0)
            total_score += (component.score / component.max_score) * weight if component.max_score > 0 else 0
            max_total += weight
        
        overall_score = (total_score / max_total * 100) if max_total > 0 else 0
        overall_score = min(max(overall_score, 0), 100)
        
        risk_level = self._get_risk_level(overall_score)
        
        return RiskAssessment(
            overall_score=overall_score,
            risk_level=risk_level,
            components=components,
            session_id=session.stream_id,
        )
    
    def _assess_protocol(self, session: SessionAnalysis) -> RiskComponent:
        findings = []
        score = 0.0
        max_score = 5.0
        
        if session.protocol == ProtocolType.SMTP and session.server_port == 25:
            findings.append("SMTP on port 25 (plaintext by default)")
            score += 2
        
        if session.protocol == ProtocolType.IMAP and session.server_port == 143:
            findings.append("IMAP on port 143 (plaintext by default)")
            score += 2
        
        if session.protocol == ProtocolType.POP3 and session.server_port == 110:
            findings.append("POP3 on port 110 (plaintext by default)")
            score += 2
        
        return RiskComponent("protocol", score, max_score, findings)
    
    def _assess_tls_version(
        self,
        session: SessionAnalysis,
        baseline: Optional[ServerBaseline],
        drift_findings: Optional[List[DriftFinding]],
    ) -> RiskComponent:
        findings = []
        score = 0.0
        max_score = 20.0
        
        if not session.tls_version:
            findings.append("No TLS version negotiated (plaintext)")
            score = max_score
            return RiskComponent("tls_version", score, max_score, findings)
        
        version = session.tls_version.value
        
        if version in ["SSL 3.0", "TLS 1.0"]:
            findings.append(f"Deprecated TLS version: {version}")
            score += 15
        elif version == "TLS 1.1":
            findings.append(f"Legacy TLS version: {version}")
            score += 10
        elif version == "TLS 1.2":
            findings.append(f"Acceptable TLS version: {version}")
            score += 3
        elif version == "TLS 1.3":
            findings.append(f"Modern TLS version: {version}")
            score += 0
        
        if drift_findings:
            for drift in drift_findings:
                if drift.drift_type.value == "TLS_VERSION":
                    findings.append(f"TLS version drift from baseline: {drift.baseline_value} -> {drift.observed_value}")
                    score += 5
        
        return RiskComponent("tls_version", min(score, max_score), max_score, findings)
    
    def _assess_cipher(
        self,
        session: SessionAnalysis,
        baseline: Optional[ServerBaseline],
        drift_findings: Optional[List[DriftFinding]],
    ) -> RiskComponent:
        findings = []
        score = 0.0
        max_score = 20.0
        
        if not session.cipher_suite:
            findings.append("No cipher suite negotiated")
            score = max_score
            return RiskComponent("cipher", score, max_score, findings)
        
        cipher = session.cipher_suite.upper()
        
        if any(p in cipher for p in ["NULL", "EXPORT", "ANON"]):
            findings.append(f"Insecure cipher: {session.cipher_suite}")
            score += 20
        elif "RC4" in cipher:
            findings.append(f"Broken cipher (RC4): {session.cipher_suite}")
            score += 18
        elif "3DES" in cipher or "DES_" in cipher:
            findings.append(f"Weak cipher (3DES/DES): {session.cipher_suite}")
            score += 15
        elif "CBC" in cipher and "GCM" not in cipher and "CHACHA20" not in cipher:
            findings.append(f"Legacy CBC cipher: {session.cipher_suite}")
            score += 8
        elif "GCM" in cipher or "CHACHA20" in cipher:
            findings.append(f"Modern AEAD cipher: {session.cipher_suite}")
            score += 0
        else:
            findings.append(f"Cipher: {session.cipher_suite}")
            score += 5
        
        if drift_findings:
            for drift in drift_findings:
                if drift.drift_type.value == "CIPHER":
                    findings.append(f"Cipher drift from baseline: {drift.baseline_value} -> {drift.observed_value}")
                    score += 5
        
        return RiskComponent("cipher", min(score, max_score), max_score, findings)
    
    def _assess_key_exchange(
        self,
        session: SessionAnalysis,
        baseline: Optional[ServerBaseline],
        drift_findings: Optional[List[DriftFinding]],
    ) -> RiskComponent:
        findings = []
        score = 0.0
        max_score = 15.0
        
        if not session.key_exchange:
            findings.append("No key exchange information")
            score += 10
            return RiskComponent("key_exchange", score, max_score, findings)
        
        kex = session.key_exchange.upper()
        
        if "ECDHE" in kex or "DHE" in kex or "X25519" in kex:
            findings.append(f"Forward secrecy capable: {session.key_exchange}")
            score += 0
        elif "ECDH" in kex or "DH_" in kex:
            findings.append(f"Static DH key exchange (no forward secrecy): {session.key_exchange}")
            score += 10
        elif "RSA" in kex and "ECDHE" not in kex and "DHE" not in kex:
            findings.append(f"Static RSA key exchange (no forward secrecy): {session.key_exchange}")
            score += 12
        else:
            findings.append(f"Key exchange: {session.key_exchange}")
            score += 5
        
        if not session.forward_secrecy:
            findings.append("No forward secrecy")
            score += 5
        
        if drift_findings:
            for drift in drift_findings:
                if drift.drift_type.value == "KEY_EXCHANGE":
                    findings.append(f"Key exchange drift from baseline: {drift.baseline_value} -> {drift.observed_value}")
                    score += 5
        
        return RiskComponent("key_exchange", min(score, max_score), max_score, findings)
    
    def _assess_certificate(
        self,
        session: SessionAnalysis,
        certificate: Optional[ParsedCertificate],
    ) -> RiskComponent:
        findings = []
        score = 0.0
        max_score = 15.0
        
        if not certificate:
            findings.append("No certificate available for validation")
            score += 10
            return RiskComponent("certificate", score, max_score, findings)
        
        if certificate.is_expired:
            findings.append(f"Certificate expired on {certificate.not_after.isoformat()}")
            score += 15
        
        if certificate.is_not_yet_valid:
            findings.append(f"Certificate not yet valid until {certificate.not_before.isoformat()}")
            score += 10
        
        if certificate.is_self_signed:
            findings.append("Self-signed certificate")
            score += 8
        
        if "RSA" in certificate.public_key_algorithm.upper() and certificate.public_key_size < 2048:
            findings.append(f"Weak RSA key size: {certificate.public_key_size} bits")
            score += 10
        elif "ECDSA" in certificate.public_key_algorithm.upper() and certificate.public_key_size < 224:
            findings.append(f"Weak ECDSA key size: {certificate.public_key_size} bits")
            score += 10
        
        weak_sig = ["MD5", "SHA1", "SHA-1"]
        if any(w in certificate.signature_algorithm.upper() for w in weak_sig):
            findings.append(f"Weak signature algorithm: {certificate.signature_algorithm}")
            score += 8
        
        return RiskComponent("certificate", min(score, max_score), max_score, findings)
    
    def _assess_starttls(
        self,
        session: SessionAnalysis,
        baseline: Optional[ServerBaseline],
        drift_findings: Optional[List[DriftFinding]],
    ) -> RiskComponent:
        findings = []
        score = 0.0
        max_score = 15.0
        
        if not session.starttls_offered and not session.tls_started:
            if session.server_port in [25, 143, 110, 587]:
                findings.append("STARTTLS not offered on opportunistic TLS port")
                score += 10
            return RiskComponent("starttls", score, max_score, findings)
        
        if session.starttls_offered and not session.tls_started:
            findings.append("STARTTLS offered but not negotiated")
            score += 8
        
        if session.starttls_requested and not session.upgrade_successful:
            findings.append("STARTTLS requested but upgrade failed")
            score += 12
        
        if session.plaintext_after_offer:
            findings.append("Plaintext traffic continues after STARTTLS offer")
            score += 10
        
        if session.auth_before_tls:
            findings.append("Authentication attempted before TLS")
            score += 15
        
        if session.upgrade_successful:
            findings.append("STARTTLS upgrade successful")
            score += 0
        
        if drift_findings:
            for drift in drift_findings:
                if drift.drift_type.value == "STARTTLS":
                    findings.append(f"STARTTLS behavior drift: {drift.description}")
                    score += 5
        
        return RiskComponent("starttls", min(score, max_score), max_score, findings)
    
    def _assess_anomaly(self, anomaly_result: Optional[AnomalyResult]) -> RiskComponent:
        findings = []
        score = 0.0
        max_score = 10.0
        
        if not anomaly_result:
            findings.append("Anomaly detection not available")
            score += 2
            return RiskComponent("anomaly", score, max_score, findings)
        
        if anomaly_result.is_anomalous:
            findings.append(f"Anomalous cryptographic behavior (score: {anomaly_result.anomaly_score:.2f})")
            score += 8
        else:
            findings.append(f"Normal behavior (anomaly score: {anomaly_result.anomaly_score:.2f})")
            score += 0
        
        return RiskComponent("anomaly", min(score, max_score), max_score, findings)
    
    def _get_risk_level(self, score: float) -> str:
        if score >= self.RISK_THRESHOLDS["CRITICAL"]:
            return "CRITICAL"
        elif score >= self.RISK_THRESHOLDS["HIGH"]:
            return "HIGH"
        elif score >= self.RISK_THRESHOLDS["MEDIUM"]:
            return "MEDIUM"
        else:
            return "LOW"
    
    def assess_overall(self, assessments: List[RiskAssessment]) -> Dict[str, Any]:
        if not assessments:
            return {"overall_score": 0, "risk_level": "LOW", "session_count": 0}
        
        avg_score = sum(a.overall_score for a in assessments) / len(assessments)
        max_score = max(a.overall_score for a in assessments)
        
        risk_level = self._get_risk_level(max_score)
        
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for a in assessments:
            for comp in a.components.values():
                for f in comp.findings:
                    if "Deprecated" in f or "Broken" in f or "expired" in f.lower() or "Insecure" in f:
                        severity_counts["CRITICAL"] += 1
                    elif "Weak" in f or "Legacy" in f or "drift" in f.lower() or "no forward" in f.lower():
                        severity_counts["HIGH"] += 1
                    elif "not offered" in f.lower() or "not negotiated" in f.lower():
                        severity_counts["MEDIUM"] += 1
                    else:
                        severity_counts["LOW"] += 1
        
        return {
            "overall_score": round(avg_score, 1),
            "max_session_score": round(max_score, 1),
            "risk_level": risk_level,
            "session_count": len(assessments),
            "severity_counts": severity_counts,
        }