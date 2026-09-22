import logging
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519, ed448
import hashlib

logger = logging.getLogger(__name__)


@dataclass
class ParsedCertificate:
    subject: str
    issuer: str
    serial_number: str
    not_before: datetime
    not_after: datetime
    is_expired: bool
    is_not_yet_valid: bool
    public_key_algorithm: str
    public_key_size: int
    signature_algorithm: str
    san: List[str] = field(default_factory=list)
    is_self_signed: bool = False
    fingerprint_sha256: str = ""
    pem_data: str = ""
    chain_info: Dict[str, Any] = field(default_factory=dict)


class CertificateParser:
    def __init__(self):
        self.certificates: Dict[str, ParsedCertificate] = {}
    
    def parse_from_tshark(self, cert_packets: List[Dict]) -> List[ParsedCertificate]:
        certs = []
        
        for packet in cert_packets:
            try:
                cert = self._parse_certificate_packet(packet)
                if cert:
                    certs.append(cert)
            except Exception as e:
                logger.warning(f"Failed to parse certificate from packet: {e}")
                continue
        
        return certs
    
    def _parse_certificate_packet(self, packet: Dict) -> Optional[ParsedCertificate]:
        subject_parts = []
        issuer_parts = []
        
        utf8_strings = packet.get("x509sat_uTF8String") or packet.get("x509sat.uTF8String")
        if utf8_strings:
            if isinstance(utf8_strings, list):
                for s in utf8_strings:
                    if "=" in s:
                        if not issuer_parts or len(issuer_parts) < len(subject_parts):
                            subject_parts.append(s)
                        else:
                            issuer_parts.append(s)
        
        printable_strings = packet.get("x509sat_printableString") or packet.get("x509sat.printableString")
        if printable_strings:
            if isinstance(printable_strings, list):
                for s in printable_strings:
                    if "=" in s:
                        if not issuer_parts or len(issuer_parts) < len(subject_parts):
                            subject_parts.append(s)
                        else:
                            issuer_parts.append(s)
        
        san = []
        dns_names = packet.get("x509ce_dNSName") or packet.get("x509ce.dNSName")
        if dns_names:
            if isinstance(dns_names, list):
                san = [str(n) for n in dns_names]
            else:
                san = [str(dns_names)]
        
        serial = packet.get("x509cert_serialNumber") or packet.get("x509cert.serialNumber")
        not_before_str = packet.get("x509cert_notBefore") or packet.get("x509cert.notBefore")
        not_after_str = packet.get("x509cert_notAfter") or packet.get("x509cert.notAfter")
        pubkey_algo = packet.get("x509cert_publicKeyAlgorithm") or packet.get("x509cert.publicKeyAlgorithm")
        pubkey_len = packet.get("x509cert_publicKeyLength") or packet.get("x509cert.publicKeyLength")
        sig_algo = packet.get("x509cert_signatureAlgorithm") or packet.get("x509cert.signatureAlgorithm")
        
        if not subject_parts and not serial:
            return None
        
        subject = ", ".join(subject_parts) if subject_parts else "Unknown"
        issuer = ", ".join(issuer_parts) if issuer_parts else "Unknown"
        
        try:
            not_before = self._parse_x509_time(not_before_str) if not_before_str else datetime.utcnow()
            not_after = self._parse_x509_time(not_after_str) if not_after_str else datetime.utcnow()
        except Exception:
            not_before = datetime.utcnow()
            not_after = datetime.utcnow()
        
        now = datetime.utcnow()
        is_expired = not_after < now
        is_not_yet_valid = not_before > now
        
        pubkey_size = int(pubkey_len) if pubkey_len else 0
        
        fingerprint = hashlib.sha256(subject.encode()).hexdigest()[:32]
        
        is_self_signed = subject == issuer
        
        return ParsedCertificate(
            subject=subject,
            issuer=issuer,
            serial_number=str(serial) if serial else "",
            not_before=not_before,
            not_after=not_after,
            is_expired=is_expired,
            is_not_yet_valid=is_not_yet_valid,
            public_key_algorithm=str(pubkey_algo) if pubkey_algo else "Unknown",
            public_key_size=pubkey_size,
            signature_algorithm=str(sig_algo) if sig_algo else "Unknown",
            san=san,
            is_self_signed=is_self_signed,
            fingerprint_sha256=fingerprint,
        )
    
    def _parse_x509_time(self, time_str: str) -> datetime:
        formats = [
            "%Y%m%d%H%M%SZ",
            "%y%m%d%H%M%SZ",
            "%b %d %H:%M:%S %Y %Z",
            "%Y-%m-%d %H:%M:%S",
        ]
        
        for fmt in formats:
            try:
                return datetime.strptime(time_str, fmt)
            except ValueError:
                continue
        
        raise ValueError(f"Unable to parse time: {time_str}")
    
    def parse_pem(self, pem_data: str) -> Optional[ParsedCertificate]:
        try:
            cert = x509.load_pem_x509_certificate(pem_data.encode())
            return self._parse_cryptography_cert(cert, pem_data)
        except Exception as e:
            logger.warning(f"Failed to parse PEM certificate: {e}")
            return None
    
    def _parse_cryptography_cert(self, cert: x509.Certificate, pem_data: str) -> ParsedCertificate:
        subject = cert.subject.rfc4514_string()
        issuer = cert.issuer.rfc4514_string()
        
        san = []
        try:
            san_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            san = [name.value for name in san_ext.value]
        except x509.ExtensionNotFound:
            pass
        
        pubkey = cert.public_key()
        pubkey_algo = type(pubkey).__name__
        pubkey_size = 0
        
        if isinstance(pubkey, rsa.RSAPublicKey):
            pubkey_size = pubkey.key_size
        elif isinstance(pubkey, ec.EllipticCurvePublicKey):
            pubkey_size = pubkey.curve.key_size
        elif isinstance(pubkey, dsa.DSAPublicKey):
            pubkey_size = pubkey.key_size
        elif isinstance(pubkey, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            pubkey_size = 256 if isinstance(pubkey, ed25519.Ed25519PublicKey) else 448
        
        sig_algo = cert.signature_algorithm_oid._name
        
        fingerprint = cert.fingerprint(hashes.SHA256()).hex()[:32]
        is_self_signed = subject == issuer
        
        return ParsedCertificate(
            subject=subject,
            issuer=issuer,
            serial_number=str(cert.serial_number),
            not_before=cert.not_valid_before_utc,
            not_after=cert.not_valid_after_utc,
            is_expired=cert.not_valid_after_utc < datetime.utcnow(),
            is_not_yet_valid=cert.not_valid_before_utc > datetime.utcnow(),
            public_key_algorithm=pubkey_algo,
            public_key_size=pubkey_size,
            signature_algorithm=sig_algo,
            san=san,
            is_self_signed=is_self_signed,
            fingerprint_sha256=fingerprint,
            pem_data=pem_data,
        )
    
    def analyze_certificate(self, cert: ParsedCertificate) -> Dict[str, Any]:
        findings = []
        
        if cert.is_expired:
            findings.append({
                "type": "EXPIRED",
                "severity": "HIGH",
                "message": f"Certificate expired on {cert.not_after.isoformat()}",
            })
        
        if cert.is_not_yet_valid:
            findings.append({
                "type": "NOT_YET_VALID",
                "severity": "MEDIUM",
                "message": f"Certificate not yet valid until {cert.not_before.isoformat()}",
            })
        
        if cert.is_self_signed:
            findings.append({
                "type": "SELF_SIGNED",
                "severity": "MEDIUM",
                "message": "Certificate is self-signed",
            })
        
        if cert.public_key_size > 0:
            if "RSA" in cert.public_key_algorithm.upper() and cert.public_key_size < 2048:
                findings.append({
                    "type": "WEAK_KEY",
                    "severity": "HIGH",
                    "message": f"RSA key size {cert.public_key_size} bits is below 2048-bit minimum",
                })
            elif "ECDSA" in cert.public_key_algorithm.upper() and cert.public_key_size < 224:
                findings.append({
                    "type": "WEAK_KEY",
                    "severity": "HIGH",
                    "message": f"ECDSA key size {cert.public_key_size} bits is below 224-bit minimum",
                })
        
        weak_sig_algos = ["MD5", "SHA1", "SHA-1"]
        if any(weak in cert.signature_algorithm.upper() for weak in weak_sig_algos):
            findings.append({
                "type": "WEAK_SIGNATURE",
                "severity": "HIGH",
                "message": f"Weak signature algorithm: {cert.signature_algorithm}",
            })
        
        return {
            "certificate": cert,
            "findings": findings,
            "risk_score": self._calculate_risk_score(findings),
        }
    
    def _calculate_risk_score(self, findings: List[Dict]) -> float:
        severity_scores = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 10, "LOW": 5, "INFO": 1}
        return min(sum(severity_scores.get(f["severity"], 0) for f in findings), 100)