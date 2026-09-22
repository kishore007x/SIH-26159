"""End-to-end analysis orchestration and JSON-backed MVP storage."""

from __future__ import annotations

import asyncio
import html
import json
import logging
import math
import threading
import uuid
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from backend.app.config import settings
from backend.app.parsers.certificate_parser import CertificateParser
from backend.app.parsers.smtp_parser import SmtpParser
from backend.app.parsers.imap_parser import ImapParser
from backend.app.parsers.pop3_parser import Pop3Parser
from backend.app.parsers.pcap_parser import parse_pcap_async
from backend.app.parsers.protocol_detector import ProtocolDetector
from backend.app.parsers.tcp_stream import TcpStreamReconstructor
from backend.app.parsers.tls_parser import TlsParser
from backend.app.utils.hashing import compute_file_hash, sanitize_filename
from backend.app.utils.tshark import TsharkError, TsharkNotFoundError, get_tshark_version

logger = logging.getLogger(__name__)

SIMULATED_NOTE = "Synthetic demonstration data; not derived from a packet capture."
ALLOWED_EXTENSIONS = {".pcap", ".pcapng", ".cap"}


class AnalysisStore:
    """Small JSON-backed store suitable for a local, single-process MVP."""

    def __init__(self, root: str):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._items: Dict[int, Dict[str, Any]] = {}
        self._next_id = self._discover_next_id()

    def _discover_next_id(self) -> int:
        ids = []
        for path in self.root.glob("analysis_*.json"):
            try:
                ids.append(int(path.stem.split("_")[1]))
            except (IndexError, ValueError):
                continue
        return max(ids, default=0) + 1

    def create(self, filename: str, file_size: int, file_hash: str, source: str, evidence_type: str) -> Dict[str, Any]:
        with self._lock:
            analysis_id = self._next_id
            self._next_id += 1
        now = datetime.now(timezone.utc).isoformat()
        item = {
            "analysis": {
                "id": analysis_id,
                "filename": filename,
                "file_size": file_size,
                "file_hash": file_hash,
                "status": "pending",
                "source": source,
                "created_at": now,
                "completed_at": None,
                "error_message": None,
            },
            "evidence": {
                "type": evidence_type,
                "is_simulated": source == "simulated",
                "tshark_version": None,
                "packet_count": 0,
                "capture_hash": file_hash,
                "note": SIMULATED_NOTE if source == "simulated" else None,
            },
            "summary": empty_summary(),
            "sessions": [],
            "findings": [],
            "certificates": [],
            "baselines": [],
            "drift": [],
            "limitations": [],
        }
        self.save(item)
        return item

    def save(self, item: Dict[str, Any]) -> Dict[str, Any]:
        analysis_id = int(item["analysis"]["id"])
        path = self.root / f"analysis_{analysis_id}.json"
        with self._lock:
            path.write_text(json.dumps(item, indent=2, default=str), encoding="utf-8")
            self._items[analysis_id] = item
        return item

    def get(self, analysis_id: int) -> Optional[Dict[str, Any]]:
        if analysis_id in self._items:
            return self._items[analysis_id]
        path = self.root / f"analysis_{analysis_id}.json"
        if not path.exists():
            return None
        try:
            item = json.loads(path.read_text(encoding="utf-8"))
            self._items[analysis_id] = item
            return item
        except json.JSONDecodeError:
            return None

    def list(self) -> List[Dict[str, Any]]:
        items = []
        for path in sorted(self.root.glob("analysis_*.json"), reverse=True):
            try:
                item = self.get(int(path.stem.split("_")[1]))
                if item:
                    items.append(item)
            except (IndexError, ValueError):
                continue
        return items


STORE = AnalysisStore(settings.reports_dir)


def empty_summary() -> Dict[str, Any]:
    return {
        "total_sessions": 0,
        "protocols": {"SMTP": 0, "IMAP": 0, "POP3": 0},
        "tls_sessions": 0,
        "starttls_sessions": 0,
        "weak_crypto_findings": 0,
        "certificate_findings": 0,
        "anomalous_sessions": 0,
        "severity_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
        "risk_score": 0.0,
        "risk_level": "LOW",
    }


def risk_level(score: float) -> str:
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"


def _set_status(item: Dict[str, Any], status: str, error: Optional[str] = None) -> None:
    item["analysis"]["status"] = status
    item["analysis"]["error_message"] = error
    if status in {"completed", "failed"}:
        item["analysis"]["completed_at"] = datetime.now(timezone.utc).isoformat()
    STORE.save(item)


def _value(packet: Any, key: str, default: Any = None) -> Any:
    if isinstance(packet, dict):
        return packet.get(key, default)
    return getattr(packet, key, default)


def _number(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _iso_timestamp(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    return datetime.fromtimestamp(_number(value), timezone.utc).isoformat()


def _finding(
    finding_id: str,
    title: str,
    severity: str,
    category: str,
    description: str,
    recommendation: str,
    confidence: float,
    session_id: Optional[int],
    frames: List[int],
    server: Optional[str],
    observed: Optional[str] = None,
    baseline: Optional[str] = None,
    impact: str = "May weaken confidentiality or increase exposure of email traffic.",
    technical: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    return {
        "id": finding_id,
        "title": title,
        "severity": severity,
        "category": category,
        "description": description,
        "impact": impact,
        "recommendation": recommendation,
        "confidence": round(confidence, 2),
        "session_id": session_id,
        "evidence_frames": frames,
        "evidence_type": "tshark",
        "affected_server": server,
        "observed_value": observed,
        "baseline_value": baseline,
        "technical_evidence": technical or {},
    }


def _session_risk(session: Dict[str, Any]) -> tuple[float, List[Dict[str, Any]]]:
    score = 0.0
    findings: List[Dict[str, Any]] = []
    sid = session["id"]
    frames = session.get("evidence_frames", [])
    server = session.get("server")
    version = session.get("tls_version")
    cipher = (session.get("cipher_suite") or "").upper()
    key_exchange = (session.get("key_exchange") or "").upper()

    if version in {"SSL 3.0", "TLS 1.0"}:
        score += 24
        findings.append(_finding("TLS-VERSION", "Deprecated TLS version", "HIGH", "TLS_VERSION", f"The session negotiated {version}.", "Require TLS 1.2 or newer, preferably TLS 1.3.", session["confidence"], sid, frames, server, version))
    elif version == "TLS 1.1":
        score += 16
        findings.append(_finding("TLS-VERSION", "Legacy TLS version", "HIGH", "TLS_VERSION", "TLS 1.1 is no longer a recommended protocol version.", "Disable TLS 1.1 and require TLS 1.2 or newer.", session["confidence"], sid, frames, server, version))
    elif not version and not session.get("implicit_tls"):
        score += 16

    if any(token in cipher for token in ("RC4", "3DES", "DES_", "EXPORT", "NULL", "ANON")):
        score += 24
        findings.append(_finding("CIPHER", "Weak or legacy cipher", "HIGH", "CIPHER", f"The observed cipher was {session.get('cipher_suite') or 'not observed'}.", "Disable legacy ciphers and prefer AEAD suites such as AES-GCM or ChaCha20-Poly1305.", session["confidence"], sid, frames, server, session.get("cipher_suite")))
    elif cipher and not any(token in cipher for token in ("GCM", "CHACHA20")):
        score += 8

    if key_exchange and not any(token in key_exchange for token in ("ECDHE", "DHE", "X25519")):
        score += 15
        findings.append(_finding("KEX", "Forward secrecy unavailable", "HIGH", "FORWARD_SECRECY", f"The observed key exchange was {session.get('key_exchange')}.", "Prefer ephemeral ECDHE or DHE key exchange.", session["confidence"], sid, frames, server, session.get("key_exchange")))

    if session.get("certificate_expired"):
        score += 22
        findings.append(_finding("CERTIFICATE", "Expired certificate", "HIGH", "CERTIFICATE", "The certificate validity window has ended.", "Replace the certificate and validate the chain before accepting mail traffic.", session["confidence"], sid, frames, server))

    if session.get("auth_before_tls") or session.get("plaintext_after_offer"):
        score += 24
        findings.append(_finding("STARTTLS", "Plaintext activity around STARTTLS", "CRITICAL", "STARTTLS", "Authentication or mail activity was observed before a successful TLS transition.", "Require TLS before authentication and reject insecure plaintext fallback.", session["confidence"], sid, frames, server, "plaintext after STARTTLS offer", impact="Credentials or message metadata may be exposed to passive observers."))
    elif session.get("starttls_offered") and not session.get("upgrade_successful"):
        score += 16
        findings.append(_finding("STARTTLS", "STARTTLS upgrade failed", "HIGH", "STARTTLS", "STARTTLS was offered but a successful TLS transition was not observed.", "Investigate the failed upgrade and enforce TLS before authentication.", session["confidence"], sid, frames, server))

    return min(score, 100), findings


def _build_summary(sessions: List[Dict[str, Any]], findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    summary = empty_summary()
    summary["total_sessions"] = len(sessions)
    for session in sessions:
        protocol = session.get("protocol")
        if protocol in summary["protocols"]:
            summary["protocols"][protocol] += 1
        if session.get("tls_version"):
            summary["tls_sessions"] += 1
        if session.get("starttls_offered"):
            summary["starttls_sessions"] += 1
        if session.get("is_anomalous"):
            summary["anomalous_sessions"] += 1
    for finding in findings:
        severity = finding["severity"]
        summary["severity_counts"][severity] = summary["severity_counts"].get(severity, 0) + 1
        if finding["category"] in {"CIPHER", "TLS_VERSION", "FORWARD_SECRECY"}:
            summary["weak_crypto_findings"] += 1
        if finding["category"] == "CERTIFICATE":
            summary["certificate_findings"] += 1
    if sessions:
        summary["risk_score"] = round(max(item.get("risk_score", 0) for item in sessions), 1)
    summary["risk_level"] = risk_level(summary["risk_score"])
    return summary


def _build_baselines(sessions: List[Dict[str, Any]]) -> tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    groups: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for session in sessions:
        key = f"{session.get('server')}:{session.get('protocol')}"
        groups[key].append(session)
    baselines = []
    drift = []
    for key, group in groups.items():
        if len(group) < 3:
            continue
        version_dist = Counter(s.get("tls_version") for s in group if s.get("tls_version"))
        cipher_dist = Counter(s.get("cipher_suite") for s in group if s.get("cipher_suite"))
        dominant_version = version_dist.most_common(1)[0][0] if version_dist else "Not observed"
        dominant_cipher = cipher_dist.most_common(1)[0][0] if cipher_dist else "Not observed"
        baseline = {"server": group[0].get("server"), "protocol": group[0].get("protocol"), "total_sessions": len(group), "tls_version_distribution": dict(version_dist), "cipher_distribution": dict(cipher_dist), "dominant_tls_version": dominant_version, "dominant_cipher": dominant_cipher}
        baselines.append(baseline)
        for session in group:
            if session.get("tls_version") and session["tls_version"] != dominant_version and version_dist[session["tls_version"]] / len(group) < 0.2:
                drift.append(_finding("DRIFT-TLS", "Cryptographic version drift", "HIGH", "DRIFT", f"Observed {session['tls_version']} differs from the {dominant_version} baseline.", "Investigate the session and enforce the established modern TLS policy.", session["confidence"], session["id"], session.get("evidence_frames", []), session.get("server"), session["tls_version"], dominant_version))
            if session.get("cipher_suite") and session["cipher_suite"] != dominant_cipher and cipher_dist[session["cipher_suite"]] / len(group) < 0.2:
                drift.append(_finding("DRIFT-CIPHER", "Cipher behavior drift", "HIGH", "DRIFT", f"Observed {session['cipher_suite']} differs from the {dominant_cipher} baseline.", "Investigate the session and remove legacy cipher fallback.", session["confidence"], session["id"], session.get("evidence_frames", []), session.get("server"), session["cipher_suite"], dominant_cipher))
    return baselines, drift


def _apply_anomaly_scores(sessions: List[Dict[str, Any]]) -> None:
    if len(sessions) < 2:
        return
    try:
        import numpy as np
        from sklearn.ensemble import IsolationForest
        features = []
        for session in sessions:
            features.append([
                {"SSL 3.0": 0, "TLS 1.0": .25, "TLS 1.1": .5, "TLS 1.2": .75, "TLS 1.3": 1}.get(session.get("tls_version"), 0),
                session.get("cipher_strength", 0), session.get("key_exchange_strength", 0),
                float(session.get("forward_secrecy", False)), float(session.get("handshake_complete", False)),
                float(session.get("auth_before_tls", False)), float(session.get("plaintext_after_offer", False)),
            ])
        model = IsolationForest(n_estimators=100, contamination=min(.2, max(1 / len(sessions), .05)), random_state=42)
        values = np.asarray(features, dtype=float)
        predictions = model.fit_predict(values)
        scores = model.decision_function(values)
        minimum, maximum = float(scores.min()), float(scores.max())
        for session, prediction, score in zip(sessions, predictions, scores):
            normalized = 1 - ((float(score) - minimum) / (maximum - minimum or 1))
            session["anomaly_score"] = round(max(0, min(1, normalized)), 2)
            session["is_anomalous"] = bool(prediction == -1)
    except Exception as error:
        logger.warning("Anomaly model unavailable: %s", error)


def _finalize(item: Dict[str, Any], sessions: List[Dict[str, Any]], findings: List[Dict[str, Any]], baselines: List[Dict[str, Any]], drift: List[Dict[str, Any]], limitations: List[str]) -> Dict[str, Any]:
    for finding in findings + drift:
        finding["evidence_type"] = item["evidence"]["type"]
    findings.extend(drift)
    item["sessions"] = sessions
    item["findings"] = findings
    item["baselines"] = baselines
    item["drift"] = drift
    item["summary"] = _build_summary(sessions, findings)
    item["limitations"] = limitations
    _set_status(item, "completed")
    return item


async def run_real_analysis(item: Dict[str, Any], capture_path: str) -> None:
    _set_status(item, "processing")
    try:
        parsed = await parse_pcap_async(capture_path)
        item["evidence"]["tshark_version"] = parsed["metadata"].get("tshark_version")
        item["evidence"]["packet_count"] = parsed["metadata"].get("packet_count", 0)
        reconstructed = TcpStreamReconstructor().reconstruct(parsed["tcp_streams"])
        detected = ProtocolDetector().detect_from_packets(parsed["tcp_streams"], parsed["smtp_packets"], parsed["imap_packets"], parsed["pop3_packets"])
        tls_parser = TlsParser()
        cert_parser = CertificateParser()
        smtp_parser = SmtpParser()
        imap_parser = ImapParser()
        pop3_parser = Pop3Parser()
        certs = cert_parser.parse_from_tshark(parsed["certificates"])
        item["certificates"] = [
            {
                "subject": cert.subject,
                "issuer": cert.issuer,
                "serial_number": cert.serial_number,
                "not_before": cert.not_before.isoformat(),
                "not_after": cert.not_after.isoformat(),
                "is_expired": cert.is_expired,
                "is_not_yet_valid": cert.is_not_yet_valid,
                "public_key_algorithm": cert.public_key_algorithm,
                "public_key_size": cert.public_key_size,
                "signature_algorithm": cert.signature_algorithm,
                "san": cert.san,
                "is_self_signed": cert.is_self_signed,
                "fingerprint_sha256": cert.fingerprint_sha256,
            }
            for cert in certs
        ]
        sessions: List[Dict[str, Any]] = []
        findings: List[Dict[str, Any]] = []
        for stream_id, protocol_info in detected.items():
            stream = reconstructed.get(stream_id)
            if not stream:
                continue
            tls_packets = [packet for packet in parsed["tls_handshakes"] if int(packet.get("tcp_stream", -1)) == stream_id]
            tls_session = tls_parser.parse(stream_id, tls_packets) if tls_packets else None
            protocol_packets = []
            if protocol_info.protocol.value == "SMTP":
                protocol_packets = [packet for packet in parsed["smtp_packets"] if int(packet.get("tcp_stream", -1)) == stream_id]
                protocol_session = smtp_parser.parse(stream_id, protocol_packets)
            elif protocol_info.protocol.value == "IMAP":
                protocol_packets = [packet for packet in parsed["imap_packets"] if int(packet.get("tcp_stream", -1)) == stream_id]
                protocol_session = imap_parser.parse(stream_id, protocol_packets)
            else:
                protocol_packets = [packet for packet in parsed["pop3_packets"] if int(packet.get("tcp_stream", -1)) == stream_id]
                protocol_session = pop3_parser.parse(stream_id, protocol_packets)
            version = TlsParser.parse_version(tls_session.negotiated_version) if tls_session else None
            cert = certs[0] if certs else None
            session = {
                "id": stream_id, "stream_id": stream_id, "protocol": protocol_info.protocol.value,
                "client": f"{stream.client_ip}:{stream.client_port}", "server": f"{stream.server_ip}:{stream.server_port}",
                "client_ip": stream.client_ip, "server_ip": stream.server_ip, "server_port": stream.server_port,
                "start_time": _iso_timestamp(stream.start_time), "end_time": _iso_timestamp(stream.end_time),
                "duration": stream.duration, "packet_count": stream.packet_count, "byte_count": stream.byte_count,
                "tls_version": version, "cipher_suite": tls_session.negotiated_cipher if tls_session else None,
                "key_exchange": tls_session.negotiated_key_exchange if tls_session else None,
                "signature_algorithm": tls_session.negotiated_signature_alg if tls_session else None,
                "sni": tls_session.sni if tls_session else None, "handshake_complete": bool(tls_session and tls_session.handshake_complete),
                "evidence_frames": stream.frame_numbers, "confidence": .95 if tls_session and tls_session.handshake_complete else .55,
                "starttls_offered": bool(getattr(protocol_session, "starttls_advertised", False) or getattr(protocol_session, "stls_advertised", False)),
                "starttls_requested": bool(getattr(protocol_session, "starttls_requested", False) or getattr(protocol_session, "stls_requested", False)),
                "tls_started": bool(tls_session or getattr(protocol_session, "tls_started", False)),
                "upgrade_successful": bool(getattr(protocol_session, "upgrade_successful", False) or tls_session),
                "plaintext_after_offer": bool(getattr(protocol_session, "plaintext_after_offer", False)),
                "auth_before_tls": bool(getattr(protocol_session, "auth_before_tls", False)), "implicit_tls": stream.server_port in {465, 993, 995},
                "certificate_subject": cert.subject if cert else None, "certificate_expired": cert.is_expired if cert else False,
                "cipher_strength": TlsParser.get_cipher_strength(tls_session.negotiated_cipher if tls_session else None),
                "key_exchange_strength": TlsParser.get_key_exchange_strength(tls_session.negotiated_key_exchange if tls_session else None),
                "forward_secrecy": TlsParser.has_forward_secrecy(tls_session.negotiated_key_exchange if tls_session else None),
                "anomaly_score": 0.0, "is_anomalous": False, "risk_score": 0.0, "risk_level": "LOW",
            }
            session["risk_score"], session_findings = _session_risk(session)
            session["risk_level"] = risk_level(session["risk_score"])
            findings.extend(session_findings)
            if cert:
                for certificate_finding in cert_parser.analyze_certificate(cert)["findings"]:
                    findings.append(_finding(
                        f"CERT-{certificate_finding['type']}",
                        f"Certificate {certificate_finding['type'].replace('_', ' ').lower()}",
                        certificate_finding["severity"],
                        "CERTIFICATE",
                        certificate_finding["message"],
                        "Replace or reconfigure the certificate and validate its cryptographic properties before accepting mail traffic.",
                        session["confidence"], session["id"], session["evidence_frames"], session["server"],
                    ))
            sessions.append(session)
        _apply_anomaly_scores(sessions)
        for session in sessions:
            if session.get("is_anomalous"):
                findings.append(_finding("ANOMALY", "Anomalous cryptographic behavior", "MEDIUM", "ANOMALY", "This session differs from the local behavioral model trained on observed sessions.", "Investigate the session alongside its packet evidence; this is an anomaly signal, not proof of attack.", session["confidence"], session["id"], session["evidence_frames"], session["server"], str(session.get("anomaly_score"))))
        baseline, drift = _build_baselines(sessions)
        _finalize(item, sessions, findings, baseline, drift, ["Only protocols and fields exposed by tshark can be assessed."] if not sessions else [])
    except (TsharkNotFoundError, TsharkError) as error:
        _set_status(item, "failed", f"Packet analysis unavailable: {error}")
    except Exception as error:
        logger.exception("Analysis failed")
        _set_status(item, "failed", f"Analysis failed: {error}")
    finally:
        Path(capture_path).unlink(missing_ok=True)


def create_demo_analysis() -> Dict[str, Any]:
    item = STORE.create("synthetic-demo.pcap", 0, "simulated", "simulated", "simulated")
    sessions = []
    for index in range(20):
        sessions.append(_demo_session(index + 1, "TLS 1.3", "TLS_AES_128_GCM_SHA256", "ECDHE/X25519", False, False, 900000 + index))
    sessions.append(_demo_session(21, "TLS 1.0", "TLS_RSA_WITH_3DES_EDE_CBC_SHA", "RSA", True, False, 900021))
    sessions.append(_demo_session(22, "TLS 1.3", "TLS_AES_128_GCM_SHA256", "ECDHE/X25519", False, True, 900022))
    findings = []
    for session in sessions:
        session["risk_score"], session_findings = _session_risk(session)
        session["risk_level"] = risk_level(session["risk_score"])
        findings.extend(session_findings)
    _apply_anomaly_scores(sessions)
    for session in sessions:
        if session["is_anomalous"]:
            findings.append(_finding("ANOMALY", "Anomalous cryptographic behavior", "MEDIUM", "ANOMALY", "The local behavioral model marked this session as unusual relative to the synthetic baseline.", "Investigate the session and compare it with real packet evidence before drawing conclusions.", .91, session["id"], session["evidence_frames"], session["server"], str(session["anomaly_score"])))
    baselines, drift = _build_baselines(sessions)
    item["certificates"] = [{"id": 1, "subject": "CN=mail.demo.local", "issuer": "CN=Demo CA", "is_expired": True, "public_key_algorithm": "RSA", "public_key_size": 1024, "signature_algorithm": "sha1WithRSAEncryption"}]
    return _finalize(item, sessions, findings, baselines, drift, ["Synthetic data is for demonstration only; frame references use the 900000+ simulated range."])


def _demo_session(index: int, version: str, cipher: str, key_exchange: str, expired: bool, starttls_failed: bool, frame: int) -> Dict[str, Any]:
    protocol = "SMTP" if index % 3 == 0 else ("IMAP" if index % 3 == 1 else "POP3")
    offered = protocol == "SMTP" or protocol == "IMAP"
    return {
        "id": index, "stream_id": index, "protocol": protocol, "client": "10.0.0.10:42000", "server": "10.0.0.20:587", "server_ip": "10.0.0.20", "server_port": 587,
        "duration": 1.2, "packet_count": 12, "byte_count": 2048, "tls_version": version, "cipher_suite": cipher, "key_exchange": key_exchange, "signature_algorithm": "RSA-PSS",
        "sni": "mail.demo.local", "handshake_complete": not starttls_failed, "evidence_frames": [frame, frame + 1, frame + 2], "confidence": .94,
        "starttls_offered": offered, "starttls_requested": offered and not starttls_failed, "tls_started": not starttls_failed, "upgrade_successful": not starttls_failed,
        "plaintext_after_offer": starttls_failed, "auth_before_tls": starttls_failed, "implicit_tls": False, "certificate_subject": "CN=mail.demo.local", "certificate_expired": expired,
        "cipher_strength": 1.0 if "GCM" in cipher else .2, "key_exchange_strength": 1.0 if "ECDHE" in key_exchange else .2, "forward_secrecy": "ECDHE" in key_exchange,
        "anomaly_score": 0.0, "is_anomalous": False, "risk_score": 0.0, "risk_level": "LOW",
    }


def build_html_report(item: Dict[str, Any]) -> str:
    summary = item["summary"]
    safe = lambda value: html.escape(str(value or "Not observed"))
    rows = "".join(f"<tr><td>{safe(finding['severity'])}</td><td>{safe(finding['title'])}</td><td>{safe(finding.get('affected_server'))}</td><td>{finding['confidence']:.0%}</td></tr>" for finding in item["findings"])
    note = safe(item["evidence"].get("note")) if item["evidence"].get("note") else "Observed from the uploaded capture."
    return f"""<!doctype html><html><head><meta charset='utf-8'><title>SecureMailScope report</title><style>body{{font-family:Arial;background:#101820;color:#e8eef2;padding:32px}}table{{border-collapse:collapse;width:100%}}td,th{{padding:10px;border:1px solid #34434b;text-align:left}}.accent{{color:#d9fa70}}</style></head><body><h1>SecureMailScope forensic report</h1><p>Source: <strong class='accent'>{safe(item['analysis']['source'])}</strong> | File: {safe(item['analysis']['filename'])}</p><p>{note}</p><h2>Risk: {summary['risk_score']} ({safe(summary['risk_level'])})</h2><p>Sessions: {summary['total_sessions']} | TLS: {summary['tls_sessions']} | Anomalies: {summary['anomalous_sessions']}</p><table><thead><tr><th>Severity</th><th>Finding</th><th>Server</th><th>Confidence</th></tr></thead><tbody>{rows or '<tr><td colspan="4">No findings observed</td></tr>'}</tbody></table></body></html>"""
