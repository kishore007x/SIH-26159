import subprocess
import shutil
import logging
from typing import List, Optional, Dict, Any
from pathlib import Path
import json

logger = logging.getLogger(__name__)


class TsharkError(Exception):
    pass


class TsharkNotFoundError(TsharkError):
    pass


def check_tshark_available(tshark_path: str = "tshark") -> bool:
    return shutil.which(tshark_path) is not None


def get_tshark_version(tshark_path: str = "tshark") -> Optional[str]:
    try:
        result = subprocess.run(
            [tshark_path, "-v"],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            lines = result.stdout.strip().split('\n')
            return lines[0] if lines else "Unknown"
    except Exception as e:
        logger.warning(f"Could not get tshark version: {e}")
    return None


def run_tshark(
    pcap_path: str,
    fields: List[str],
    display_filter: str = "",
    tshark_path: str = "tshark",
    extra_args: Optional[List[str]] = None
) -> List[Dict[str, Any]]:
    if not check_tshark_available(tshark_path):
        raise TsharkNotFoundError(
            f"tshark not found at '{tshark_path}'. Please install Wireshark/tshark and ensure it's in PATH."
        )
    
    cmd = [
        tshark_path,
        "-r", pcap_path,
        "-T", "json",
    ]
    
    if display_filter:
        cmd.extend(["-Y", display_filter])
    
    if fields:
        for field in fields:
            cmd.extend(["-e", field])
    
    if extra_args:
        cmd.extend(extra_args)
    
    logger.debug(f"Running tshark command: {' '.join(cmd)}")
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300
        )
        
        if result.returncode != 0:
            logger.error(f"tshark stderr: {result.stderr}")
            raise TsharkError(f"tshark failed with code {result.returncode}: {result.stderr}")
        
        if not result.stdout.strip():
            return []
        
        try:
            packets = json.loads(result.stdout)
            return _parse_tshark_json(packets, fields)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse tshark JSON output: {e}")
            raise TsharkError(f"Invalid JSON from tshark: {e}")
            
    except subprocess.TimeoutExpired:
        raise TsharkError("tshark timed out after 300 seconds")
    except Exception as e:
        logger.error(f"tshark execution error: {e}")
        raise TsharkError(f"tshark execution failed: {e}")


def _parse_tshark_json(packets: List[Dict], fields: List[str]) -> List[Dict[str, Any]]:
    results = []
    
    for packet in packets:
        try:
            source = packet.get("_source", {})
            layers = source.get("layers", {})
            
            frame = layers.get("frame", {})
            frame_number = frame.get("frame.number", [None])[0]
            frame_time = frame.get("frame.time_epoch", [None])[0]
            
            parsed = {
                "frame_number": int(frame_number) if frame_number else None,
                "frame_time": float(frame_time) if frame_time else None,
            }
            
            for field in fields:
                value = _extract_field(layers, field)
                parsed[field.replace(".", "_")] = value
            
            results.append(parsed)
        except Exception as e:
            logger.warning(f"Failed to parse packet: {e}")
            continue
    
    return results


def _extract_field(layers: Dict, field: str) -> Any:
    parts = field.split(".")
    current = layers
    
    for part in parts:
        if isinstance(current, dict):
            current = current.get(part)
        elif isinstance(current, list):
            if current and isinstance(current[0], dict):
                current = current[0].get(part)
            else:
                return current[0] if current else None
        else:
            return None
    
    if isinstance(current, list):
        return current[0] if current else None
    return current


def extract_tcp_streams(pcap_path: str, tshark_path: str = "tshark") -> List[Dict[str, Any]]:
    fields = [
        "frame.number",
        "frame.time_epoch",
        "ip.src",
        "ip.dst",
        "tcp.srcport",
        "tcp.dstport",
        "tcp.stream",
        "tcp.flags",
        "tcp.len",
        "_ws.col.Protocol",
    ]
    
    filter_str = "tcp"
    return run_tshark(pcap_path, fields, filter_str, tshark_path)


def extract_smtp_packets(pcap_path: str, tshark_path: str = "tshark") -> List[Dict[str, Any]]:
    fields = [
        "frame.number",
        "frame.time_epoch",
        "ip.src",
        "ip.dst",
        "tcp.srcport",
        "tcp.dstport",
        "tcp.stream",
        "smtp.command",
        "smtp.request",
        "smtp.response",
        "smtp.reply_code",
        "smtp.parameter",
    ]
    
    filter_str = "smtp"
    return run_tshark(pcap_path, fields, filter_str, tshark_path)


def extract_imap_packets(pcap_path: str, tshark_path: str = "tshark") -> List[Dict[str, Any]]:
    fields = [
        "frame.number",
        "frame.time_epoch",
        "ip.src",
        "ip.dst",
        "tcp.srcport",
        "tcp.dstport",
        "tcp.stream",
        "imap.command",
        "imap.response",
        "imap.tag",
    ]
    
    filter_str = "imap"
    return run_tshark(pcap_path, fields, filter_str, tshark_path)


def extract_pop3_packets(pcap_path: str, tshark_path: str = "tshark") -> List[Dict[str, Any]]:
    fields = [
        "frame.number",
        "frame.time_epoch",
        "ip.src",
        "ip.dst",
        "tcp.srcport",
        "tcp.dstport",
        "tcp.stream",
        "pop3.command",
        "pop3.response",
    ]
    
    filter_str = "pop3"
    return run_tshark(pcap_path, fields, filter_str, tshark_path)


def extract_tls_handshakes(pcap_path: str, tshark_path: str = "tshark") -> List[Dict[str, Any]]:
    fields = [
        "frame.number",
        "frame.time_epoch",
        "ip.src",
        "ip.dst",
        "tcp.srcport",
        "tcp.dstport",
        "tcp.stream",
        "tls.handshake.version",
        "tls.handshake.ciphersuite",
        "tls.handshake.extensions.supported_group",
        "tls.handshake.extensions.signature_algorithm",
        "tls.handshake.extensions.server_name",
        "tls.record.version",
        "tls.handshake.type",
        "x509sat.uTF8String",
        "x509sat.printableString",
        "x509ce.dNSName",
        "x509af.algorithm",
        "x509af.parameters",
    ]
    
    filter_str = "tls.handshake"
    return run_tshark(pcap_path, fields, filter_str, tshark_path)


def extract_certificates(pcap_path: str, tshark_path: str = "tshark") -> List[Dict[str, Any]]:
    fields = [
        "frame.number",
        "frame.time_epoch",
        "ip.src",
        "ip.dst",
        "tcp.srcport",
        "tcp.dstport",
        "tcp.stream",
        "x509sat.uTF8String",
        "x509sat.printableString",
        "x509ce.dNSName",
        "x509af.algorithm",
        "x509af.parameters",
        "x509cert.serialNumber",
        "x509cert.notBefore",
        "x509cert.notAfter",
        "x509cert.publicKeyAlgorithm",
        "x509cert.publicKeyLength",
        "x509cert.signatureAlgorithm",
    ]
    
    filter_str = "x509cert"
    return run_tshark(pcap_path, fields, filter_str, tshark_path)


def get_tcp_stream_packets(pcap_path: str, stream_id: int, tshark_path: str = "tshark") -> List[Dict[str, Any]]:
    fields = [
        "frame.number",
        "frame.time_epoch",
        "ip.src",
        "ip.dst",
        "tcp.srcport",
        "tcp.dstport",
        "tcp.flags",
        "tcp.len",
        "data.data",
    ]
    
    filter_str = f"tcp.stream == {stream_id}"
    return run_tshark(pcap_path, fields, filter_str, tshark_path)