import logging
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from pathlib import Path

from backend.app.utils.tshark import (
    check_tshark_available,
    get_tshark_version,
    extract_tcp_streams,
    extract_smtp_packets,
    extract_imap_packets,
    extract_pop3_packets,
    extract_tls_handshakes,
    extract_certificates,
    TsharkNotFoundError,
    TsharkError,
)
from backend.app.utils.hashing import compute_file_hash, sanitize_filename
from backend.app.config import settings

logger = logging.getLogger(__name__)


@dataclass
class PcapMetadata:
    filename: str
    file_size: int
    file_hash: str
    packet_count: int
    tshark_version: Optional[str]


class PcapParser:
    def __init__(self, tshark_path: str = None):
        self.tshark_path = tshark_path or settings.tshark_path
        self._verify_tshark()
    
    def _verify_tshark(self):
        if not check_tshark_available(self.tshark_path):
            raise TsharkNotFoundError(
                f"tshark not found at '{self.tshark_path}'. "
                f"Please install Wireshark and ensure tshark is in PATH, "
                f"or set TSHARK_PATH environment variable."
            )
        version = get_tshark_version(self.tshark_path)
        logger.info(f"Using tshark: {version}")
    
    def parse(self, pcap_path: str) -> Dict[str, Any]:
        path = Path(pcap_path)
        if not path.exists():
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")
        
        logger.info(f"Parsing PCAP: {pcap_path}")
        
        file_hash = compute_file_hash(pcap_path)
        file_size = path.stat().st_size
        tshark_version = get_tshark_version(self.tshark_path)
        
        tcp_streams = extract_tcp_streams(pcap_path, self.tshark_path)
        packet_count = len(tcp_streams)
        
        smtp_packets = extract_smtp_packets(pcap_path, self.tshark_path)
        imap_packets = extract_imap_packets(pcap_path, self.tshark_path)
        pop3_packets = extract_pop3_packets(pcap_path, self.tshark_path)
        tls_handshakes = extract_tls_handshakes(pcap_path, self.tshark_path)
        certificates = extract_certificates(pcap_path, self.tshark_path)
        
        return {
            "metadata": {
                "filename": path.name,
                "file_size": file_size,
                "file_hash": file_hash,
                "packet_count": packet_count,
                "tshark_version": tshark_version,
            },
            "tcp_streams": tcp_streams,
            "smtp_packets": smtp_packets,
            "imap_packets": imap_packets,
            "pop3_packets": pop3_packets,
            "tls_handshakes": tls_handshakes,
            "certificates": certificates,
        }


async def parse_pcap_async(pcap_path: str, tshark_path: str = None) -> Dict[str, Any]:
    import asyncio
    parser = PcapParser(tshark_path)
    return await asyncio.to_thread(parser.parse, pcap_path)