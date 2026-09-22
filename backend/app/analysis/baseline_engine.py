import logging
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from collections import Counter, defaultdict

from backend.app.analysis.crypto_analyzer import SessionAnalysis
from backend.app.models.schemas import ProtocolType

logger = logging.getLogger(__name__)


@dataclass
class ServerBaseline:
    server_ip: str
    server_port: int
    protocol: ProtocolType
    total_sessions: int
    
    tls_version_dist: Dict[str, int] = field(default_factory=dict)
    cipher_dist: Dict[str, int] = field(default_factory=dict)
    key_exchange_dist: Dict[str, int] = field(default_factory=dict)
    certificate_fingerprint_dist: Dict[str, int] = field(default_factory=dict)
    
    starttls_success_count: int = 0
    starttls_total: int = 0
    
    dominant_tls_version: str = ""
    dominant_cipher: str = ""
    dominant_key_exchange: str = ""
    
    @property
    def starttls_success_rate(self) -> float:
        if self.starttls_total == 0:
            return 1.0
        return self.starttls_success_count / self.starttls_total


class BaselineEngine:
    def __init__(self, min_sessions_for_baseline: int = 3):
        self.min_sessions_for_baseline = min_sessions_for_baseline
        self.baselines: Dict[str, ServerBaseline] = {}
    
    def build_baselines(self, sessions: List[SessionAnalysis]) -> Dict[str, ServerBaseline]:
        groups = defaultdict(list)
        
        for session in sessions:
            key = f"{session.server_ip}:{session.server_port}:{session.protocol.value}"
            groups[key].append(session)
        
        for key, group_sessions in groups.items():
            if len(group_sessions) < self.min_sessions_for_baseline:
                continue
            
            baseline = self._compute_baseline(key, group_sessions)
            self.baselines[key] = baseline
        
        return self.baselines
    
    def _compute_baseline(self, key: str, sessions: List[SessionAnalysis]) -> ServerBaseline:
        server_ip, server_port_str, protocol_str = key.split(":", 2)
        server_port = int(server_port_str)
        protocol = ProtocolType(protocol_str)
        
        tls_versions = []
        ciphers = []
        key_exchanges = []
        cert_fingerprints = []
        
        starttls_success = 0
        starttls_total = 0
        
        for session in sessions:
            if session.tls_version:
                tls_versions.append(session.tls_version.value)
            if session.cipher_suite:
                ciphers.append(session.cipher_suite)
            if session.key_exchange:
                key_exchanges.append(session.key_exchange)
            
            if session.starttls_offered or session.tls_started:
                starttls_total += 1
                if session.upgrade_successful:
                    starttls_success += 1
        
        tls_version_dist = dict(Counter(tls_versions))
        cipher_dist = dict(Counter(ciphers))
        key_exchange_dist = dict(Counter(key_exchanges))
        
        dominant_tls = max(tls_version_dist.items(), key=lambda x: x[1])[0] if tls_version_dist else ""
        dominant_cipher = max(cipher_dist.items(), key=lambda x: x[1])[0] if cipher_dist else ""
        dominant_kex = max(key_exchange_dist.items(), key=lambda x: x[1])[0] if key_exchange_dist else ""
        
        return ServerBaseline(
            server_ip=server_ip,
            server_port=server_port,
            protocol=protocol,
            total_sessions=len(sessions),
            tls_version_dist=tls_version_dist,
            cipher_dist=cipher_dist,
            key_exchange_dist=key_exchange_dist,
            certificate_fingerprint_dist={},
            starttls_success_count=starttls_success,
            starttls_total=starttls_total,
            dominant_tls_version=dominant_tls,
            dominant_cipher=dominant_cipher,
            dominant_key_exchange=dominant_kex,
        )
    
    def get_baseline(self, server_ip: str, server_port: int, protocol: ProtocolType) -> Optional[ServerBaseline]:
        key = f"{server_ip}:{server_port}:{protocol.value}"
        return self.baselines.get(key)
    
    def get_all_baselines(self) -> Dict[str, ServerBaseline]:
        return self.baselines
    
    def get_baseline_summary(self) -> List[Dict[str, Any]]:
        return [
            {
                "server_ip": b.server_ip,
                "server_port": b.server_port,
                "protocol": b.protocol.value,
                "total_sessions": b.total_sessions,
                "dominant_tls_version": b.dominant_tls_version,
                "dominant_cipher": b.dominant_cipher,
                "dominant_key_exchange": b.dominant_key_exchange,
                "starttls_success_rate": b.starttls_success_rate,
                "tls_version_distribution": b.tls_version_dist,
                "cipher_distribution": b.cipher_dist,
            }
            for b in self.baselines.values()
        ]