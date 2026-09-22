import logging
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict

logger = logging.getLogger(__name__)


@dataclass
class TcpStreamPacket:
    frame_number: int
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    flags: str
    length: int
    stream_id: int


@dataclass
class ReconstructedStream:
    stream_id: int
    client_ip: str
    server_ip: str
    client_port: int
    server_port: int
    packets: List[TcpStreamPacket] = field(default_factory=list)
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    duration: float = 0.0
    packet_count: int = 0
    byte_count: int = 0
    frame_numbers: List[int] = field(default_factory=list)


class TcpStreamReconstructor:
    def __init__(self):
        self.streams: Dict[int, ReconstructedStream] = {}
    
    def reconstruct(self, tcp_packets: List[Dict]) -> Dict[int, ReconstructedStream]:
        stream_packets = defaultdict(list)
        
        for packet in tcp_packets:
            stream_id = packet.get("tcp_stream")
            if stream_id is None:
                continue
            stream_id = int(stream_id)
            
            tcp_packet = TcpStreamPacket(
                frame_number=packet.get("frame_number", 0),
                timestamp=packet.get("frame_time", 0.0),
                src_ip=packet.get("ip_src", ""),
                dst_ip=packet.get("ip_dst", ""),
                src_port=int(packet.get("tcp_srcport", 0)),
                dst_port=int(packet.get("tcp_dstport", 0)),
                flags=packet.get("tcp_flags", ""),
                length=int(packet.get("tcp_len", 0)),
                stream_id=stream_id,
            )
            stream_packets[stream_id].append(tcp_packet)
        
        for stream_id, packets in stream_packets.items():
            packets.sort(key=lambda p: p.timestamp)
            
            if not packets:
                continue
            
            first = packets[0]
            last = packets[-1]
            
            email_server_ports = {25, 110, 143, 465, 587, 993, 995}
            if first.src_port in email_server_ports and first.dst_port not in email_server_ports:
                client_ip = first.dst_ip
                server_ip = first.src_ip
                client_port = first.dst_port
                server_port = first.src_port
            else:
                client_ip = first.src_ip
                server_ip = first.dst_ip
                client_port = first.src_port
                server_port = first.dst_port
            
            stream = ReconstructedStream(
                stream_id=stream_id,
                client_ip=client_ip,
                server_ip=server_ip,
                client_port=client_port,
                server_port=server_port,
                packets=packets,
                start_time=datetime.fromtimestamp(first.timestamp) if first.timestamp else None,
                end_time=datetime.fromtimestamp(last.timestamp) if last.timestamp else None,
                duration=(last.timestamp - first.timestamp) if first.timestamp and last.timestamp else 0.0,
                packet_count=len(packets),
                byte_count=sum(p.length for p in packets),
                frame_numbers=[p.frame_number for p in packets],
            )
            
            self.streams[stream_id] = stream
        
        logger.info(f"Reconstructed {len(self.streams)} TCP streams")
        return self.streams
    
    def get_stream(self, stream_id: int) -> Optional[ReconstructedStream]:
        return self.streams.get(stream_id)
    
    def get_all_streams(self) -> List[ReconstructedStream]:
        return list(self.streams.values())