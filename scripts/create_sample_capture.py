"""Create a small valid PCAP/ZIP fixture for SecureMailScope demos."""

from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

from scapy.all import IP, Raw, TCP, wrpcap

ROOT = Path(__file__).resolve().parents[1]
OUTPUT_DIR = ROOT / "data" / "generated"
PUBLIC_DIR = ROOT / "frontend" / "public"
PCAP_PATH = OUTPUT_DIR / "securemailscope-sample.pcap"
ZIP_PATH = OUTPUT_DIR / "securemailscope-sample.zip"
PUBLIC_ZIP_PATH = PUBLIC_DIR / ZIP_PATH.name


def tcp_exchange(packets, client_ip, client_port, server_ip, server_port, messages):
    sequence = 1000
    acknowledgement = 2000
    packets.extend([
        IP(src=client_ip, dst=server_ip) / TCP(sport=client_port, dport=server_port, flags="S", seq=sequence),
        IP(src=server_ip, dst=client_ip) / TCP(sport=server_port, dport=client_port, flags="SA", seq=acknowledgement, ack=sequence + 1),
        IP(src=client_ip, dst=server_ip) / TCP(sport=client_port, dport=server_port, flags="A", seq=sequence + 1, ack=acknowledgement + 1),
    ])
    for direction, payload in messages:
        if direction == "client":
            source, destination, sport, dport = client_ip, server_ip, client_port, server_port
            sequence += 1
        else:
            source, destination, sport, dport = server_ip, client_ip, server_port, client_port
            acknowledgement += 1
        packets.append(IP(src=source, dst=destination) / TCP(sport=sport, dport=dport, flags="PA", seq=sequence, ack=acknowledgement + 1) / Raw(payload.encode()))
    packets.append(IP(src=client_ip, dst=server_ip) / TCP(sport=client_port, dport=server_port, flags="FA", seq=sequence + 1, ack=acknowledgement + 1))


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    PUBLIC_DIR.mkdir(parents=True, exist_ok=True)
    packets = []
    tcp_exchange(packets, "10.10.0.10", 42000, "10.10.0.20", 587, [
        ("server", "220 mail.demo.local ESMTP"),
        ("client", "EHLO client.demo.local"),
        ("server", "250-mail.demo.local\\r\\n250-STARTTLS\\r\\n250 AUTH PLAIN"),
        ("client", "AUTH PLAIN dGVzdAB0ZXN0"),
        ("client", "STARTTLS"),
        ("server", "454 TLS not available"),
    ])
    tcp_exchange(packets, "10.10.0.11", 42001, "10.10.0.21", 143, [
        ("server", "* OK IMAP4 ready"),
        ("client", "a001 CAPABILITY"),
        ("server", "* CAPABILITY IMAP4rev1 STARTTLS\\r\\na001 OK CAPABILITY completed"),
        ("client", "a002 STARTTLS"),
        ("server", "a002 OK Begin TLS negotiation now"),
    ])
    tcp_exchange(packets, "10.10.0.12", 42002, "10.10.0.22", 110, [
        ("server", "+OK POP3 server ready"),
        ("client", "STLS"),
        ("server", "+OK Begin TLS negotiation now"),
    ])
    wrpcap(str(PCAP_PATH), packets)
    readme = """SecureMailScope sample capture\n\nThis is synthetic PCAP data for local demonstration, not a recording of real traffic.\nIt contains representative SMTP, IMAP, and POP3 TCP conversations with STARTTLS/STLS patterns.\nUpload securemailscope-sample.pcap to the running SecureMailScope dashboard.\n"""
    with ZipFile(ZIP_PATH, "w", ZIP_DEFLATED) as archive:
        archive.write(PCAP_PATH, PCAP_PATH.name)
        archive.writestr("README.txt", readme)
    PUBLIC_ZIP_PATH.write_bytes(ZIP_PATH.read_bytes())
    print(f"Created {PCAP_PATH}")
    print(f"Created {ZIP_PATH}")
    print(f"Published {PUBLIC_ZIP_PATH}")


if __name__ == "__main__":
    main()
