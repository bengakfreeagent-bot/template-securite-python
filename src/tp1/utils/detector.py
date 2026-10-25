import re
from collections import defaultdict
from urllib.parse import unquote_plus

from scapy.all import ARP, IP, TCP, Raw

PORT_SCAN_THRESHOLD = 15
SQLI_PATTERNS = [
    r"'\s*or\s*'?\d+'?\s*=\s*'?\d+",
    r"union\s+(all\s+)?select",
    r"'\s*or\s*'[^']*'\s*=\s*'",
    r"'\s*;\s*drop\s+table",
    r"'\s*--",
    r"sleep\s*\(\s*\d+\s*\)",
    r"information_schema",
]
FLAG_REGEX = re.compile(rb"ESGI\{[^}\s]+\}")


def decode_payload(payload: bytes) -> str:

    text = payload.decode("latin-1", errors="ignore")
    return unquote_plus(text).lower()


def is_sql_injection(payload: bytes) -> bool:

    text = decode_payload(payload)
    return any(re.search(pattern, text) for pattern in SQLI_PATTERNS)


class Detector:

    def __init__(self, packets: list) -> None:
        self.packets = packets
        self.attacks: list[dict[str, str]] = []
        self.flag = ""

    def detect_arp_spoofing(self) -> list[dict[str, str]]:

        macs_by_ip: dict[str, set[str]] = defaultdict(set)
        unsolicited: dict[str, int] = defaultdict(int)
        replies: dict[str, int] = defaultdict(int)
        pending: set[tuple[str, str]] = set()

        for packet in self.packets:
            if not packet.haslayer(ARP):
                continue
            arp = packet[ARP]
            if arp.op == 1:
                pending.add((arp.psrc, arp.pdst))
            elif arp.op == 2:
                macs_by_ip[arp.psrc].add(arp.hwsrc)
                replies[arp.hwsrc] += 1
                if (arp.pdst, arp.psrc) in pending:
                    pending.discard((arp.pdst, arp.psrc))
                else:
                    unsolicited[arp.hwsrc] += 1

        attacks = []
        for macs in macs_by_ip.values():
            if len(macs) < 2:
                continue
            attacker = max(macs, key=lambda mac: (unsolicited[mac], replies[mac]))
            attacks.append({"type": "arp_spoofing", "attacker": attacker})
        return attacks

    def detect_port_scan(self, threshold: int = PORT_SCAN_THRESHOLD) -> list[dict[str, str]]:

        ports_by_src: dict[str, set[int]] = defaultdict(set)
        for packet in self.packets:
            if packet.haslayer(IP) and packet.haslayer(TCP):
                flags = packet[TCP].flags
                if flags & 0x02 and not flags & 0x10:
                    ports_by_src[packet[IP].src].add(packet[TCP].dport)

        return [
            {"type": "port_scan", "attacker": src}
            for src, ports in ports_by_src.items()
            if len(ports) >= threshold
        ]

    def detect_sql_injection(self) -> list[dict[str, str]]:

        attackers: list[str] = []
        for packet in self.packets:
            if not (packet.haslayer(IP) and packet.haslayer(TCP) and packet.haslayer(Raw)):
                continue
            src = packet[IP].src
            if is_sql_injection(bytes(packet[Raw].load)) and src not in attackers:
                attackers.append(src)
        return [{"type": "sql_injection", "attacker": src} for src in attackers]

    def find_flag(self) -> str:

        attacker_ips = {attack["attacker"] for attack in self.attacks}
        candidates: list[tuple[int, str]] = []
        for packet in self.packets:
            if not packet.haslayer(Raw):
                continue
            payload = bytes(packet[Raw].load)
            for match in FLAG_REGEX.findall(payload):
                score = 0
                if packet.haslayer(IP) and packet[IP].src in attacker_ips:
                    score += 2
                if is_sql_injection(payload):
                    score += 1
                candidates.append((score, match.decode()))
        if not candidates:
            return ""
        return max(candidates, key=lambda candidate: candidate[0])[1]

    def run(self) -> list[dict[str, str]]:

        self.attacks = self.detect_arp_spoofing() + self.detect_port_scan() + self.detect_sql_injection()
        self.flag = self.find_flag()
        return self.attacks