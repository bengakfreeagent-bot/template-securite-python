from scapy.all import ARP, IP, TCP, Ether, Raw

from src.tp1.utils.detector import Detector, decode_payload, is_sql_injection

ATTACKER_MAC = "02:49:0e:b6:2f:ec"
ROUTER_MAC = "02:21:52:b5:0a:6e"


def build_packets() -> list:
    packets = [
        # requête ARP légitime puis réponse du vrai routeur
        Ether() / ARP(op=1, psrc="10.0.0.12", hwsrc="66:d2:59:f0:bb:45", pdst="10.0.0.1"),
        Ether() / ARP(op=2, psrc="10.0.0.1", hwsrc=ROUTER_MAC, pdst="10.0.0.12"),
        # réponses non sollicitées de l'attaquant
        Ether() / ARP(op=2, psrc="10.0.0.1", hwsrc=ATTACKER_MAC, pdst="10.0.0.12"),
        Ether() / ARP(op=2, psrc="10.0.0.1", hwsrc=ATTACKER_MAC, pdst="10.0.0.13"),
        # injection SQL avec le vrai flag
        Ether()
        / IP(src="10.0.0.77", dst="10.0.0.200")
        / TCP(sport=4000, dport=80, flags="PA")
        / Raw(b"GET /login.php?user=admin%27%20OR%201=1--%20&token=ESGI{vrai} HTTP/1.1\r\n\r\n"),
        # faux flag envoyé par une autre machine
        Ether()
        / IP(src="10.0.0.120", dst="10.0.0.200")
        / TCP(sport=4001, dport=80, flags="PA")
        / Raw(b"GET /status HTTP/1.1\r\nX-Note: the flag is ESGI{faux}\r\n\r\n"),
    ]
    # scan de ports : 20 SYN vers des ports différents
    packets += [
        Ether() / IP(src="10.0.0.66", dst="10.0.0.200") / TCP(dport=port, flags="S") for port in range(20, 40)
    ]
    return packets


def test_decode_payload():
    assert decode_payload(b"user=admin%27%20OR%201=1") == "user=admin' or 1=1"


def test_is_sql_injection():
    assert is_sql_injection(b"id=1 UNION SELECT password FROM users")
    assert not is_sql_injection(b"GET /index.html HTTP/1.1")


def test_detector_init():
    detector = Detector([])
    assert detector.attacks == []
    assert detector.flag == ""


def test_detect_arp_spoofing():
    attacks = Detector(build_packets()).detect_arp_spoofing()
    assert attacks == [{"type": "arp_spoofing", "attacker": ATTACKER_MAC}]


def test_detect_port_scan():
    attacks = Detector(build_packets()).detect_port_scan()
    assert attacks == [{"type": "port_scan", "attacker": "10.0.0.66"}]


def test_detect_sql_injection():
    attacks = Detector(build_packets()).detect_sql_injection()
    assert attacks == [{"type": "sql_injection", "attacker": "10.0.0.77"}]


def test_find_flag_prefers_attacker():
    detector = Detector(build_packets())
    detector.attacks = [{"type": "sql_injection", "attacker": "10.0.0.77"}]
    assert detector.find_flag() == "ESGI{vrai}"


def test_find_flag_none():
    assert Detector([]).find_flag() == ""


def test_run():
    detector = Detector(build_packets())
    attacks = detector.run()
    assert len(attacks) == 3
    assert detector.flag == "ESGI{vrai}"