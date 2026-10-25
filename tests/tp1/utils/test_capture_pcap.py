import pytest
from scapy.all import ARP, IP, TCP, UDP, Ether, Raw, wrpcap

from src.tp1.utils.capture import Capture


@pytest.fixture
def pcap_file(tmp_path):
    packets = [
        Ether() / IP(dst="10.0.0.1") / TCP(sport=12345, dport=80) / Raw(b"GET / HTTP/1.1\r\n\r\n"),
        Ether() / IP(dst="10.0.0.1") / TCP(sport=12345, dport=443),
        Ether() / IP(dst="10.0.0.2") / UDP(sport=5000, dport=5001),
        Ether() / ARP(pdst="10.0.0.3"),
    ]
    path = tmp_path / "test.pcap"
    wrpcap(str(path), packets)
    return str(path)


def test_capture_init_with_parameters():
    capture = Capture("file.pcap", "eth0")

    assert capture.pcap_file == "file.pcap"
    assert capture.interface == "eth0"


def test_capture_traffic_reads_pcap(pcap_file):
    capture = Capture(pcap_file)

    capture.capture_traffic()

    assert len(capture.packets) == 4


def test_capture_traffic_missing_pcap_raises():
    capture = Capture("does_not_exist.pcap")

    with pytest.raises(FileNotFoundError):
        capture.capture_traffic()


def test_get_all_protocols_counts_ethernet_and_http(pcap_file):
    capture = Capture(pcap_file)
    capture.capture_traffic()

    capture.get_all_protocols()

    assert capture.protocols["Ethernet"] == 4
    assert capture.protocols["IP"] == 3
    assert capture.protocols["TCP"] == 2
    assert capture.protocols["UDP"] == 1
    assert capture.protocols["ARP"] == 1
    assert capture.protocols["HTTP"] == 1