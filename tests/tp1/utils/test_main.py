import json

from scapy.all import IP, TCP, Ether, wrpcap

from src.tp1.main import main


def test_main_writes_report_json(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    pcap = tmp_path / "test.pcap"
    packets = [Ether() / IP(src="10.0.0.66", dst="10.0.0.1") / TCP(dport=p, flags="S") for p in range(1, 30)]
    wrpcap(str(pcap), packets)
    out = tmp_path / "report.json"

    main(["--pcap", str(pcap), "--out", str(out)])

    data = json.loads(out.read_text())
    assert data["protocols"]["TCP"] == 29
    assert {"type": "port_scan", "attacker": "10.0.0.66"} in data["attacks"]
    assert "flag" in data