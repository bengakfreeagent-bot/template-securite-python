import json
from unittest.mock import patch

from src.tp1.utils.capture import Capture


def test_capture_init():
    # When
    capture = Capture()

    # Then
    assert capture.interface == ""
    assert capture.summary == ""


def test_given_capture_when_capture_traffic_then_interface_is_set():
    # Given
    capture = Capture()

    # When
    with patch("src.tp1.utils.capture.sniff", return_value=[]) as mock_sniff:
        capture.capture_traffic()

    # Then
    mock_sniff.assert_called_once()
    assert capture.packets == []


def test_sort_network_protocols():
    # Given
    capture = Capture()

    # When
    result = capture.sort_network_protocols()

    # Then
    assert result == ""


def test_sort_network_protocols_sorted():
    capture = Capture()
    capture.protocols.update({"TCP": 2, "ARP": 1})

    assert capture.sort_network_protocols() == "ARP, TCP"


def test_get_all_protocols():
    # Given
    capture = Capture()

    # When
    result = capture.get_all_protocols()

    # Then
    assert result == ""


def test_analyse():
    # Given
    capture = Capture()

    # When
    with (
        patch.object(capture, "get_all_protocols") as mock_get_protocols,
        patch.object(capture, "sort_network_protocols") as mock_sort,
        patch.object(capture, "_gen_summary") as mock_gen_summary,
    ):
        mock_gen_summary.return_value = "Test summary"
        capture.analyse("tcp")

    # Then
    mock_get_protocols.assert_called_once()
    mock_sort.assert_called_once()
    mock_gen_summary.assert_called_once()
    assert capture.summary == "Test summary"


def test_get_summary():
    # Given
    capture = Capture()
    capture.summary = "Test summary"

    # When
    result = capture.get_summary()

    # Then
    assert result == "Test summary"


def test_gen_summary():
    # Given
    capture = Capture()

    # When
    result = capture._gen_summary()

    # Then
    assert "Aucune attaque" in result


def test_to_dict():
    capture = Capture()
    capture.protocols.update({"TCP": 3})
    capture.attacks = [{"type": "port_scan", "attacker": "10.0.0.5"}]
    capture.flag = "ESGI{test}"

    assert capture.to_dict() == {
        "protocols": {"TCP": 3},
        "attacks": [{"type": "port_scan", "attacker": "10.0.0.5"}],
        "flag": "ESGI{test}",
    }


def test_save_json(tmp_path):
    capture = Capture()
    capture.flag = "ESGI{test}"
    out = tmp_path / "report.json"

    capture.save_json(str(out))

    assert json.loads(out.read_text())["flag"] == "ESGI{test}"