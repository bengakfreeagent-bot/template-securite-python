import sys

from tp2.utils.binary import parse_binary, unique


def test_unique():
    assert unique(["a", "b", "a", "", "c"]) == ["a", "b", "c"]


def test_parse_binary_executable():
    result = parse_binary(sys.executable)
    assert result["format"] in ("PE", "ELF", "MachO")
    assert isinstance(result["imports"], list)
    assert len(result["sections"]) > 0


def test_parse_binary_not_binary(tmp_path):
    f = tmp_path / "script.txt"
    f.write_text("echo hello")
    result = parse_binary(f)
    assert result["format"] is None
    assert result["imports"] == []
