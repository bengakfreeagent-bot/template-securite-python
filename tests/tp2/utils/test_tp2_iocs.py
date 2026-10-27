import base64

from tp2.utils.iocs import (
    clean_backslashes,
    extract_iocs,
    extract_strings,
    find_flag,
    is_benign,
    is_valid_ip,
    search_flag,
    url_host,
)


def test_extract_strings():
    data = b"abc\x00hello\x00" + "wide_text".encode("utf-16le")
    result = extract_strings(data)
    assert "hello" in result
    assert "wide_text" in result
    assert "abc" not in result
    assert "owide_text" in result


def test_is_valid_ip():
    assert is_valid_ip("185.10.20.30")
    assert not is_valid_ip("999.1.1.1")


def test_clean_backslashes():
    assert clean_backslashes("Global\\\\abc") == "Global\\abc"


def test_is_benign():
    assert is_benign("www.gnu.org")
    assert is_benign("gnu.org")
    assert not is_benign("c2-1234.example.test")
    assert not is_benign("notgnu.org")


def test_url_host():
    assert url_host("http://user@C2.example.test:8080/gate.php") == "c2.example.test"


def test_extract_iocs(sample):
    iocs = extract_iocs(sample)
    assert iocs["urls"] == ["http://c2.example.test/gate.php"]
    assert "c2.example.test" in iocs["domains"]
    assert iocs["ips"] == ["185.10.20.30"]
    assert iocs["mutex"] == ["Global\\abc123"]
    assert iocs["registry"] == ["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\svc"]
    assert "C:\\Users\\Public\\evil.exe" in iocs["paths"]
    assert "evil.exe" not in iocs["domains"]
    assert extract_iocs(b'version="1.1.0.14"')["ips"] == []
    noisy = extract_iocs(b"https://www.gnu.org/software/coreutils/ http://c2.example.test/a")
    assert noisy["urls"] == ["http://c2.example.test/a"]
    assert noisy["domains"] == ["c2.example.test"]


def test_search_flag():
    assert search_flag(b"xx ESGI{abc} yy") == "ESGI{abc}"
    assert search_flag("ESGI{wide}".encode("utf-16le")) == "ESGI{wide}"
    assert search_flag(b"nothing") is None


def test_find_flag():
    assert find_flag(b"ESGI{plain}") == "ESGI{plain}"
    encoded = base64.b64encode(b"ESGI{base64_ok}")
    assert find_flag(b"x = '" + encoded + b"'") == "ESGI{base64_ok}"
    assert find_flag(b"ESGI{hex}".hex().encode()) == "ESGI{hex}"
    assert find_flag(b"}desrever{IGSE") == "ESGI{reversed}"
    xored = bytes(b ^ 0x41 for b in b"ESGI{xor}")
    assert find_flag(xored) == "ESGI{xor}"
    assert find_flag(b"RFTV{ebg}") == "ESGI{rot}"
    assert find_flag(b"rien ici") == ""
