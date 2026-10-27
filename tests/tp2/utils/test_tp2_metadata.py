import hashlib

from tp2.utils.metadata import detect_file_type, get_file_metadata, guess_type_from_header, shannon_entropy


def test_shannon_entropy():
    assert shannon_entropy(b"") == 0.0
    assert shannon_entropy(b"aaaa") == 0.0
    assert shannon_entropy(bytes(range(256))) == 8.0


def test_detect_file_type():
    result = detect_file_type(b"hello world\n")
    assert isinstance(result, str)
    assert result != ""


def test_get_file_metadata(sample):
    meta = get_file_metadata(sample)
    assert meta["sha256"] == hashlib.sha256(sample).hexdigest()
    assert meta["md5"] == hashlib.md5(sample).hexdigest()
    assert meta["size"] == len(sample)
    assert 0 <= meta["entropy"] <= 8
    assert isinstance(meta["file_type"], str)


def test_guess_type_from_header():
    elf = b"\x7fELF\x02\x01\x01" + b"\x00" * 9 + b"\x03\x00" + b"\x00" * 20
    assert guess_type_from_header(elf) == "ELF 64-bit LSB shared object"
    assert guess_type_from_header(b"MZ\x90\x00").startswith("PE32")
    assert guess_type_from_header(b"hello world") == "ASCII text"
    assert guess_type_from_header(b"\x00\x01\x02") == "data"
