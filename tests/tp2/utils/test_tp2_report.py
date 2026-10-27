import json

import pytest

from tp2.utils.report import build_output, generate_report, pdf_text, write_pdf


@pytest.fixture
def result() -> dict:
    return {
        "name": "sample.exe",
        "sha256": "a" * 64,
        "md5": "b" * 32,
        "size": 10,
        "entropy": 7.5,
        "file_type": "data",
        "iocs": {"domains": ["c2.test"], "paths": ["C:\\x"]},
        "imports": ["connect"],
        "sections": [{"name": ".text", "size": 100, "entropy": 6.1}],
        "yara_matches": ["Has_Mutex"],
        "family_guess": "dropper",
        "mitre_attack": ["T1071"],
        "llm_summary": "résumé avec accent → flèche",
        "score": 7,
        "flag": "ESGI{x}",
        "injection": ["ignore"],
    }


def test_build_output(result):
    out = build_output(result)
    assert list(out.keys()) == [
        "sha256",
        "md5",
        "size",
        "entropy",
        "file_type",
        "iocs",
        "imports",
        "yara_matches",
        "family_guess",
        "mitre_attack",
        "llm_summary",
        "score",
        "flag",
    ]
    assert list(out["iocs"].keys()) == ["domains", "ips", "urls", "mutex", "registry"]
    assert out["iocs"]["ips"] == []


def test_pdf_text():
    assert pdf_text("flèche →") == "flèche ?"


def test_write_pdf(result, tmp_path):
    path = tmp_path / "r.pdf"
    write_pdf(result, path)
    assert path.read_bytes().startswith(b"%PDF")


def test_generate_report(result, tmp_path):
    path = generate_report(result, tmp_path / "out")
    assert path.name == "a" * 64 + ".json"
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["score"] == 7
    assert data["flag"] == "ESGI{x}"
    assert (tmp_path / "out" / ("a" * 64 + ".pdf")).exists()
