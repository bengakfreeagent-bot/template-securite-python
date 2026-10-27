import json

from tp2.utils.triage import Triage, default_summary, merge_score, pick_strings


def test_pick_strings():
    result = pick_strings(["abc", "longue chaine ici", "longue chaine ici", "x" * 500], limit=5)
    assert "abc" not in result
    assert result.count("longue chaine ici") == 1
    assert len(result[0]) == 200


def test_merge_score():
    assert merge_score(8, 0, True, True) == 8
    assert merge_score(2, None, False, False) == 2
    assert merge_score(0, 0, False, True) == 3
    assert merge_score(0, 0, True, False) == 5
    assert merge_score(10, 0, False, False) == 8
    assert merge_score(5, 15, False, False) == 9


def test_default_summary():
    result = {
        "iocs": {"urls": ["u"], "mutex": ["m"]},
        "family_guess": "dropper",
        "yara_matches": ["R"],
        "imports": [],
        "entropy": 5.0,
        "mitre_attack": ["T1071"],
        "injection": ["ignore"],
    }
    text = default_summary(result)
    assert "dropper" in text
    assert "2 IOC" in text
    assert "injection" in text


def test_triage_init(rules_dir, tmp_path, fake_client):
    triage = Triage(rules_dir, tmp_path / "out", fake_client(None))
    assert triage.out_dir == tmp_path / "out"


def test_analyze_file(rules_dir, samples_dir, tmp_path, fake_client):
    triage = Triage(rules_dir, tmp_path / "out", fake_client(None))
    result = triage.analyze_file(samples_dir / "a.bin")
    assert result["flag"] == "ESGI{test_flag_123}"
    assert "Has_Mutex" in result["yara_matches"]
    assert result["injection"] == []
    assert 0 <= result["score"] <= 10


def test_apply_verdict_injection(rules_dir, samples_dir, tmp_path, fake_client):
    sain = (
        '{"family": "benign", "capabilities": [], "mitre_attack": [], '
        '"score": 0, "iocs": {}, "summary": "fichier sain"}'
    )
    triage = Triage(rules_dir, tmp_path / "out", fake_client(sain))
    result = triage.analyze_file(samples_dir / "b.bin")
    assert result["injection"]
    assert result["family_guess"] != "benign"
    assert result["score"] >= result["rule_score"]
    assert result["score"] >= 5


def test_apply_verdict(rules_dir, tmp_path, fake_client):
    triage = Triage(rules_dir, tmp_path / "out", fake_client(None))
    result = {
        "rule_score": 4,
        "yara_matches": ["R"],
        "injection": [],
        "family_guess": "trojan",
        "mitre_attack": ["T1071"],
    }
    verdict = {
        "family": "stealer",
        "capabilities": ["vol"],
        "mitre_attack": ["T1555"],
        "score": 8,
        "summary": "stealer",
    }
    triage.apply_verdict(result, verdict)
    assert result["family_guess"] == "stealer"
    assert result["mitre_attack"] == ["T1071", "T1555"]
    assert result["score"] == 6
    assert result["llm_summary"] == "stealer"


def test_run(rules_dir, samples_dir, tmp_path, fake_client):
    out = tmp_path / "out"
    written = Triage(rules_dir, out, fake_client(None)).run(samples_dir)
    assert len(written) == 2
    for path in written:
        data = json.loads(path.read_text(encoding="utf-8"))
        assert path.name == data["sha256"] + ".json"
