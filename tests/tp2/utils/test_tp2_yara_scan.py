from tp2.utils.yara_scan import YaraScanner, yara_scan


def test_scanner_rule_files(rules_dir):
    scanner = YaraScanner(rules_dir)
    files = scanner._rule_files()
    assert len(files) == 1
    assert len(scanner._compile()) == 2


def test_scanner_missing_dir(tmp_path):
    scanner = YaraScanner(tmp_path / "nope")
    assert scanner._rule_files() == {}
    assert scanner.scan(b"rien") == []


def test_scanner_scan(rules_dir, sample):
    matches = YaraScanner(rules_dir).scan(sample)
    assert "Has_Mutex" in matches
    assert "Suspicious_Downloader" in matches
    assert "Custom_Run_Key_Persistence" in matches


def test_yara_scan(rules_dir, injected):
    matches = yara_scan(injected, rules_dir)
    assert "Custom_Prompt_Injection" in matches
