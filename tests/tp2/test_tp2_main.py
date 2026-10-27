from tp2.main import main, parse_args


def test_parse_args():
    args = parse_args(["--samples", "s", "--rules", "r", "--out", "o"])
    assert args.samples == "s"
    assert args.rules == "r"
    assert args.out == "o"


def test_main(tmp_path, monkeypatch):
    monkeypatch.setenv("LLM_BACKEND", "none")
    samples = tmp_path / "samples"
    samples.mkdir()
    (samples / "x.txt").write_bytes(b"http://bad.example.test/a.php Global\\m1 ESGI{main}")
    rules = tmp_path / "rules"
    rules.mkdir()
    out = tmp_path / "out"
    assert main(["--samples", str(samples), "--rules", str(rules), "--out", str(out)]) == 0
    assert (out / "x.txt.triage.json").exists()
    assert (out / "x.triage.json").exists()
