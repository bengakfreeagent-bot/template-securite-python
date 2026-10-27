from pathlib import Path

from tp2.utils.analysis import compute_score, detect_injection, guess_family, guess_mitre
from tp2.utils.binary import parse_binary
from tp2.utils.config import logger
from tp2.utils.iocs import extract_iocs, extract_strings, find_flag
from tp2.utils.llm import LLMClient, build_summary, llm_triage
from tp2.utils.metadata import get_file_metadata
from tp2.utils.report import generate_report
from tp2.utils.yara_scan import YaraScanner


def pick_strings(strings, limit=80):
    res = []
    for s in sorted(strings, key=len, reverse=True):
        s = s.strip()[:200]
        if len(s) >= 6 and s not in res:
            res.append(s)
        if len(res) >= limit:
            break
    return res


def merge_score(rule_score, llm_score, injection, has_yara):
    if llm_score is None:
        score = rule_score
    elif injection:
        score = max(rule_score, llm_score)
    else:
        score = round(rule_score * 0.6 + llm_score * 0.4)
        if score < rule_score - 2:
            score = rule_score - 2

    if has_yara and score < 3:
        score = 3
    if injection and score < 5:
        score = 5
    return max(0, min(10, int(score)))


def default_summary(result):
    nb = 0
    for k in ["domains", "ips", "urls", "mutex", "registry"]:
        nb += len(result["iocs"].get(k, []))
    techniques = ", ".join(result["mitre_attack"])
    if techniques == "":
        techniques = "aucune"

    text = f"Analyse statique : famille probable {result['family_guess']}, "
    text += f"{len(result['yara_matches'])} regle(s) YARA, {nb} IOC, "
    text += f"{len(result['imports'])} import(s), entropie {result['entropy']}. "
    text += f"Techniques : {techniques}."
    if result.get("injection"):
        text += " Tentative d'injection de prompt detectee dans le fichier, ignoree."
    return text


class Triage:
    def __init__(self, rules_dir, out_dir, client=None):
        self.scanner = YaraScanner(rules_dir)
        self.out_dir = Path(out_dir)
        if client is None:
            client = LLMClient()
        self.client = client

    def analyze_file(self, path):
        path = Path(path)
        data = path.read_bytes()

        result = get_file_metadata(data)
        result["name"] = path.name
        result["iocs"] = extract_iocs(data)

        binary = parse_binary(path)
        result["imports"] = binary["imports"]
        result["exports"] = binary["exports"]
        result["sections"] = binary["sections"]

        result["yara_matches"] = self.scanner.scan(data)
        result["flag"] = find_flag(data)

        strings = extract_strings(data)
        text = "\n".join(strings)
        injection = detect_injection(text)
        result["injection"] = injection
        if injection:
            logger.warning(f"injection de prompt dans {path.name} : {injection[:3]}")

        result["family_guess"] = guess_family(text, result["iocs"], result["imports"], path.name)
        result["mitre_attack"] = guess_mitre(text, result["iocs"], result["imports"], result["entropy"])
        result["rule_score"] = compute_score(
            result["yara_matches"],
            result["iocs"],
            result["imports"],
            result["entropy"],
            len(injection) > 0,
            result["mitre_attack"],
            result["family_guess"],
        )

        summary = build_summary(result, pick_strings(strings), injection)
        verdict = llm_triage(summary, self.client)
        self.apply_verdict(result, verdict)
        return result

    def apply_verdict(self, result, verdict):
        injection = bool(result.get("injection"))
        has_yara = len(result["yara_matches"]) > 0

        if verdict is None:
            result["score"] = merge_score(result["rule_score"], None, injection, has_yara)
            result["llm_summary"] = default_summary(result)
            return

        result["score"] = merge_score(result["rule_score"], verdict["score"], injection, has_yara)
        if not injection and verdict["family"] not in ["unknown", "benign"]:
            result["family_guess"] = verdict["family"]
        result["mitre_attack"] = sorted(set(result["mitre_attack"] + verdict["mitre_attack"]))
        result["capabilities"] = verdict["capabilities"]
        result["llm_summary"] = verdict["summary"]
        if injection:
            result["llm_summary"] += " [Attention : injection de prompt detectee, verdict du LLM non pris tel quel.]"

    def run(self, samples_dir):
        files = []
        for p in sorted(Path(samples_dir).rglob("*")):
            if p.is_file():
                files.append(p)
        logger.info(f"{len(files)} fichier(s) a analyser")

        reports = []
        for f in files:
            try:
                result = self.analyze_file(f)
                reports.append(generate_report(result, self.out_dir))
                logger.info(f"{f.name} : score {result['score']}, famille {result['family_guess']}")
            except Exception as e:
                logger.error(f"erreur sur {f.name} : {e}")
        return reports
