from pathlib import Path

from tp2.utils.analysis import (
    compute_score,
    detect_injection,
    guess_family,
    guess_mitre,
)
from tp2.utils.binary import parse_binary
from tp2.utils.config import logger
from tp2.utils.iocs import extract_iocs, extract_strings, find_flag
from tp2.utils.llm import LLMClient, build_summary, llm_triage
from tp2.utils.metadata import get_file_metadata
from tp2.utils.report import generate_report
from tp2.utils.yara_scan import YaraScanner


def pick_strings(strings: list[str], limit: int = 80) -> list[str]:
    """Garde les chaines les plus utiles pour le LLM."""
    picked = []
    seen = set()
    for s in sorted(strings, key=len, reverse=True):
        s = s.strip()
        if len(s) < 6 or s in seen:
            continue
        seen.add(s)
        picked.append(s[:200])
        if len(picked) >= limit:
            break
    return picked


def merge_score(rule_score: int, llm_score: int | None, injection: bool, has_yara: bool) -> int:
    """Combine le score des regles et celui du LLM sans laisser le LLM decider seul."""
    if llm_score is None:
        score = rule_score
    elif injection:
        score = max(rule_score, llm_score)
    else:
        score = round(rule_score * 0.6 + llm_score * 0.4)
        score = max(score, rule_score - 2)
    if has_yara:
        score = max(score, 3)
    if injection:
        score = max(score, 5)
    return max(0, min(10, int(score)))


def default_summary(result: dict) -> str:
    """Resume ecrit sans LLM, a partir des resultats."""
    iocs = result["iocs"]
    count = sum(len(iocs.get(k, [])) for k in ("domains", "ips", "urls", "mutex", "registry"))
    text = (
        f"Analyse statique : famille probable {result['family_guess']}, "
        f"{len(result['yara_matches'])} regle(s) YARA, {count} IOC, "
        f"{len(result['imports'])} import(s), entropie {result['entropy']}. "
        f"Techniques : {', '.join(result['mitre_attack']) or 'aucune'}."
    )
    if result.get("injection"):
        text += " Tentative d'injection de prompt detectee dans le fichier, ignoree."
    return text


class Triage:
    """Enchaine toutes les etapes d'analyse sur un dossier d'echantillons."""

    def __init__(
        self,
        rules_dir: str | Path,
        out_dir: str | Path,
        client: LLMClient | None = None,
    ) -> None:
        self.scanner = YaraScanner(rules_dir)
        self.out_dir = Path(out_dir)
        self.client = client if client is not None else LLMClient()

    def analyze_file(self, path: str | Path) -> dict:
        """Analyse un fichier et retourne le resultat complet."""
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
            logger.warning(f"{path.name} : injection de prompt detectee {injection[:3]}")

        result["family_guess"] = guess_family(text, result["iocs"], result["imports"], path.name)
        result["mitre_attack"] = guess_mitre(text, result["iocs"], result["imports"], result["entropy"])
        result["rule_score"] = compute_score(
            result["yara_matches"],
            result["iocs"],
            result["imports"],
            result["entropy"],
            bool(injection),
            result["mitre_attack"],
            result["family_guess"],
        )

        summary = build_summary(result, pick_strings(strings), injection)
        verdict = llm_triage(summary, self.client)
        self.apply_verdict(result, verdict)
        return result

    def apply_verdict(self, result: dict, verdict: dict | None) -> None:
        """Fusionne le verdict du LLM avec l'analyse deterministe."""
        injection = bool(result.get("injection"))
        llm_score = verdict["score"] if verdict else None
        result["score"] = merge_score(result["rule_score"], llm_score, injection, bool(result["yara_matches"]))
        if verdict is None:
            result["llm_summary"] = default_summary(result)
            return
        family = verdict["family"]
        if not injection and family not in ("unknown", "benign"):
            result["family_guess"] = family
        result["mitre_attack"] = sorted(set(result["mitre_attack"]) | set(verdict["mitre_attack"]))
        result["capabilities"] = verdict["capabilities"]
        summary = verdict["summary"]
        if injection:
            summary += " [Attention : injection de prompt detectee dans le fichier, verdict du LLM non pris tel quel.]"
        result["llm_summary"] = summary

    def run(self, samples_dir: str | Path) -> list[Path]:
        """Analyse tous les fichiers du dossier et ecrit les rapports."""
        samples = Path(samples_dir)
        files = sorted(p for p in samples.rglob("*") if p.is_file())
        logger.info(f"{len(files)} echantillon(s) a analyser dans {samples}")
        written = []
        for path in files:
            try:
                result = self.analyze_file(path)
                written.append(generate_report(result, self.out_dir))
                logger.info(f"{path.name} -> score {result['score']} ({result['family_guess']})")
            except Exception as e:
                logger.error(f"echec sur {path.name} : {e}")
        return written
