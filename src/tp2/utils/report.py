import json
from pathlib import Path

from fpdf import FPDF

from tp2.utils.config import logger

IOC_KEYS = ("domains", "ips", "urls", "mutex", "registry")


def build_output(result: dict) -> dict:
    """Met le resultat au format JSON attendu par la correction."""
    iocs = result.get("iocs", {})
    return {
        "sha256": result["sha256"],
        "md5": result["md5"],
        "size": result["size"],
        "entropy": result["entropy"],
        "file_type": result["file_type"],
        "iocs": {key: list(iocs.get(key, [])) for key in IOC_KEYS},
        "imports": list(result.get("imports", [])),
        "yara_matches": list(result.get("yara_matches", [])),
        "family_guess": result.get("family_guess", "unknown"),
        "mitre_attack": list(result.get("mitre_attack", [])),
        "llm_summary": result.get("llm_summary", ""),
        "score": int(result.get("score", 0)),
        "flag": result.get("flag", ""),
    }


def pdf_text(value: object) -> str:
    """Rend le texte compatible avec les polices de base de fpdf."""
    return str(value).encode("latin-1", errors="replace").decode("latin-1")


def write_pdf(result: dict, path: Path) -> None:
    """Ecrit un rapport PDF lisible pour un echantillon."""
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    width = pdf.w - pdf.l_margin - pdf.r_margin

    pdf.set_font("Helvetica", "B", 16)
    pdf.multi_cell(width, 10, "Rapport de triage malware", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 10)
    pdf.multi_cell(
        width,
        6,
        pdf_text(f"Fichier : {result.get('name', '')}"),
        new_x="LMARGIN",
        new_y="NEXT",
    )

    def section(title: str, lines: list[str]) -> None:
        pdf.ln(3)
        pdf.set_font("Helvetica", "B", 12)
        pdf.multi_cell(width, 8, pdf_text(title), new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 9)
        if not lines:
            lines = ["(rien)"]
        for line in lines:
            pdf.multi_cell(width, 5, pdf_text(line), wrapmode="CHAR", new_x="LMARGIN", new_y="NEXT")

    section(
        "Verdict",
        [
            f"Score : {result.get('score')}/10",
            f"Famille : {result.get('family_guess')}",
            f"MITRE ATT&CK : {', '.join(result.get('mitre_attack', []))}",
            f"Injection de prompt detectee : {'oui' if result.get('injection') else 'non'}",
            f"Flag : {result.get('flag') or '-'}",
        ],
    )
    section("Resume", [result.get("llm_summary", "")])
    section(
        "Metadonnees",
        [
            f"SHA-256 : {result.get('sha256')}",
            f"MD5 : {result.get('md5')}",
            f"Taille : {result.get('size')} octets",
            f"Type : {result.get('file_type')}",
            f"Entropie : {result.get('entropy')}",
        ],
    )
    iocs = result.get("iocs", {})
    for key in (*IOC_KEYS, "paths"):
        section(f"IOC - {key}", list(iocs.get(key, []))[:50])
    section("YARA", result.get("yara_matches", []))
    section("Imports", [", ".join(result.get("imports", [])[:150])])
    sections = [f"{s['name']} - taille {s['size']} - entropie {s['entropy']}" for s in result.get("sections", [])]
    section("Sections", sections)
    pdf.output(str(path))


def generate_report(result: dict, out_dir: str | Path, pdf: bool = True) -> Path:
    """Ecrit le JSON <sha256>.json et le PDF associe, retourne le chemin du JSON."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    json_path = out / f"{result['sha256']}.json"
    json_path.write_text(json.dumps(build_output(result), indent=2, ensure_ascii=False), encoding="utf-8")
    if pdf:
        try:
            write_pdf(result, out / f"{result['sha256']}.pdf")
        except Exception as e:
            logger.warning(f"PDF non genere pour {result['sha256']} : {e}")
    return json_path
