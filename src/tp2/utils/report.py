import json
from pathlib import Path

from fpdf import FPDF

from tp2.utils.config import logger

IOC_KEYS = ["domains", "ips", "urls", "mutex", "registry"]


def build_output(result):
    iocs = {}
    for k in IOC_KEYS:
        iocs[k] = list(result.get("iocs", {}).get(k, []))
    return {
        "sha256": result["sha256"],
        "md5": result["md5"],
        "size": result["size"],
        "entropy": result["entropy"],
        "file_type": result["file_type"],
        "iocs": iocs,
        "imports": list(result.get("imports", [])),
        "yara_matches": list(result.get("yara_matches", [])),
        "family_guess": result.get("family_guess", "unknown"),
        "mitre_attack": list(result.get("mitre_attack", [])),
        "llm_summary": result.get("llm_summary", ""),
        "score": int(result.get("score", 0)),
        "flag": result.get("flag", ""),
    }


def pdf_text(value):
    return str(value).encode("latin-1", errors="replace").decode("latin-1")


def write_pdf(result, path):
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    w = pdf.w - pdf.l_margin - pdf.r_margin

    def line(text, size=9, h=5, style=""):
        pdf.set_font("Helvetica", style, size)
        pdf.multi_cell(w, h, pdf_text(text), wrapmode="CHAR", new_x="LMARGIN", new_y="NEXT")

    def section(title, lines):
        pdf.ln(3)
        line(title, 12, 8, "B")
        if len(lines) == 0:
            lines = ["(rien)"]
        for x in lines:
            line(x)

    line("Rapport de triage malware", 16, 10, "B")
    line("Fichier : " + str(result.get("name", "")), 10, 6)

    if result.get("injection"):
        injection = "oui"
    else:
        injection = "non"
    section(
        "Verdict",
        [
            f"Score : {result.get('score')}/10",
            f"Famille : {result.get('family_guess')}",
            "MITRE ATT&CK : " + ", ".join(result.get("mitre_attack", [])),
            "Injection de prompt detectee : " + injection,
            "Flag : " + (result.get("flag") or "-"),
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
    for k in IOC_KEYS + ["paths"]:
        section("IOC - " + k, list(iocs.get(k, []))[:50])
    section("YARA", result.get("yara_matches", []))
    section("Imports", [", ".join(result.get("imports", [])[:150])])

    sections = []
    for s in result.get("sections", []):
        sections.append(f"{s['name']} - taille {s['size']} - entropie {s['entropy']}")
    section("Sections", sections)

    pdf.output(str(path))


def generate_report(result, out_dir, pdf=True):
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    data = build_output(result)
    names = [result["sha256"] + ".json"]
    if result.get("name"):
        names.append(result["name"] + ".triage.json")
        stem = Path(result["name"]).stem
        if stem != result["name"]:
            names.append(stem + ".triage.json")
    for name in names:
        with open(out / name, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    json_path = out / names[0]

    if pdf:
        try:
            write_pdf(result, out / (result["sha256"] + ".pdf"))
        except Exception as e:
            logger.warning(f"erreur PDF : {e}")
    return json_path
