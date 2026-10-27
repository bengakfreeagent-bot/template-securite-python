import re

INJECTION_PATTERNS = [
    r"ignore\s+(?:all\s+)?(?:the\s+)?(?:previous|prior|above)\s+instructions?",
    r"disregard\s+(?:all\s+)?(?:the\s+)?(?:previous|prior|above)",
    r"forget\s+(?:all\s+)?(?:your|the)\s+(?:previous\s+)?instructions",
    r"ignor(?:e|ez)\s+(?:toutes\s+)?les\s+instructions",
    r"oublie(?:z)?\s+(?:toutes\s+)?les\s+instructions",
    r"(?:d[ée]clare|consid[èe]re|classe|marque)[rz]?\s+(?:ce|le)\s+fichier\s+(?:comme\s+)?(?:sain|b[ée]nin|propre)",
    r"(?:declare|mark|classify|report)\s+(?:this|the)\s+(?:file|sample)\s+as\s+(?:safe|clean|benign)",
    r"this\s+(?:file|sample)\s+is\s+(?:safe|clean|benign)",
    r"ce\s+fichier\s+est\s+(?:sain|b[ée]nin|propre)",
    r"you\s+are\s+now\s+",
    r"new\s+instructions?\s*:",
    r"nouvelles?\s+instructions?\s*:",
    r"\bsystem\s*prompt\b",
    r"<\s*/?\s*(?:system|assistant|user)\s*>",
    r"score\s*[:=]\s*0\b",
    r"\"?score\"?\s*:\s*0\b",
]
INJECTION_RE = re.compile("|".join(INJECTION_PATTERNS), re.IGNORECASE)

FAMILY_KEYWORDS = {
    "ransomware": [
        "ransom",
        "encrypt",
        "decrypt",
        "bitcoin",
        "your files",
        "vos fichiers",
        ".locked",
        "vssadmin",
        "shadowcopy",
        "cryptencrypt",
        "readme_",
    ],
    "keylogger": [
        "getasynckeystate",
        "setwindowshookex",
        "getkeystate",
        "keylog",
        "keystroke",
        "wh_keyboard",
    ],
    "stealer": [
        "password",
        "login data",
        "cookies",
        "wallet",
        "credential",
        "logins.json",
        "cryptunprotectdata",
        "stealer",
        "browser",
    ],
    "miner": ["stratum+tcp", "xmrig", "monero", "hashrate", "cryptonight", "miner"],
    "downloader": [
        "urldownloadtofile",
        "internetopenurl",
        "winhttp",
        "invoke-webrequest",
        "downloadstring",
        "downloadfile",
        "wget ",
        "curl ",
        "/payload",
    ],
    "dropper": [
        "dropper",
        "drop",
        "writefile",
        "createprocess",
        "shellexecute",
        "%temp%",
        "\\temp\\",
        "/tmp/",
        "resource",
        "payload.exe",
    ],
    "backdoor": [
        "wsasocket",
        "reverse shell",
        "cmd.exe",
        "/bin/sh",
        "/bin/bash",
        "backdoor",
    ],
    "worm": ["worm", "spread", "smb", "autorun.inf", "netshareenum", "usb"],
}

MITRE_RULES = [
    (
        "T1059",
        [
            "cmd.exe",
            "powershell",
            "/bin/sh",
            "/bin/bash",
            "createprocess",
            "winexec",
            "shellexecute",
            "system(",
        ],
    ),
    (
        "T1105",
        [
            "urldownloadtofile",
            "downloadfile",
            "downloadstring",
            "wget ",
            "curl ",
            "invoke-webrequest",
        ],
    ),
    ("T1547", ["currentversion\\run", "currentversion\\\\run", "startup", "winlogon"]),
    ("T1053", ["schtasks", "crontab", "at.exe"]),
    ("T1543", ["createservice", "systemctl", "sc create"]),
    (
        "T1055",
        [
            "virtualallocex",
            "writeprocessmemory",
            "createremotethread",
            "ntunmapviewofsection",
        ],
    ),
    ("T1056", ["getasynckeystate", "setwindowshookex", "keylog"]),
    ("T1486", ["encrypt", "ransom", ".locked"]),
    ("T1490", ["vssadmin", "shadowcopy", "bcdedit"]),
    ("T1555", ["password", "login data", "credential", "cryptunprotectdata"]),
    ("T1622", ["isdebuggerpresent", "checkremotedebuggerpresent"]),
    ("T1497", ["vmware", "virtualbox", "vbox", "sandbox"]),
    ("T1496", ["stratum+tcp", "xmrig", "monero"]),
    ("T1112", ["regsetvalue", "regcreatekey", "reg add"]),
    ("T1070", ["wevtutil", "clear-eventlog", "del /f"]),
    ("T1082", ["getcomputername", "systeminfo", "uname", "gethostname"]),
]

SUSPICIOUS_IMPORTS = {
    "virtualallocex",
    "writeprocessmemory",
    "createremotethread",
    "wsasocketa",
    "wsasocketw",
    "connect",
    "internetopena",
    "internetopenurla",
    "urldownloadtofilea",
    "urldownloadtofilew",
    "createprocessa",
    "createprocessw",
    "winexec",
    "shellexecutea",
    "shellexecutew",
    "regsetvalueexa",
    "regsetvalueexw",
    "getasynckeystate",
    "setwindowshookexa",
    "setwindowshookexw",
    "cryptencrypt",
    "isdebuggerpresent",
    "createmutexa",
    "createmutexw",
    "execve",
    "system",
    "socket",
    "fork",
    "ptrace",
}


def detect_injection(text: str) -> list[str]:
    """Retourne les morceaux de texte qui ressemblent a une injection de prompt."""
    found = []
    for m in INJECTION_RE.finditer(text):
        piece = m.group().strip()
        if piece not in found:
            found.append(piece)
    return found


def guess_family(text: str, iocs: dict, imports: list[str], name: str = "") -> str:
    """Devine la famille du malware a partir de mots cles et du nom du fichier."""
    content = (text + " " + " ".join(imports)).lower()
    scores = {}
    for family, words in FAMILY_KEYWORDS.items():
        scores[family] = sum(1 for w in words if w in content)
        if family in name.lower():
            scores[family] += 3
    if iocs.get("urls") and scores["downloader"] == 0:
        scores["dropper"] += 1
    best = max(scores, key=lambda f: scores[f])
    if scores[best] == 0:
        if any(iocs.get(k) for k in ("urls", "domains", "ips", "registry", "mutex")):
            return "trojan"
        return "unknown"
    return best


def guess_mitre(text: str, iocs: dict, imports: list[str], entropy: float) -> list[str]:
    """Associe des techniques MITRE ATT&CK aux indicateurs trouves."""
    content = (text + " " + " ".join(imports)).lower()
    techniques = set()
    for technique, words in MITRE_RULES:
        if any(w in content for w in words):
            techniques.add(technique)
    if iocs.get("urls") or iocs.get("domains") or iocs.get("ips"):
        techniques.add("T1071")
    if any("\\run" in r.lower() for r in iocs.get("registry", [])):
        techniques.add("T1547")
    if iocs.get("registry"):
        techniques.add("T1112")
    if entropy >= 7.2:
        techniques.add("T1027")
    return sorted(techniques)


def compute_score(
    yara_matches: list[str],
    iocs: dict,
    imports: list[str],
    entropy: float,
    injection: bool,
    mitre: list[str],
    family: str = "unknown",
) -> int:
    """Calcule un score de 0 a 10 sans LLM, a partir des YARA et des IOC."""
    score = 0.0
    if family not in ("unknown", "benign"):
        score += 1.5
    score += min(len(yara_matches) * 1.5, 4)
    if iocs.get("urls") or iocs.get("domains") or iocs.get("ips"):
        score += 2
    if iocs.get("registry"):
        score += 1
    if iocs.get("mutex"):
        score += 1
    bad_imports = [i for i in imports if i.lower() in SUSPICIOUS_IMPORTS]
    score += min(len(bad_imports) * 0.5, 2)
    if entropy >= 7.2:
        score += 1
    score += min(len(mitre) * 0.5, 2.5)
    if injection:
        score += 2
    return max(0, min(10, round(score)))
