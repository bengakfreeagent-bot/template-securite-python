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
    r"\"?score\"?\s*[:=]\s*0\b",
]

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
    "keylogger": ["getasynckeystate", "setwindowshookex", "getkeystate", "keylog", "keystroke", "wh_keyboard"],
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
    "backdoor": ["wsasocket", "reverse shell", "cmd.exe", "/bin/sh", "/bin/bash", "backdoor"],
    "worm": ["worm", "spread", "smb", "autorun.inf", "netshareenum", "usb"],
}

MITRE = {
    "T1059": ["cmd.exe", "powershell", "/bin/sh", "/bin/bash", "createprocess", "winexec", "shellexecute", "system("],
    "T1105": ["urldownloadtofile", "downloadfile", "downloadstring", "wget ", "curl ", "invoke-webrequest"],
    "T1547": ["currentversion\\run", "currentversion\\\\run", "startup", "winlogon"],
    "T1053": ["schtasks", "crontab", "at.exe"],
    "T1543": ["createservice", "systemctl", "sc create"],
    "T1055": ["virtualallocex", "writeprocessmemory", "createremotethread", "ntunmapviewofsection"],
    "T1056": ["getasynckeystate", "setwindowshookex", "keylog"],
    "T1486": ["encrypt", "ransom", ".locked"],
    "T1490": ["vssadmin", "shadowcopy", "bcdedit"],
    "T1555": ["password", "login data", "credential", "cryptunprotectdata"],
    "T1622": ["isdebuggerpresent", "checkremotedebuggerpresent"],
    "T1497": ["vmware", "virtualbox", "vbox", "sandbox"],
    "T1496": ["stratum+tcp", "xmrig", "monero"],
    "T1112": ["regsetvalue", "regcreatekey", "reg add"],
    "T1070": ["wevtutil", "clear-eventlog", "del /f"],
    "T1082": ["getcomputername", "systeminfo", "uname", "gethostname"],
}

SUSPICIOUS_IMPORTS = [
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
]


def detect_injection(text):
    res = []
    for p in INJECTION_PATTERNS:
        for m in re.finditer(p, text, re.IGNORECASE):
            s = m.group().strip()
            if s not in res:
                res.append(s)
    return res


def guess_family(text, iocs, imports, name=""):
    content = (text + " " + " ".join(imports)).lower()
    scores = {}
    for family in FAMILY_KEYWORDS:
        n = 0
        for word in FAMILY_KEYWORDS[family]:
            if word in content:
                n += 1
        if family in name.lower():
            n += 3
        scores[family] = n

    if iocs.get("urls") and scores["downloader"] == 0:
        scores["dropper"] += 1

    best = max(scores, key=scores.get)
    if scores[best] > 0:
        return best
    if iocs.get("urls") or iocs.get("domains") or iocs.get("ips") or iocs.get("registry") or iocs.get("mutex"):
        return "trojan"
    return "unknown"


def guess_mitre(text, iocs, imports, entropy):
    content = (text + " " + " ".join(imports)).lower()
    res = []
    for t in MITRE:
        for word in MITRE[t]:
            if word in content:
                res.append(t)
                break

    if iocs.get("urls") or iocs.get("domains") or iocs.get("ips"):
        res.append("T1071")
    if iocs.get("registry"):
        res.append("T1112")
        for r in iocs["registry"]:
            if "\\run" in r.lower():
                res.append("T1547")
    if entropy >= 7.2:
        res.append("T1027")
    return sorted(set(res))


def compute_score(yara_matches, iocs, imports, entropy, injection, mitre, family="unknown"):
    score = 0
    if family != "unknown" and family != "benign":
        score += 1.5
    score += min(len(yara_matches) * 1.5, 4)
    if iocs.get("urls") or iocs.get("domains") or iocs.get("ips"):
        score += 2
    if iocs.get("registry"):
        score += 1
    if iocs.get("mutex"):
        score += 1

    nb = 0
    for i in imports:
        if i.lower() in SUSPICIOUS_IMPORTS:
            nb += 1
    score += min(nb * 0.5, 2)

    if entropy >= 7.2:
        score += 1
    score += min(len(mitre) * 0.5, 2.5)
    if injection:
        score += 2

    score = round(score)
    if score > 10:
        score = 10
    return score
