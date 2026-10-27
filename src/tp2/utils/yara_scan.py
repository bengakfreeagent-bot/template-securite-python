from pathlib import Path

import yara

from tp2.utils.config import logger

CUSTOM_RULES = r"""
rule Custom_Prompt_Injection
{
    meta:
        description = "Texte qui essaie de manipuler un LLM"
    strings:
        $en1 = "ignore previous instructions" nocase ascii wide
        $en2 = "ignore all previous" nocase ascii wide
        $en3 = "disregard the above" nocase ascii wide
        $en4 = "you are now" nocase ascii wide
        $en5 = "this file is safe" nocase ascii wide
        $en6 = "mark this file as benign" nocase ascii wide
        $fr1 = "ignore les instructions" nocase ascii wide
        $fr2 = "ignorez les instructions" nocase ascii wide
        $fr3 = "fichier sain" nocase ascii wide
        $fr4 = "fichier est sain" nocase ascii wide
    condition:
        any of them
}

rule Custom_Run_Key_Persistence
{
    meta:
        description = "Persistance avec la cle Run"
    strings:
        $run1 = "CurrentVersion\\Run" nocase ascii wide
        $run2 = "CurrentVersion\\\\Run" nocase ascii wide
    condition:
        any of them
}

rule Custom_Network_Beacon
{
    meta:
        description = "API reseau et URL"
    strings:
        $url1 = "http://" nocase ascii wide
        $url2 = "https://" nocase ascii wide
        $api1 = "InternetOpen" ascii wide
        $api2 = "WSASocket" ascii wide
        $api3 = "URLDownloadToFile" ascii wide
        $api4 = "connect" fullword ascii wide
    condition:
        any of ($url*) and any of ($api*)
}
"""


class YaraScanner:
    def __init__(self, rules_dir=None):
        self.rules_dir = None
        if rules_dir:
            self.rules_dir = Path(rules_dir)
        self.rules = self._compile()

    def _rule_files(self):
        files = {}
        if self.rules_dir is None:
            return files
        if not self.rules_dir.is_dir():
            logger.warning(f"dossier de regles introuvable : {self.rules_dir}")
            return files

        i = 0
        for path in sorted(self.rules_dir.rglob("*")):
            i += 1
            if not path.is_file():
                continue
            if path.suffix.lower() not in [".yar", ".yara", ".rule", ".rules"]:
                continue
            try:
                yara.compile(filepath=str(path))
            except yara.Error as e:
                logger.warning(f"regle ignoree {path.name} : {e}")
                continue
            files[f"r{i}_{path.stem}"] = str(path)
        return files

    def _compile(self):
        rules = []
        files = self._rule_files()
        if len(files) > 0:
            rules.append(yara.compile(filepaths=files))
            logger.info(f"{len(files)} fichier(s) de regles")
        rules.append(yara.compile(source=CUSTOM_RULES))
        return rules

    def scan(self, data):
        res = set()
        for rules in self.rules:
            try:
                for m in rules.match(data=data, timeout=60):
                    res.add(m.rule)
            except yara.Error as e:
                logger.warning(f"erreur yara : {e}")
        return sorted(res)


def yara_scan(data, rules_dir="rules"):
    return YaraScanner(rules_dir).scan(data)
