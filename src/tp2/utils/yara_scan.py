from pathlib import Path

import yara

from tp2.utils.config import logger

RULE_EXTENSIONS = {".yar", ".yara", ".rule", ".rules"}

CUSTOM_RULES = r"""
rule Custom_Prompt_Injection
{
    meta:
        author = "binome"
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
        author = "binome"
        description = "Persistance par cle Run du registre"
    strings:
        $run1 = "CurrentVersion\\Run" nocase ascii wide
        $run2 = "CurrentVersion\\\\Run" nocase ascii wide
        $api = "RegSetValueEx" ascii wide
    condition:
        any of ($run*) or ($api and any of ($run*))
}

rule Custom_Network_Beacon
{
    meta:
        author = "binome"
        description = "Combinaison d'API reseau et d'URL"
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
    """Charge les regles YARA d'un dossier et ajoute nos regles perso."""

    def __init__(self, rules_dir: str | Path | None = None) -> None:
        self.rules_dir = Path(rules_dir) if rules_dir else None
        self.rules = self._compile()

    def _rule_files(self) -> dict[str, str]:
        files: dict[str, str] = {}
        if not self.rules_dir or not self.rules_dir.is_dir():
            if self.rules_dir:
                logger.warning(f"dossier de regles introuvable : {self.rules_dir}")
            return files
        for i, path in enumerate(sorted(self.rules_dir.rglob("*"))):
            if path.is_file() and path.suffix.lower() in RULE_EXTENSIONS:
                try:
                    yara.compile(filepath=str(path))
                except yara.Error as e:
                    logger.warning(f"regle ignoree {path.name} : {e}")
                    continue
                files[f"r{i}_{path.stem}"] = str(path)
        return files

    def _compile(self) -> list[yara.Rules]:
        compiled = []
        files = self._rule_files()
        if files:
            compiled.append(yara.compile(filepaths=files))
            logger.info(f"{len(files)} fichier(s) de regles charges")
        compiled.append(yara.compile(source=CUSTOM_RULES))
        return compiled

    def scan(self, data: bytes) -> list[str]:
        """Retourne la liste des regles qui matchent."""
        names = set()
        for rules in self.rules:
            try:
                for match in rules.match(data=data, timeout=60):
                    names.add(match.rule)
            except yara.Error as e:
                logger.warning(f"erreur scan yara : {e}")
        return sorted(names)


def yara_scan(data: bytes, rules_dir: str | Path | None = "rules") -> list[str]:
    """Scanne des donnees avec les regles du dossier et nos regles."""
    return YaraScanner(rules_dir).scan(data)
