# TP1 - Analyse de trafic réseau (Sécurité Python, ESGI)

## Description

Outil en ligne de commande qui analyse un trafic réseau avec Scapy :

- lecture d'un fichier `.pcap` (ou capture en direct sur une interface) ;
- comptage des paquets par protocole (Ethernet, IP, TCP, UDP, ARP, ICMP, DNS, HTTP) ;
- détection du trafic illégitime (ARP spoofing, injection SQL...) ;
- génération d'un rapport PDF et d'un rapport JSON.

## Installation

```bash
poetry install
```

## Utilisation

```bash
poetry run tp1 --pcap FICHIER.pcap --out report.json
```

| Option    | Description                                  | Défaut        |
|-----------|----------------------------------------------|---------------|
| `--pcap`  | Fichier pcap à analyser (sinon capture live) | aucun         |
| `--out`   | Fichier JSON de sortie                       | `report.json` |
| `--iface` | Interface réseau pour la capture en direct   | aucune        |

## Tests

```bash
poetry run pytest
```## TP2 - Triage automatise de malware

Outil en ligne de commande qui analyse des fichiers suspects et sort un rapport JSON (et PDF) par echantillon.

### Lancement

```bash
poetry install
poetry run tp2 --samples samples/ --rules rules/ --out out/
```

- `--samples` : dossier des echantillons (parcouru recursivement)
- `--rules` : dossier des regles YARA (`.yar`, `.yara`)
- `--out` : dossier de sortie, un fichier `<sha256>.json` et un `<sha256>.pdf` par echantillon

### Etapes de l'analyse

1. `get_file_metadata` : SHA-256, MD5, taille, type (python-magic) et entropie de Shannon
2. `extract_iocs` : domaines, IP, URLs, mutex, cles de registre et chemins (chaines ASCII et UTF-16)
3. `parse_binary` : imports, exports et sections avec lief (PE / ELF)
4. `yara_scan` : regles du dossier `--rules` + 3 regles a nous (`Custom_Prompt_Injection`,
   `Custom_Run_Key_Persistence`, `Custom_Network_Beacon`)
5. `find_flag` : recherche du flag `ESGI{...}` en clair, UTF-16, base64, hex, rot13, inverse et xor 1 octet
6. `llm_triage` : envoi d'un resume structure au LLM (jamais le binaire brut), verdict JSON valide
7. `generate_report` : JSON au format de la correction + PDF lisible

### LLM

La classe `LLMClient` gere OpenRouter (si `OPENROUTER_API_KEY` est dans `.env`) ou Ollama en local.
Variables possibles : `LLM_BACKEND` (`openrouter`, `ollama`, `none`), `OPENROUTER_MODEL`, `OLLAMA_MODEL`.
Si le LLM ne repond pas, l'outil continue avec un verdict deterministe (score, famille, MITRE calcules par regles).

### Protection contre l'injection de prompt

- les chaines du fichier sont envoyees entre des delimiteurs `<<<DONNEES_NON_FIABLES>>>` et nettoyees
- les injections sont detectees par regex et par une regle YARA, ce qui augmente le score
- le score final combine les regles (YARA, IOC, imports, entropie) et le LLM, le LLM ne peut pas le faire chuter
- la reponse du LLM est validee : JSON strict, champs obligatoires, score borne entre 0 et 10, IDs MITRE verifies

### Tests et qualite

```bash
poetry run pytest
poetry run ruff check src tests
pre-commit install && pre-commit run --all-files
```
