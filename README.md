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
```