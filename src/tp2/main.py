import argparse

from tp2.utils.config import logger
from tp2.utils.triage import Triage


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Triage automatise de malware")
    parser.add_argument("--samples", required=True, help="dossier des echantillons")
    parser.add_argument("--rules", default="rules", help="dossier des regles YARA")
    parser.add_argument("--out", default="out", help="dossier de sortie")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    triage = Triage(args.rules, args.out)
    written = triage.run(args.samples)
    logger.info(f"{len(written)} rapport(s) ecrit(s) dans {args.out}")
    return 0


if __name__ == "__main__":
    main()
