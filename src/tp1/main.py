import argparse

from tp1.utils.capture import Capture
from tp1.utils.config import logger
from tp1.utils.report import Report


def main(argv: list[str] | None = None) -> None:
    """
    Parse arguments, analyse the traffic and write report.json and report.pdf
    """
    parser = argparse.ArgumentParser(description="TP1 - analyse de trafic réseau")
    parser.add_argument("--pcap", help="Fichier pcap à analyser (sinon capture en direct)")
    parser.add_argument("--out", default="report.json", help="Fichier JSON de sortie")
    parser.add_argument("--iface", help="Interface réseau pour la capture en direct")
    args = parser.parse_args(argv)

    logger.info("Starting TP1")

    capture = Capture(args.pcap, args.iface)
    capture.capture_traffic()
    capture.analyse("tcp")
    capture.save_json(args.out)

    try:
        summary = capture.get_summary()
        pdf_filename = "report.pdf"
        report = Report(capture, pdf_filename, summary)
        report.generate("graph")
        report.generate("array")
        report.save(pdf_filename)
    except (OSError, ValueError) as error:  # le PDF ne doit jamais bloquer le JSON
        logger.error(f"PDF report failed: {error}")


if __name__ == "__main__":
    main()