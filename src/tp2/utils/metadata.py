import hashlib
import math
import subprocess
import tempfile
from collections import Counter

from tp2.utils.config import logger


def shannon_entropy(data: bytes) -> float:
    """Calcule l'entropie de Shannon (entre 0 et 8)."""
    if not data:
        return 0.0
    total = len(data)
    entropy = 0.0
    for count in Counter(data).values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


def guess_type_from_header(data: bytes) -> str:
    """Devine le type du fichier avec ses premiers octets."""
    if data.startswith(b"\x7fELF") and len(data) > 18:
        bits = "64-bit" if data[4] == 2 else "32-bit"
        order = "LSB" if data[5] == 1 else "MSB"
        kinds = {1: "relocatable", 2: "executable", 3: "shared object", 4: "core file"}
        kind = kinds.get(
            int.from_bytes(data[16:18], "little" if data[5] == 1 else "big"), "file"
        )
        return f"ELF {bits} {order} {kind}"
    if data.startswith(b"MZ"):
        return "PE32 executable (MS Windows)"
    if data[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe"):
        return "Mach-O executable"
    if data.startswith(b"PK\x03\x04"):
        return "Zip archive data"
    if data.startswith(b"%PDF"):
        return "PDF document"
    if data.startswith(b"#!"):
        return "script text executable"
    sample = data[:4096]
    if sample and all(b in b"\t\n\r" or 32 <= b < 127 for b in sample):
        return "ASCII text"
    return "data"


def detect_file_type(data: bytes) -> str:
    """Retourne le type du fichier avec python-magic, ou la commande file sinon."""
    try:
        import magic

        return str(magic.from_buffer(data))
    except Exception as e:
        logger.debug(f"python-magic indisponible : {e}")
    try:
        with tempfile.NamedTemporaryFile() as tmp:
            tmp.write(data)
            tmp.flush()
            res = subprocess.run(
                ["file", "-b", tmp.name], capture_output=True, text=True, timeout=10
            )
            if res.returncode == 0 and res.stdout.strip():
                return res.stdout.strip()
    except Exception as e:
        logger.debug(f"commande file indisponible : {e}")
    return guess_type_from_header(data)


def get_file_metadata(data: bytes) -> dict:
    """Retourne sha256, md5, taille, type et entropie du fichier."""
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "md5": hashlib.md5(data).hexdigest(),
        "size": len(data),
        "file_type": detect_file_type(data),
        "entropy": round(shannon_entropy(data), 2),
    }
