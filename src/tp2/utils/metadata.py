import hashlib
import math
import subprocess
import tempfile

from tp2.utils.config import logger


def shannon_entropy(data):
    if len(data) == 0:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    entropy = 0.0
    for c in counts:
        if c > 0:
            p = c / len(data)
            entropy -= p * math.log2(p)
    return entropy


def guess_type_from_header(data):
    if data[:4] == b"\x7fELF" and len(data) > 18:
        bits = "64-bit" if data[4] == 2 else "32-bit"
        if data[5] == 1:
            order = "LSB"
            e_type = int.from_bytes(data[16:18], "little")
        else:
            order = "MSB"
            e_type = int.from_bytes(data[16:18], "big")
        types = {1: "relocatable", 2: "executable", 3: "shared object", 4: "core file"}
        return f"ELF {bits} {order} {types.get(e_type, 'file')}"
    if data[:2] == b"MZ":
        return "PE32 executable (MS Windows)"
    if data[:4] == b"\xcf\xfa\xed\xfe" or data[:4] == b"\xce\xfa\xed\xfe":
        return "Mach-O executable"
    if data[:4] == b"PK\x03\x04":
        return "Zip archive data"
    if data[:4] == b"%PDF":
        return "PDF document"
    if data[:2] == b"#!":
        return "script text executable"

    if len(data) > 0:
        text = True
        for b in data[:4096]:
            if not (32 <= b < 127 or b in (9, 10, 13)):
                text = False
                break
        if text:
            return "ASCII text"
    return "data"


def detect_file_type(data):
    try:
        import magic

        return str(magic.from_buffer(data))
    except Exception as e:
        logger.debug(f"python-magic ne marche pas : {e}")

    try:
        with tempfile.NamedTemporaryFile() as tmp:
            tmp.write(data)
            tmp.flush()
            out = subprocess.run(["file", "-b", tmp.name], capture_output=True, text=True, timeout=10)
        if out.returncode == 0 and out.stdout.strip() != "":
            return out.stdout.strip()
    except Exception as e:
        logger.debug(f"commande file indisponible : {e}")

    return guess_type_from_header(data)


def get_file_metadata(data):
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "md5": hashlib.md5(data).hexdigest(),
        "size": len(data),
        "file_type": detect_file_type(data),
        "entropy": round(shannon_entropy(data), 2),
    }
