from pathlib import Path

from tp2.utils.config import logger


def unique(items: list[str]) -> list[str]:
    """Supprime les doublons en gardant l'ordre."""
    seen = set()
    result = []
    for item in items:
        if item and item not in seen:
            seen.add(item)
            result.append(item)
    return result


def parse_binary(path: str | Path) -> dict:
    """Recupere les imports, exports et sections d'un PE ou ELF avec lief."""
    result: dict = {"format": None, "imports": [], "exports": [], "sections": []}
    try:
        import lief

        lief.logging.disable()
        binary = lief.parse(str(path))
    except Exception as e:
        logger.warning(f"lief n'a pas pu lire {path} : {e}")
        return result

    if binary is None:
        return result

    if isinstance(binary, lief.PE.Binary):
        result["format"] = "PE"
        imports = []
        for lib in binary.imports:
            for entry in lib.entries:
                if entry.name:
                    imports.append(str(entry.name))
        result["imports"] = unique(imports)
    elif isinstance(binary, lief.ELF.Binary):
        result["format"] = "ELF"
        result["imports"] = unique(
            [str(f.name).split("@")[0] for f in binary.imported_functions]
        )
    else:
        result["format"] = type(binary).__module__.split(".")[-1]
        try:
            result["imports"] = unique(
                [str(f.name).lstrip("_") for f in binary.imported_functions]
            )
        except Exception:
            pass

    try:
        result["exports"] = unique([str(f.name) for f in binary.exported_functions])
    except Exception:
        pass

    for section in binary.sections:
        result["sections"].append(
            {
                "name": str(section.name),
                "size": int(section.size),
                "entropy": round(float(getattr(section, "entropy", 0.0)), 2),
            }
        )
    return result
