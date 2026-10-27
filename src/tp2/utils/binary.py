import lief

from tp2.utils.config import logger

lief.logging.disable()


def unique(items):
    res = []
    for x in items:
        if x and x not in res:
            res.append(x)
    return res


def parse_binary(path):
    result = {"format": None, "imports": [], "exports": [], "sections": []}
    try:
        binary = lief.parse(str(path))
    except Exception as e:
        logger.warning(f"lief n'arrive pas a lire {path} : {e}")
        return result
    if binary is None:
        return result

    imports = []
    if isinstance(binary, lief.PE.Binary):
        result["format"] = "PE"
        for lib in binary.imports:
            for entry in lib.entries:
                if entry.name:
                    imports.append(str(entry.name))
    elif isinstance(binary, lief.ELF.Binary):
        result["format"] = "ELF"
        for f in binary.imported_functions:
            imports.append(str(f.name).split("@")[0])
    else:
        result["format"] = "MachO"
        try:
            for f in binary.imported_functions:
                imports.append(str(f.name).lstrip("_"))
        except Exception:
            pass
    result["imports"] = unique(imports)

    try:
        result["exports"] = unique([str(f.name) for f in binary.exported_functions])
    except Exception:
        pass

    for s in binary.sections:
        result["sections"].append(
            {
                "name": str(s.name),
                "size": int(s.size),
                "entropy": round(float(s.entropy), 2),
            }
        )
    return result
