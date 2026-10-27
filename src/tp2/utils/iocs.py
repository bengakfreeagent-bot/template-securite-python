import base64
import binascii
import codecs
import ipaddress
import re

KNOWN_TLDS = set(
    (
        "com net org info biz io co me cc tv ws ru su cn hk tw jp kr kp ir in pk vn ua by kz de fr "
        "uk eu us nl be ch it es pt pl ro bg cz se no fi dk br ar mx ca au nz za ng tr il ae sa id "
        "my sg th ph tk ml ga cf gq pw to ly gl xyz top club online site website space store shop "
        "app dev cloud tech live link click lol download host work win bid loan icu fun pro mobi "
        "name today zip mov onion bit local lan corp internal test example invalid localhost gov "
        "edu mil int network services support digital"
    ).split()
)

BENIGN_DOMAINS = {
    "gnu.org",
    "translationproject.org",
    "sourceware.org",
    "kernel.org",
    "w3.org",
    "microsoft.com",
    "windowsupdate.com",
    "digicert.com",
    "verisign.com",
    "globalsign.com",
    "sectigo.com",
    "openssl.org",
    "python.org",
    "mozilla.org",
    "xiph.org",
    "freedesktop.org",
}

DOMAIN_RE = re.compile(
    r"(?<![\w.\-@])(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}(?![\w\-])",
    re.IGNORECASE,
)
IP_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
URL_RE = re.compile(r"\b(?:https?|ftp)://[^\s\"'<>`\\|{}^]+", re.IGNORECASE)
MUTEX_RE = re.compile(
    r"\b(?:Global|Local|Session\\{1,2}\d+)\\{1,2}[\w.\-{}$#@]+", re.IGNORECASE
)
REGISTRY_RE = re.compile(
    r"\b(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS"
    r"|HKEY_CURRENT_CONFIG|HKLM|HKCU|HKCR|HKU|HKCC)"
    r"(?:\\{1,2}[\w.\-{}$@]+(?: NT)?)+"
)
WIN_PATH_RE = re.compile(
    r"(?:\b[A-Za-z]:|%[A-Za-z_]+%)(?:\\{1,2}[\w.\-{}$@~ ()]*[\w.\-{}$@~)])+"
)
UNIX_PATH_RE = re.compile(
    r"(?<![\w/])/(?:tmp|etc|var|usr|home|bin|sbin|dev|opt|root|proc|lib)"
    r"(?:/[\w.\-]+)+"
)
FLAG_RE = re.compile(rb"ESGI\{[^}\s]{1,200}\}")


def extract_strings(data: bytes, min_len: int = 4) -> list[str]:
    """Extrait les chaines ASCII et UTF-16LE du fichier."""
    result = []
    for m in re.finditer(rb"[\x20-\x7e\t]{%d,}" % min_len, data):
        result.append(m.group().decode("ascii"))
    for m in re.finditer(rb"(?:[\x20-\x7e\t]\x00){%d,}" % min_len, data):
        text = m.group().decode("utf-16le")
        result.append(text)
        if (
            m.start() > 0
            and 0x20 <= data[m.start() - 1] <= 0x7E
            and len(text) > min_len
        ):
            result.append(text[1:])
    return result


def is_valid_ip(value: str) -> bool:
    """Verifie qu'une chaine est une IPv4 correcte."""
    try:
        ipaddress.IPv4Address(value)
        return True
    except ValueError:
        return False


def clean_backslashes(value: str) -> str:
    """Remplace les doubles antislash par un seul."""
    while "\\\\" in value:
        value = value.replace("\\\\", "\\")
    return value


def is_benign(host: str) -> bool:
    """Indique si un domaine appartient a une infrastructure connue et legitime."""
    host = host.lower().strip(".")
    return any(host == d or host.endswith("." + d) for d in BENIGN_DOMAINS)


def url_host(url: str) -> str:
    """Retourne l'hote d'une URL."""
    rest = url.split("://", 1)[1]
    host = re.split(r"[/?#]", rest, maxsplit=1)[0]
    host = host.split("@")[-1]
    return host.split(":")[0].lower()


def extract_iocs(data: bytes) -> dict[str, list[str]]:
    """Extrait domaines, IP, URLs, mutex, cles de registre et chemins."""
    text = "\n".join(extract_strings(data))

    urls = set()
    for m in URL_RE.finditer(text):
        url = m.group().rstrip(".,;:)]'\"")
        if "://" in url and len(url.split("://", 1)[1]) > 0:
            urls.add(url)

    ips = set()
    for m in IP_RE.finditer(text):
        before = text[max(0, m.start() - 12) : m.start()].lower()
        if "version" in before or before.endswith("v"):
            continue
        if is_valid_ip(m.group()):
            ips.add(m.group())

    domains = set()
    for url in urls:
        host = url_host(url)
        if host and not is_valid_ip(host) and "." in host:
            domains.add(host)
        elif is_valid_ip(host):
            ips.add(host)
    for m in DOMAIN_RE.finditer(text):
        dom = m.group().lower().strip(".")
        if dom.split(".")[-1] in KNOWN_TLDS:
            domains.add(dom)
    domains = {d for d in domains if d[1:] not in domains and not is_benign(d)}
    urls = {u for u in urls if not is_benign(url_host(u))}

    mutex = {clean_backslashes(m) for m in MUTEX_RE.findall(text)}
    registry = {clean_backslashes(m) for m in REGISTRY_RE.findall(text)}

    paths = {clean_backslashes(m).strip() for m in WIN_PATH_RE.findall(text)}
    paths |= set(UNIX_PATH_RE.findall(text))

    return {
        "domains": sorted(domains),
        "ips": sorted(ips),
        "urls": sorted(urls),
        "mutex": sorted(mutex),
        "registry": sorted(registry),
        "paths": sorted(paths),
    }


def search_flag(blob: bytes) -> str | None:
    """Cherche un flag ESGI{...} en clair ou en UTF-16."""
    m = FLAG_RE.search(blob)
    if m:
        return m.group().decode("ascii", errors="ignore")
    m = FLAG_RE.search(blob.replace(b"\x00", b""))
    if m:
        return m.group().decode("ascii", errors="ignore")
    return None


def find_flag(data: bytes) -> str:
    """Cherche le flag en clair, puis en base64, hex, rot13, inverse et xor."""
    flag = search_flag(data)
    if flag:
        return flag

    for m in re.finditer(rb"[A-Za-z0-9+/]{16,}={0,2}", data):
        chunk = m.group()
        try:
            decoded = base64.b64decode(chunk + b"=" * (-len(chunk) % 4))
        except (binascii.Error, ValueError):
            continue
        flag = search_flag(decoded)
        if flag:
            return flag

    for m in re.finditer(rb"(?:[0-9a-fA-F]{2}){8,}", data):
        try:
            decoded = bytes.fromhex(m.group().decode())
        except ValueError:
            continue
        flag = search_flag(decoded)
        if flag:
            return flag

    text = data.decode("latin-1")
    rot = codecs.encode(text, "rot13").encode("latin-1")
    flag = search_flag(rot)
    if flag:
        return flag

    flag = search_flag(data[::-1])
    if flag:
        return flag

    for key in range(1, 256):
        table = bytes(b ^ key for b in range(256))
        flag = search_flag(data.translate(table))
        if flag:
            return flag

    return ""
