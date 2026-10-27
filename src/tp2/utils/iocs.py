import base64
import codecs
import ipaddress
import re

TLDS = (
    "com net org info biz io co me cc tv ws ru su cn hk tw jp kr kp ir in pk vn ua by kz de fr "
    "uk eu us nl be ch it es pt pl ro bg cz se no fi dk br ar mx ca au nz za ng tr il ae sa id "
    "my sg th ph tk ml ga cf gq pw to ly gl xyz top club online site website space store shop "
    "app dev cloud tech live link click lol download host work win bid loan icu fun pro mobi "
    "name today zip mov onion bit local lan corp internal test example invalid localhost gov "
    "edu mil int network services support digital"
).split()

BENIGN_DOMAINS = [
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
]

URL_RE = r"\b(?:https?|ftp)://[^\s\"'<>`\\|{}^]+"
IP_RE = r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])"
DOMAIN_RE = r"(?<![\w.\-@])(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}(?![\w\-])"
MUTEX_RE = r"\b(?:Global|Local|Session\\{1,2}\d+)\\{1,2}[\w.\-{}$#@]+"
REGISTRY_RE = (
    r"\b(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|HKEY_CURRENT_CONFIG"
    r"|HKLM|HKCU|HKCR|HKU|HKCC)(?:\\{1,2}[\w.\-{}$@]+(?: NT)?)+"
)
WIN_PATH_RE = r"(?:\b[A-Za-z]:|%[A-Za-z_]+%)(?:\\{1,2}[\w.\-{}$@~ ()]*[\w.\-{}$@~)])+"
UNIX_PATH_RE = r"(?<![\w/])/(?:tmp|etc|var|usr|home|bin|sbin|dev|opt|root|proc|lib)(?:/[\w.\-]+)+"
FLAG_RE = rb"ESGI\{[^}\s]{1,200}\}"


def extract_strings(data, min_len=4):
    res = []
    for m in re.finditer(rb"[\x20-\x7e\t]{%d,}" % min_len, data):
        res.append(m.group().decode())
    for m in re.finditer(rb"(?:[\x20-\x7e\t]\x00){%d,}" % min_len, data):
        s = m.group().decode("utf-16le")
        res.append(s)
        i = m.start()
        if i > 0 and 0x20 <= data[i - 1] <= 0x7E and len(s) > min_len:
            res.append(s[1:])
    return res


def is_valid_ip(value):
    try:
        ipaddress.IPv4Address(value)
        return True
    except ValueError:
        return False


def clean_backslashes(value):
    while "\\\\" in value:
        value = value.replace("\\\\", "\\")
    return value


def is_benign(host):
    host = host.lower().strip(".")
    for d in BENIGN_DOMAINS:
        if host == d or host.endswith("." + d):
            return True
    return False


def url_host(url):
    host = url.split("://", 1)[1]
    host = re.split(r"[/?#]", host)[0]
    host = host.split("@")[-1]
    host = host.split(":")[0]
    return host.lower()


def extract_iocs(data):
    text = "\n".join(extract_strings(data))

    urls = []
    for u in re.findall(URL_RE, text, re.IGNORECASE):
        u = u.rstrip(".,;:)]'\"")
        if not u.endswith("://") and u not in urls:
            urls.append(u)

    ips = []
    for m in re.finditer(IP_RE, text):
        before = text[max(0, m.start() - 12) : m.start()].lower()
        if "version" in before or before.endswith("v"):
            continue
        if is_valid_ip(m.group()) and m.group() not in ips:
            ips.append(m.group())

    domains = []
    for u in urls:
        host = url_host(u)
        if is_valid_ip(host):
            if host not in ips:
                ips.append(host)
        elif "." in host and host not in domains:
            domains.append(host)
    for d in re.findall(DOMAIN_RE, text, re.IGNORECASE):
        d = d.lower().strip(".")
        if d.split(".")[-1] in TLDS and d not in domains:
            domains.append(d)

    good_domains = []
    for d in domains:
        if d[1:] not in domains and not is_benign(d):
            good_domains.append(d)
    good_urls = []
    for u in urls:
        if not is_benign(url_host(u)):
            good_urls.append(u)

    mutex = set()
    for m in re.findall(MUTEX_RE, text, re.IGNORECASE):
        mutex.add(clean_backslashes(m))
    registry = set()
    for r in re.findall(REGISTRY_RE, text):
        registry.add(clean_backslashes(r))
    paths = set()
    for p in re.findall(WIN_PATH_RE, text):
        paths.add(clean_backslashes(p).strip())
    for p in re.findall(UNIX_PATH_RE, text):
        paths.add(p)

    return {
        "domains": sorted(good_domains),
        "ips": sorted(ips),
        "urls": sorted(good_urls),
        "mutex": sorted(mutex),
        "registry": sorted(registry),
        "paths": sorted(paths),
    }


def search_flag(blob):
    m = re.search(FLAG_RE, blob)
    if m is None:
        m = re.search(FLAG_RE, blob.replace(b"\x00", b""))
    if m is None:
        return None
    return m.group().decode("ascii", errors="ignore")


def find_flag(data):
    flag = search_flag(data)
    if flag:
        return flag

    for m in re.finditer(rb"[A-Za-z0-9+/]{16,}={0,2}", data):
        b = m.group()
        b = b + b"=" * (-len(b) % 4)
        try:
            flag = search_flag(base64.b64decode(b))
        except ValueError:
            continue
        if flag:
            return flag

    for m in re.finditer(rb"(?:[0-9a-fA-F]{2}){8,}", data):
        flag = search_flag(bytes.fromhex(m.group().decode()))
        if flag:
            return flag

    rot = codecs.encode(data.decode("latin-1"), "rot13").encode("latin-1")
    flag = search_flag(rot)
    if flag:
        return flag

    flag = search_flag(data[::-1])
    if flag:
        return flag

    for key in range(1, 256):
        table = bytes([i ^ key for i in range(256)])
        flag = search_flag(data.translate(table))
        if flag:
            return flag
    return ""
