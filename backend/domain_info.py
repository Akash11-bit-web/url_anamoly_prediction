import whois
import tldextract
import socket
import ssl
import httpx
import datetime
from urllib.parse import urlparse

def parse_date(date_val):
    """Handles date as string, datetime, or list — with timezone stripping"""
    if date_val is None:
        return None
    if isinstance(date_val, list):
        date_val = date_val[0]
    if isinstance(date_val, datetime.datetime):
        return date_val.replace(tzinfo=None)  # strip timezone
    if isinstance(date_val, str):
        for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d", "%d-%b-%Y", "%Y%m%d"):
            try:
                return datetime.datetime.strptime(date_val.strip(), fmt)
            except:
                continue
    return None


def get_domain_info(url: str) -> dict:

    # ── 1. Extract domain ─────────────────────────────
    extracted = tldextract.extract(url)
    domain    = f"{extracted.domain}.{extracted.suffix}"
    subdomain = extracted.subdomain or "None"

    info = {
        "domain"       : domain,
        "subdomain"    : subdomain,
        "organization" : "N/A",
        "country"      : "N/A",
        "registrar"    : "N/A",
        "creation_date": "N/A",
        "domain_age"   : "N/A",
        "expiry_date"  : "N/A",
        "name_servers" : ["N/A"],
        "ip_address"   : "N/A",
        "ssl_valid"    : "❌ Not Found",
        "ssl_expiry"   : "N/A",
        "server"       : "N/A",
        "status_code"  : "N/A",
        "redirects"    : False,
        "final_url"    : url,
    }

    # ── 2. WHOIS ──────────────────────────────────────
    try:
        w = whois.whois(domain)

        info["organization"] = w.org or w.name or "N/A"
        info["country"]      = w.country   or "N/A"
        info["registrar"]    = w.registrar or "N/A"

        # Creation date & age
        creation = parse_date(w.creation_date)
        if creation:
            age = (datetime.datetime.now() - creation).days // 365
            info["creation_date"] = creation.strftime("%Y-%m-%d")
            info["domain_age"]    = f"{age} year(s)"

        # Expiry date
        expiry = parse_date(w.expiration_date)
        if expiry:
            info["expiry_date"] = expiry.strftime("%Y-%m-%d")

        # Name servers
        ns = w.name_servers
        if ns:
            if isinstance(ns, str):
                ns = [ns]
            info["name_servers"] = list(set([
                n.lower().rstrip(".") for n in ns if n
            ]))[:4]

    except Exception as e:
        print(f"WHOIS error: {e}")

    # ── 3. IP Address ─────────────────────────────────
    try:
        info["ip_address"] = socket.gethostbyname(domain)
    except Exception as e:
        print(f"IP error: {e}")

    # ── 4. SSL Certificate ────────────────────────────
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            cert       = s.getpeercert()
            ssl_expiry = datetime.datetime.strptime(
                cert["notAfter"], "%b %d %H:%M:%S %Y %Z"
            )
            info["ssl_valid"]  = "✅ Valid"
            info["ssl_expiry"] = ssl_expiry.strftime("%Y-%m-%d")
    except Exception as e:
        print(f"SSL error: {e}")

    # ── 5. HTTP Headers ───────────────────────────────
    try:
        resp = httpx.get(
            f"https://{domain}",
            timeout=8,
            follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0"}
        )
        info["server"]      = resp.headers.get("server", "N/A")
        info["status_code"] = resp.status_code
        info["redirects"]   = len(resp.history) > 0
        info["final_url"]   = str(resp.url)
    except Exception as e:
        print(f"HTTP error: {e}")

    return info