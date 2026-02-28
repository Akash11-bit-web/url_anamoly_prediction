import re
from urllib.parse import urlparse

def extract_features(url: str) -> list:
    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    features = {
        "url_length": len(url),
        "hostname_length": len(hostname),
        "num_dots": url.count("."),
        "num_hyphens": url.count("-"),
        "num_at": url.count("@"),
        "num_slash": url.count("/"),
        "num_digits": sum(c.isdigit() for c in url),
        "has_https": 1 if parsed.scheme == "https" else 0,
        "has_ip": 1 if re.match(r'\d+\.\d+\.\d+\.\d+', hostname) else 0,
        "has_suspicious_words": 1 if any(w in url.lower() for w in
            ["login", "secure", "verify", "update", "bank", "free", "click", "confirm"]) else 0,
        "num_subdomains": hostname.count("."),
        "path_length": len(parsed.path),
        "has_port": 1 if parsed.port else 0,
    }
    return list(features.values())


def analyze_suspicious_reasons(url: str) -> dict:
    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    reasons = []
    attack_types = []

    # ── Check each suspicious feature ──────────────────

    if len(url) > 75:
        reasons.append(f"🔴 URL is unusually long ({len(url)} characters) — used to hide the real destination")

    if re.match(r'\d+\.\d+\.\d+\.\d+', hostname):
        reasons.append("🔴 URL uses a raw IP address instead of a domain name — legitimate sites never do this")
        attack_types.append("IP-based Phishing")

    if parsed.scheme != "https":
        reasons.append("🔴 URL uses HTTP instead of HTTPS — no encryption, data can be intercepted")
        attack_types.append("Unsecured Connection Attack")

    suspicious_words = ["login", "secure", "verify", "update", "bank", "free", "click", "confirm"]
    found_words = [w for w in suspicious_words if w in url.lower()]
    if found_words:
        reasons.append(f"🔴 Contains suspicious keywords: {', '.join(found_words)} — commonly used in phishing to create urgency")
        attack_types.append("Phishing / Social Engineering")

    if url.count("-") > 3:
        reasons.append(f"🔴 Too many hyphens ({url.count('-')}) — used to mimic legitimate domains (e.g. paypal-secure-login.com)")
        attack_types.append("Domain Spoofing")

    if url.count("@") > 0:
        reasons.append("🔴 Contains '@' symbol — browsers ignore everything before '@', used to disguise real destination")
        attack_types.append("URL Obfuscation Attack")

    if hostname.count(".") > 3:
        reasons.append(f"🔴 Too many subdomains ({hostname.count('.')} dots) — used to make fake URLs look real (e.g. paypal.login.evil.com)")
        attack_types.append("Subdomain Spoofing")

    if parsed.port:
        reasons.append(f"🔴 Uses unusual port {parsed.port} — legitimate websites use standard ports 80/443")
        attack_types.append("Port-based Evasion")

    if len(parsed.path) > 50:
        reasons.append(f"🔴 Very long URL path ({len(parsed.path)} chars) — used to confuse users and hide malicious redirects")

    if url.count("/") > 6:
        reasons.append(f"🔴 Excessive slashes ({url.count('/')}) — indicates deeply nested fake pages")

    # ── Determine attack category ───────────────────────
    if not attack_types:
        attack_types.append("Suspicious / Anomalous URL")

    # Remove duplicates
    attack_types = list(set(attack_types))

    return {
        "reasons": reasons,
        "attack_types": attack_types,
        "risk_level": "🔴 High Risk" if len(reasons) >= 3 else "🟡 Medium Risk" if len(reasons) >= 1 else "🟢 Low Risk"
    }