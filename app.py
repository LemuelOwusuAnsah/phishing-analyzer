import math
import re
import socket
from collections import Counter
from urllib.parse import urlparse

import tldextract
from flask import Flask, jsonify, render_template, request

app = Flask(__name__)

SUSPICIOUS_TLDS = {
    "zip", "mov", "tk", "ml", "ga", "cf", "gq", "top", "work", "click",
    "link", "xyz", "country", "kim", "loan", "download", "stream",
}

POPULAR_BRANDS = [
    "google", "paypal", "amazon", "microsoft", "apple", "netflix",
    "facebook", "instagram", "whatsapp", "binance", "coinbase", "steam",
    "roblox", "discord", "outlook", "office365", "dhl", "fedex", "usps",
]

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "update", "account", "signin", "confirm",
    "banking", "wallet", "recover", "unlock", "gift", "bonus", "prize",
    "free", "urgent", "alert", "suspended",
]


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def has_homoglyphs(hostname: str) -> bool:
    return any(ord(c) > 127 for c in hostname)


def has_ip_host(hostname: str) -> bool:
    try:
        socket.inet_aton(hostname)
        return True
    except OSError:
        return bool(re.match(r"^[0-9a-fA-F:]+$", hostname) and ":" in hostname)


def brand_lookalike(domain: str):
    domain = domain.lower()
    for brand in POPULAR_BRANDS:
        if brand in domain:
            continue
        d = levenshtein(domain.split(".")[0], brand)
        if 1 <= d <= 2:
            return brand, d
    return None


def analyze_url(url: str) -> dict:
    if not re.match(r"^https?://", url, re.I):
        url = "http://" + url

    parsed = urlparse(url)
    ext = tldextract.extract(url)
    hostname = parsed.hostname or ""
    full = parsed.geturl()

    findings = []
    score = 0

    def add(sev, title, detail, weight):
        nonlocal score
        findings.append({"severity": sev, "title": title, "detail": detail})
        score += weight

    if parsed.scheme != "https":
        add("high", "No HTTPS", "Connection is not encrypted (http://).", 25)

    if has_ip_host(hostname):
        add("high", "IP address as host",
            "Legitimate sites rarely use raw IP addresses.", 30)

    if has_homoglyphs(hostname) or "xn--" in hostname:
        add("high", "Homoglyph / IDN host",
            "Hostname contains non-ASCII or punycode characters.", 30)

    if ext.suffix in SUSPICIOUS_TLDS:
        add("medium", f"Suspicious TLD (.{ext.suffix})",
            "This TLD is heavily abused by phishing campaigns.", 15)

    sub_parts = [p for p in ext.subdomain.split(".") if p]
    if len(sub_parts) >= 3:
        add("medium", "Deep subdomain chain",
            f"{len(sub_parts)} subdomain levels — often used to fake trust.", 15)

    look = brand_lookalike(ext.domain)
    if look:
        brand, dist = look
        add("high", f"Lookalike of '{brand}'",
            f"Domain '{ext.domain}' is edit-distance {dist} from '{brand}'.", 30)

    sub_lower = ext.subdomain.lower()
    if any(b in sub_lower for b in POPULAR_BRANDS) and ext.domain not in POPULAR_BRANDS:
        add("high", "Brand in subdomain",
            "Brand name appears in subdomain but not in registered domain.", 25)

    hits = [k for k in SUSPICIOUS_KEYWORDS if k in full.lower()]
    if hits:
        add("low", "Phishing keywords present",
            "Found: " + ", ".join(hits), min(len(hits) * 5, 20))

    if "@" in parsed.netloc:
        add("high", "'@' in URL",
            "Everything before '@' is ignored by browsers — classic trick.", 25)

    if len(full) > 100:
        add("low", "Very long URL",
            f"{len(full)} characters — obscures the real domain.", 10)

    shorteners = {"bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "is.gd", "buff.ly"}
    if f"{ext.domain}.{ext.suffix}" in shorteners:
        add("medium", "URL shortener",
            "Destination is hidden behind a redirect service.", 15)

    if ext.domain.count("-") >= 2:
        add("low", "Multiple hyphens in domain",
            "Common in typosquatting domains.", 10)

    ent = shannon_entropy(ext.domain)
    if ent > 3.8:
        add("low", "High entropy domain",
            f"Entropy {ent:.2f} — possibly algorithmically generated.", 10)

    score = min(score, 100)
    if score >= 60:
        verdict, color = "DANGEROUS", "red"
    elif score >= 30:
        verdict, color = "SUSPICIOUS", "orange"
    elif score >= 10:
        verdict, color = "CAUTION", "yellow"
    else:
        verdict, color = "LIKELY SAFE", "green"

    return {
        "url": url,
        "hostname": hostname,
        "registered_domain": f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain,
        "scheme": parsed.scheme,
        "score": score,
        "verdict": verdict,
        "color": color,
        "entropy": round(ent, 2),
        "findings": findings,
    }


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    return jsonify(analyze_url(url))


if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)
