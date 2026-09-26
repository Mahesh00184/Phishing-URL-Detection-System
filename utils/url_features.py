"""
URL Feature Extraction Module for Phishing URL Detection System.
Academic & Production-ready Lexical and Structural URL Analysis.
Does NOT send any network requests or open URLs.
"""

import math
import re
from urllib.parse import urlparse, parse_qs

# Suspicious words commonly found in phishing lures
SUSPICIOUS_KEYWORDS = [
    "login", "signin", "sign-in", "log-in", "verify", "verification",
    "secure", "security", "update", "banking", "account", "confirm",
    "password", "credential", "auth", "authenticate", "wallet", "support",
    "service", "billing", "invoice", "payment", "ebayisapi", "webscr",
    "paypal", "appleid", "recovery", "alert", "notification", "suspend",
    "temporary", "unlock", "validation", "client", "portal", "token"
]

# Known URL shortener domains
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "bit.do", "shorturl.at", "tiny.cc", "rb.gy",
    "cutt.ly", "rebrand.ly", "clck.ru", "s.id", "soo.gd", "snip.li"
}

# TLDs historically associated with high abuse or cheap/free malicious registration
SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "top", "xyz", "work", "click",
    "loan", "fit", "surf", "date", "racing", "download", "men", "bid",
    "stream", "win", "party", "trade", "accountant", "faith", "cricket"
}

# Major, highly established domains with verified long age & reputation for local heuristic evaluation
ESTABLISHED_DOMAINS = {
    "google.com", "youtube.com", "microsoft.com", "apple.com", "amazon.com",
    "github.com", "wikipedia.org", "linkedin.com", "facebook.com", "twitter.com",
    "instagram.com", "netflix.com", "yahoo.com", "cloudflare.com", "reddit.com",
    "stackoverflow.com", "wordpress.org", "adobe.com", "gov", "edu", "mil",
    "bbc.com", "cnn.com", "nytimes.com", "medium.com", "dropbox.com", "paypal.com"
}

# Ordered list of feature names used for the ML model
FEATURE_NAMES = [
    "url_length",
    "domain_length",
    "num_dots",
    "num_hyphens",
    "num_special_chars",
    "num_digits",
    "num_subdomains",
    "has_ip_address",
    "has_at_symbol",
    "suspicious_word_count",
    "has_https",
    "num_params",
    "path_length",
    "domain_age_heuristic",
    "is_shortened",
    "suspicious_tld",
    "digit_ratio",
    "entropy",
]


def normalize_url(url: str) -> str:
    """
    Cleans and standardizes the URL string.
    Ensures safe parsing without network activity.
    """
    if not url:
        return ""
    url = url.strip()
    # Remove surrounding quotes or angles if pasted
    url = url.strip("<>\"'`")
    
    # If no protocol is provided, prepend http:// for standard lexical parsing
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url
    return url


def calculate_shannon_entropy(text: str) -> float:
    """
    Computes Shannon Entropy of a string to measure lexical randomness.
    Phishing URLs and DGA (Domain Generation Algorithm) strings typically have higher entropy.
    """
    if not text:
        return 0.0
    length = len(text)
    prob_map = {}
    for char in text:
        prob_map[char] = prob_map.get(char, 0) + 1
    entropy = -sum((count / length) * math.log2(count / length) for count in prob_map.values())
    return round(entropy, 4)


def extract_features(raw_url: str) -> dict:
    """
    Extracts 18 lexical and structural cybersecurity features from a URL.
    Returns a dictionary of feature names and computed values.
    """
    url = normalize_url(raw_url)
    parsed = urlparse(url)

    domain = parsed.netloc.lower()
    path = parsed.path
    query = parsed.query

    # Split domain and port if present
    if ":" in domain and not domain.startswith("["):
        domain_name = domain.split(":")[0]
    else:
        domain_name = domain

    # 1. URL Length
    url_length = len(url)

    # 2. Domain Length
    domain_length = len(domain_name)

    # 3. Number of dots
    num_dots = url.count(".")

    # 4. Number of hyphens
    num_hyphens = url.count("-")

    # 5. Number of special characters
    special_chars = set("@?=_&%#~+!$,;")
    num_special_chars = sum(1 for c in url if c in special_chars)

    # 6. Number of digits
    num_digits = sum(1 for c in url if c.isdigit())

    # 7. Number of subdomains
    # Count dots in domain name. E.g., 'sub.example.com' has 2 dots => 1 subdomain (assuming standard 2-level TLD)
    domain_parts = [p for p in domain_name.split(".") if p]
    if len(domain_parts) > 2:
        num_subdomains = len(domain_parts) - 2
    else:
        num_subdomains = 0

    # 8. Presence of IP address (IPv4 or IPv6)
    ipv4_pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    has_ip = 1 if re.match(ipv4_pattern, domain_name) or domain_name.startswith("[") else 0

    # 9. Presence of @ symbol
    has_at_symbol = 1 if "@" in url else 0

    # 10. Presence of suspicious keywords
    lower_url = url.lower()
    suspicious_word_count = sum(1 for word in SUSPICIOUS_KEYWORDS if word in lower_url)

    # 11. Presence of HTTPS
    has_https = 1 if parsed.scheme.lower() == "https" else 0

    # 12. Number of URL parameters
    params = parse_qs(query)
    num_params = len(params)

    # 13. Path characters count
    path_length = len(path)

    # 14. Domain Age Heuristic (Local without external network/API call)
    # 2 = Well-known established domain (older, high trust)
    # 1 = Standard commercial / national TLD
    # 0 = Potential newly registered / disposable / unrated
    domain_age_heuristic = 1
    for est in ESTABLISHED_DOMAINS:
        if domain_name == est or domain_name.endswith("." + est):
            domain_age_heuristic = 2
            break

    # 15. Presence of URL shortening patterns
    is_shortened = 1 if domain_name in SHORTENER_DOMAINS else 0

    # 16. Suspicious TLD detection
    tld = domain_parts[-1] if domain_parts else ""
    suspicious_tld = 1 if tld in SUSPICIOUS_TLDS else 0
    if suspicious_tld:
        domain_age_heuristic = 0

    # 17. Ratio of digits to characters
    digit_ratio = round(num_digits / max(url_length, 1), 4)

    # 18. Shannon Entropy of the URL string
    entropy = calculate_shannon_entropy(url)

    return {
        "url_length": url_length,
        "domain_length": domain_length,
        "num_dots": num_dots,
        "num_hyphens": num_hyphens,
        "num_special_chars": num_special_chars,
        "num_digits": num_digits,
        "num_subdomains": num_subdomains,
        "has_ip_address": has_ip,
        "has_at_symbol": has_at_symbol,
        "suspicious_word_count": suspicious_word_count,
        "has_https": has_https,
        "num_params": num_params,
        "path_length": path_length,
        "domain_age_heuristic": domain_age_heuristic,
        "is_shortened": is_shortened,
        "suspicious_tld": suspicious_tld,
        "digit_ratio": digit_ratio,
        "entropy": entropy,
        # Helper metadata for UI display
        "domain_name": domain_name,
        "protocol": parsed.scheme or "http",
        "tld": tld,
    }


def extract_feature_vector(raw_url: str) -> list:
    """
    Extracts features as an ordered list matching FEATURE_NAMES for ML inference.
    """
    feats = extract_features(raw_url)
    return [feats[name] for name in FEATURE_NAMES]


def evaluate_reasons(features: dict, raw_url: str) -> list:
    """
    Produces clear, academic-grade cybersecurity detection reasons based on extracted features.
    """
    reasons = []

    if features.get("has_ip_address"):
        reasons.append("URL uses a raw IP address instead of a registered domain name (common evasion tactic).")

    if features.get("has_at_symbol"):
        reasons.append("URL contains '@' character, which can deceive browsers into ignoring leading authority credentials.")

    if features.get("is_shortened"):
        reasons.append("Uses a known URL shortening service, masking the final destination.")

    if features.get("suspicious_tld"):
        reasons.append(f"Domain uses a Top-Level Domain (.{features.get('tld')}) frequently associated with malicious abuse.")

    if features.get("has_https") == 0:
        reasons.append("Insecure protocol: URL transmits data in plain text via HTTP without SSL/TLS encryption.")

    if features.get("suspicious_word_count", 0) >= 2:
        reasons.append(f"Contains {features.get('suspicious_word_count')} high-risk authentication/banking keywords often used in credential-harvesting lures.")
    elif features.get("suspicious_word_count", 0) == 1:
        reasons.append("Contains sensitive action keyword commonly targeted by phishing campaigns.")

    if features.get("num_subdomains", 0) >= 3:
        reasons.append(f"Excessive subdomain nesting ({features.get('num_subdomains')} subdomains), typical of DNS tunneling or brand spoofing.")

    if features.get("url_length", 0) > 85:
        reasons.append(f"Unusually long URL ({features.get('url_length')} characters), often used to hide payload destinations.")

    if features.get("num_hyphens", 0) >= 3:
        reasons.append("Multiple hyphens in domain/path indicating potential typosquatting or brand impersonation.")

    if features.get("digit_ratio", 0) > 0.25:
        reasons.append("High ratio of numeric digits to letters, characteristic of automated malicious domain generation (DGA).")

    if features.get("entropy", 0) > 4.5:
        reasons.append(f"Elevated Shannon entropy ({features.get('entropy')}), suggesting randomized, encoded, or obfuscated URL tokens.")

    if not reasons:
        reasons.append("No obvious lexical red flags detected; structure adheres to standard legitimate web conventions.")

    return reasons
