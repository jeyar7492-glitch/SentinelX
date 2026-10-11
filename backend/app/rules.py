"""
SentinelX Transparent Rules & Heuristic Definitions
Zero-cost, local-only rule database for phishing and URL anomaly detection.
"""

from typing import Set

# Established, widely recognized domains for baseline reputation verification
# Note: Reputable domains can still be analyzed for HTTP vs HTTPS or redirect flaws.
TRUSTED_DOMAINS: Set[str] = {
    "google.com",
    "www.google.com",
    "github.com",
    "www.github.com",
    "microsoft.com",
    "www.microsoft.com",
    "apple.com",
    "www.apple.com",
    "amazon.com",
    "www.amazon.com",
    "wikipedia.org",
    "en.wikipedia.org",
    "mozilla.org",
    "www.mozilla.org",
    "python.org",
    "www.python.org",
    "ubuntu.com",
    "www.ubuntu.com",
    "cloudflare.com",
    "www.cloudflare.com",
    "stackoverflow.com",
    "www.stackoverflow.com",
}

# High-value brand targets frequently spoofed in phishing campaigns
TARGET_BRANDS: Set[str] = {
    "paypal",
    "chase",
    "wellsfargo",
    "bankofamerica",
    "citibank",
    "apple",
    "microsoft",
    "google",
    "netflix",
    "amazon",
    "facebook",
    "instagram",
    "dropbox",
    "binance",
    "coinbase",
    "walmart",
    "steam",
    "roblox",
    "outlook",
    "yahoo",
    "icloud",
    "metamask",
}

# Top-level domains statistically associated with disposable, zero-cost, or high-abuse phishing kits
HIGH_RISK_TLDS: Set[str] = {
    "tk",
    "ml",
    "ga",
    "cf",
    "gq",
    "top",
    "xyz",
    "buzz",
    "club",
    "work",
    "icu",
    "fit",
    "surf",
    "monster",
    "click",
    "link",
    "cam",
    "rest",
}

# Suspicious keywords that signal sensitive login/credential-harvesting operations
SENSITIVE_PATH_KEYWORDS: Set[str] = {
    "login",
    "signin",
    "sign-in",
    "log-in",
    "verify",
    "verification",
    "account-update",
    "security-check",
    "reset-password",
    "confirm-identity",
    "recover-account",
    "banking",
    "wallet-connect",
    "seedphrase",
}

# Parameter names commonly abused for open redirect and credential-forwarding attacks
REDIRECT_PARAMS: Set[str] = {
    "redirect",
    "redirect_to",
    "redirect_url",
    "url",
    "return",
    "return_to",
    "next",
    "dest",
    "destination",
    "target",
    "continue",
    "goto",
}
