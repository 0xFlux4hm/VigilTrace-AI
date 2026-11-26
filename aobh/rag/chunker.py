"""chunker.py — vocabulary tables + tokenizer/query expansion for the RAG corpus.

Split out of rag_store.py along the existing function/table boundaries; names
and behavior are unchanged. Agent slang (idor, ssrf, rce, sqli...) is expanded
to the corpus' CWE-style vocabulary so tool queries match report titles.
"""
from __future__ import annotations

import re

STOPWORDS = {
    "a", "an", "and", "are", "as", "at", "be", "by", "can", "for", "from", "in",
    "into", "is", "it", "its", "may", "not", "of", "on", "or", "that", "the",
    "their", "them", "this", "to", "via", "was", "were", "when", "which", "will",
    "with", "without", "allows", "allow", "using", "use", "user", "users",
    # corpus noise (URL fragments and filler common in report titles)
    "api", "www", "com", "http", "https", "endpoint", "endpoints", "parameter",
    "parameters", "adding", "enable", "enables", "accessing", "app", "site",
}

# Agent slang -> corpus vocabulary (CWE-ish labels used in HackerOne titles/labels).
SYNONYMS = {
    "idor": ["access control", "object reference", "authorization", "insecure direct object"],
    "bola": ["access control", "authorization", "object reference"],
    "authz": ["authorization", "access control"],
    "authn": ["authentication"],
    "ssrf": ["request forgery", "server side", "blind"],
    "xxe": ["xml external entity", "xxe"],
    "rce": ["code execution", "command injection", "remote"],
    "sqli": ["sql injection"],
    "lfi": ["file reading", "path traversal", "local file"],
    "path traversal": ["path traversal", "file reading"],
    "xss": ["cross site scripting"],
    "csrf": ["request forgery", "cross site request"],
    "open redirect": ["open redirect"],
    "takeover": ["subdomain takeover"],
    "race condition": ["race condition"],
    "smuggling": ["request smuggling"],
    "cache poisoning": ["web cache"],
    "ssti": ["template injection"],
    "privesc": ["privilege escalation"],
    "ato": ["account takeover"],
    "mfa": ["mfa", "two factor", "otp"],
    "jwt": ["jwt", "token"],
    "oauth": ["oauth"],
    "openid": ["openid"],
    "cors": ["cors", "cross origin"],
    "upload": ["upload"],
    "graphql": ["graphql"],
    "prototype pollution": ["prototype pollution"],
}

TECH_VOCAB = {
    "wordpress", "woocommerce", "drupal", "joomla", "django", "rails", "ruby",
    "laravel", "php", "spring", "java", "asp", ".net", "flask", "express",
    "node", "nextjs", "react", "angular", "vue", "svelte", "graphql", "rest",
    "api", "oauth", "jwt", "saml", "sso", "openid", "kubernetes", "docker",
    "aws", "s3", "gcp", "azure", "lambda", "elasticsearch", "redis", "mysql",
    "postgres", "mongodb", "kafka", "mobile", "android", "ios", "flutter",
    "electron", "chrome", "extension", "pdf", "upload", "webhook", "saml",
    "gitlab", "nextcloud", "owncloud", "shopify", "twilio", "stripe", "paypal",
}

TOKEN_RE = re.compile(r"[a-z0-9_.]+")


def tokenize(text: str) -> list[str]:
    return [t for t in TOKEN_RE.findall(text.lower()) if t not in STOPWORDS]


def expand_query(text: str) -> list[str]:
    """Return query tokens plus synonym expansions for slang terms found."""
    toks = tokenize(text)
    low = " ".join(toks)
    out = list(toks)
    for slang, extras in SYNONYMS.items():
        if slang in low:
            out.extend(tokenize(slang))  # keep the slang itself
            out.extend(tokenize(" ".join(extras)))
    return out
