from __future__ import annotations

import re
from urllib.parse import urlparse

from app.models import Entity

DOMAIN_RE = re.compile(r"(?<![A-Za-z0-9._%+@-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}(?![A-Za-z0-9-])")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
URL_RE = re.compile(r"https?://[^\s,;()<>\]\[{}\"]+", re.I)

def _strip_known_indicators(text: str) -> str:
    """Blank indicators that have dedicated parsers before generic domain scanning."""
    text = re.sub(URL_RE, " ", text)
    text = re.sub(EMAIL_RE, " ", text)
    return text


def has_investigable_target(query: str) -> bool:
    """Return True only for concrete externally investigable indicators.

    The backend uses the same policy as the UI: free-form keywords such as
    "hello" are not enough to run an investigation.
    """
    if not query or not query.strip():
        return False
    if URL_RE.search(query) or EMAIL_RE.search(query) or IP_RE.search(query):
        return True
    return bool(DOMAIN_RE.search(_strip_known_indicators(query)))


def canonical_domain(value: str) -> str:
    value = value.lower().strip().strip(".,;:()[]{}<>\'\"")
    if value.startswith("www."):
        value = value[4:]
    return value


def extract_entities(query: str) -> list[Entity]:
    found: dict[tuple[str, str], Entity] = {}

    for url in URL_RE.findall(query):
        parsed = urlparse(url)
        if parsed.netloc:
            domain = canonical_domain(parsed.netloc.split(":")[0])
            found.setdefault(("domain", domain), Entity(type="domain", value=domain, display=domain, confidence=0.96))

    for email in EMAIL_RE.findall(query):
        found[("email", email.lower())] = Entity(type="email", value=email.lower(), display=email.lower(), confidence=0.98)
        domain = canonical_domain(email.split("@", 1)[1])
        found.setdefault(("domain", domain), Entity(type="domain", value=domain, display=domain, confidence=0.9))

    domain_scan_text = _strip_known_indicators(query)
    for domain in DOMAIN_RE.findall(domain_scan_text):
        d = canonical_domain(domain)
        if not d.startswith("cve-"):
            found.setdefault(("domain", d), Entity(type="domain", value=d, display=d, confidence=0.92))

    for ip in IP_RE.findall(query):
        found[("ip", ip)] = Entity(type="ip", value=ip, display=ip, confidence=0.95)

    for cve in CVE_RE.findall(query):
        found[("cve", cve.upper())] = Entity(type="cve", value=cve.upper(), display=cve.upper(), confidence=0.98)

    # A lightweight org/keyword fallback. Avoid pretending high confidence.
    cleaned = re.sub(URL_RE, " ", query)
    cleaned = re.sub(EMAIL_RE, " ", cleaned)
    cleaned = re.sub(DOMAIN_RE, " ", cleaned)
    cleaned = re.sub(IP_RE, " ", cleaned)
    cleaned = re.sub(CVE_RE, " ", cleaned)
    candidates = re.findall(r"[A-Za-z가-힣0-9][A-Za-z가-힣0-9_-]{2,}", cleaned)
    stop = {"최근", "외부", "노출", "노출을", "유출", "유출을", "분석", "분석하고", "공격자", "공격자가", "가능성", "가능성이", "방어용", "미끼", "배치", "전략", "전략을", "생성", "생성해줘", "알려줘", "만들어줘", "조사", "조사해줘", "관련", "다음에", "관심", "가질", "높은", "경로", "경로와", "사이트주소", "계정", "계정과", "감염", "단말", "단말을", "랜섬웨어", "언급", "언급을", "텔레그램", "위협", "신호", "신호를", "조사하고", "분석해줘", "공격자의", "시야와"}
    for token in candidates[:5]:
        if token not in stop and len(token) >= 3:
            found.setdefault(("keyword", token), Entity(type="keyword", value=token, display=token, confidence=0.45))

    if not found:
        found[("keyword", query[:80])] = Entity(type="keyword", value=query[:80], display=query[:80], confidence=0.3)

    return list(found.values())
