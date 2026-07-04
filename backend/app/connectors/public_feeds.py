from __future__ import annotations

import csv
import io
from functools import lru_cache
from typing import Any

import requests

CISA_KEV_JSON = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_CSV = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"


@lru_cache(maxsize=1)
def fetch_cisa_kev() -> dict[str, Any]:
    try:
        r = requests.get(CISA_KEV_JSON, timeout=20)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        return {"error": str(e), "vulnerabilities": []}


def kev_lookup(cves: list[str]) -> list[dict[str, Any]]:
    wanted = {c.upper() for c in cves}
    data = fetch_cisa_kev()
    out = []
    for item in data.get("vulnerabilities", []):
        if str(item.get("cveID", "")).upper() in wanted:
            out.append(item)
    return out


def epss_lookup(cves: list[str]) -> list[dict[str, Any]]:
    # FIRST also provides API, but this endpoint is stable enough for fallback.
    # To avoid heavy downloads during hackathon, return empty unless explicit CVEs are present.
    if not cves:
        return []
    try:
        api = "https://api.first.org/data/v1/epss"
        r = requests.get(api, params={"cve": ",".join(cves)}, timeout=20)
        r.raise_for_status()
        return r.json().get("data", [])
    except Exception:
        return []
