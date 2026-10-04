"""
CVE Daily Brief
---------------
Pulls new CVEs from the NVD API, filters by configurable keywords and CVSS
score threshold, cross-references against the CISA Known Exploited
Vulnerabilities (KEV) catalogue, and writes a plain-text digest.

Configure via config.json — see config.example.json for a template.
"""

import json
import os
import requests
from datetime import datetime, timezone, timedelta
from pathlib import Path


# -- Paths --------------------------------------------------------------------

BASE_DIR = Path(__file__).parent
CONFIG_PATH = BASE_DIR / "config.json"

# -- External API endpoints ---------------------------------------------------

NVD_CVE_URL  = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_CVE_PAGE = "https://nvd.nist.gov/vuln/detail/"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


# -- Config loading -----------------------------------------------------------

def load_config() -> dict:
    """Load configuration from config.json."""
    if not CONFIG_PATH.exists():
        raise FileNotFoundError(
            f"config.json not found at {CONFIG_PATH}. "
            "Copy config.example.json to config.json and populate it."
        )
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


# -- Data fetching ------------------------------------------------------------

def get_recent_cves(hours: int) -> list:
    """Fetch CVEs published in the last N hours from NVD."""
    end_dt   = datetime.now(timezone.utc)
    start_dt = end_dt - timedelta(hours=hours)

    params = {
        "pubStartDate": start_dt.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate":   end_dt.strftime("%Y-%m-%dT%H:%M:%S.000"),
    }

    try:
        response = requests.get(NVD_CVE_URL, params=params, timeout=30)
        response.raise_for_status()
    except requests.exceptions.Timeout:
        print("[ERROR] NVD API request timed out.")
        return []
    except requests.exceptions.HTTPError as e:
        print(f"[ERROR] HTTP error from NVD API: {e}")
        return []
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Could not reach NVD API: {e}")
        return []

    return response.json().get("vulnerabilities", [])


def get_cisa_kev_ids() -> set:
    """Return a set of CVE IDs currently listed in the CISA KEV catalogue."""
    try:
        response = requests.get(CISA_KEV_URL, timeout=30)
        response.raise_for_status()
        entries = response.json().get("vulnerabilities", [])
        return {v["cveID"] for v in entries}
    except Exception as e:
        print(f"[WARNING] Could not fetch CISA KEV catalogue: {e}")
        return set()


# -- Filtering ----------------------------------------------------------------

def filter_by_keywords(vulnerabilities: list, keywords: list, min_score: float) -> list:
    """
    Filter CVEs by keyword match in the English description and minimum CVSS v3.1
    base score. If no keywords are configured, all CVEs above the score threshold
    are returned.
    """
    lower_keywords = [kw.lower() for kw in keywords]
    matched = []

    for vuln in vulnerabilities:
        cve = vuln.get("cve", {})

        descriptions  = cve.get("descriptions", [])
        english_desc  = next(
            (d.get("value", "") for d in descriptions if d.get("lang") == "en"),
            ""
        ).lower()

        if lower_keywords and not any(kw in english_desc for kw in lower_keywords):
            continue

        cvss_v31 = cve.get("metrics", {}).get("cvssMetricV31", [])
        if cvss_v31:
            base_score = float(cvss_v31[0].get("cvssData", {}).get("baseScore", 0.0))
            if base_score < min_score:
                continue

        matched.append(vuln)

    return matched


# -- Formatting ---------------------------------------------------------------

def format_brief(vulnerabilities: list, kev_ids: set) -> str:
    """Format filtered CVEs into a readable plain-text digest."""
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    count = len(vulnerabilities)

    lines = [
        f"Daily CVE Brief — {today}",
        f"CVEs matched: {count}",
        "=" * 60,
    ]

    if count == 0:
        lines.append("\nNo CVEs matched your filters in the last lookback window.")
        return "\n".join(lines)

    for vuln in vulnerabilities:
        cve    = vuln.get("cve", {})
        cve_id = cve.get("id", "UNKNOWN")

        descriptions = cve.get("descriptions", [])
        description  = next(
            (d.get("value", "") for d in descriptions if d.get("lang") == "en"),
            "No description available."
        )
        if len(description) > 300:
            description = description[:297] + "..."

        score    = "N/A"
        severity = "N/A"
        cvss_v31 = cve.get("metrics", {}).get("cvssMetricV31", [])
        if cvss_v31:
            cvss_data = cvss_v31[0].get("cvssData", {})
            score     = cvss_data.get("baseScore",  "N/A")
            severity  = cvss_data.get("baseSeverity", "N/A")

        kev_flag = "YES — Actively exploited (CISA KEV)" if cve_id in kev_ids else "No"

        lines += [
            f"\nCVE ID      : {cve_id}",
            f"Score       : {score} ({severity})",
            f"In CISA KEV : {kev_flag}",
            f"Description : {description}",
            f"Link        : {NVD_CVE_PAGE}{cve_id}",
            "-" * 60,
        ]

    return "\n".join(lines)


# -- Entry point --------------------------------------------------------------

def main():
    config = load_config()

    keywords      : list  = config.get("keywords", [])
    min_score     : float = float(config.get("min_cvss_score", 7.0))
    lookback_hours: int   = int(config.get("lookback_hours", 24))
    output_dir    : str   = config.get("output_dir", str(BASE_DIR))

    if not keywords:
        print("[WARNING] No keywords defined in config.json — returning all CVEs above the score threshold.")

    print(f"[*] Fetching CVEs from the last {lookback_hours} hours...")
    vulnerabilities = get_recent_cves(hours=lookback_hours)
    print(f"[*] Total CVEs retrieved: {len(vulnerabilities)}")

    print("[*] Fetching CISA KEV catalogue...")
    kev_ids = get_cisa_kev_ids()
    print(f"[*] CISA KEV entries loaded: {len(kev_ids)}")

    filtered = filter_by_keywords(vulnerabilities, keywords, min_score)
    print(f"[*] CVEs matched after filtering: {len(filtered)}")

    brief    = format_brief(filtered, kev_ids)
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    output_path = Path(output_dir) / f"DailyCVEBrief_{date_str}.txt"
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(brief)

    print(brief)
    print(f"\n[*] Brief saved to: {output_path}")


if __name__ == "__main__":
    main()
