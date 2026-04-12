import os
import asyncio
import aiohttp
from datetime import datetime, timedelta, timezone


NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class NVDClient:
    def __init__(self):
        # Optional: set NVD_API_KEY env var for higher rate limits (50 req/30s vs 5 req/30s)
        self.api_key = os.getenv("NVD_API_KEY")

    async def fetch_cves(
        self,
        days_back: int = 7,
        min_cvss: float = 7.0,
        keyword: str | None = None,
        max_results: int = 500,
    ) -> list[dict]:
        """
        Fetch recent CVEs from NVD.
        Returns list of dicts: {id, description, cvss, severity, cpes, published, url}
        """
        MAX_DAYS = 90  # Internal policy limit (NVD allows 120, but we cap at 90)
        if days_back < 1:
            raise ValueError("days_back must be at least 1.")
        if days_back > MAX_DAYS:
            raise ValueError(
                f"days_back={days_back} exceeds the maximum allowed value of {MAX_DAYS} days. "
                "Fetching a very large CVE window produces noisy results and strains the NVD API. "
                f"Please use a value between 1 and {MAX_DAYS}."
            )

        now = datetime.now(timezone.utc)
        pub_start = (now - timedelta(days=days_back)).strftime("%Y-%m-%dT%H:%M:%S.000")
        pub_end   = now.strftime("%Y-%m-%dT%H:%M:%S.000")

        params = {
            "pubStartDate": pub_start,
            "pubEndDate":   pub_end,
            "resultsPerPage": min(max_results, 2000),
            "startIndex": 0,
        }
        if keyword:
            params["keywordSearch"] = keyword

        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["apiKey"] = self.api_key

        all_cves = []
        async with aiohttp.ClientSession() as session:
            # NVD may paginate; handle up to 3 pages
            for _ in range(3):
                async with session.get(NVD_BASE, params=params, headers=headers, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                    if resp.status == 403:
                        raise RuntimeError("NVD API rate limit hit. Set NVD_API_KEY for higher limits, or wait 30s.")
                    if resp.status != 200:
                        text = await resp.text()
                        raise RuntimeError(f"NVD API error {resp.status}: {text[:300]}")
                    data = await resp.json()

                vulnerabilities = data.get("vulnerabilities", [])
                for item in vulnerabilities:
                    parsed = _parse_cve(item.get("cve", {}))
                    if parsed and parsed["cvss"] >= min_cvss:
                        all_cves.append(parsed)

                total     = data.get("totalResults", 0)
                returned  = data.get("resultsPerPage", 0)
                start     = data.get("startIndex", 0)

                if start + returned >= total:
                    break
                params["startIndex"] = start + returned
                # Be polite to NVD API
                await asyncio.sleep(0.6 if self.api_key else 6)

        # Sort by CVSS descending
        all_cves.sort(key=lambda x: x["cvss"], reverse=True)
        return all_cves


def _parse_cve(cve: dict) -> dict | None:
    cve_id = cve.get("id", "")
    if not cve_id:
        return None

    # Description (prefer English)
    descriptions = cve.get("descriptions", [])
    description = next(
        (d["value"] for d in descriptions if d.get("lang") == "en"),
        descriptions[0]["value"] if descriptions else "No description available.",
    )

    # CVSS – prefer v3.1, fall back to v3.0, then v2
    cvss_score    = 0.0
    cvss_severity = "UNKNOWN"
    metrics = cve.get("metrics", {})

    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key, [])
        if entries:
            data = entries[0].get("cvssData", {})
            cvss_score    = data.get("baseScore", 0.0)
            cvss_severity = data.get("baseSeverity", "UNKNOWN")
            break
    else:
        entries = metrics.get("cvssMetricV2", [])
        if entries:
            data = entries[0].get("cvssData", {})
            cvss_score    = data.get("baseScore", 0.0)
            cvss_severity = entries[0].get("baseSeverity", "UNKNOWN")

    # CPE strings (affected configurations)
    cpes = []
    configs = cve.get("configurations", [])
    for config in configs:
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if match.get("vulnerable"):
                    cpes.append(match.get("criteria", ""))

    published = cve.get("published", "")[:10]

    return {
        "id":          cve_id,
        "description": description,
        "cvss":        float(cvss_score),
        "severity":    cvss_severity,
        "cpes":        cpes,
        "published":   published,
        "url":         f"https://nvd.nist.gov/vuln/detail/{cve_id}",
    }
