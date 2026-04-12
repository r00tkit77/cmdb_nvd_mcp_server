import sys
import os
import json
import asyncio
from mcp.server.fastmcp import FastMCP
from cmdb import CMDB
from nvd_client import NVDClient
from email_sender import EmailSender


sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.chdir(os.path.dirname(os.path.abspath(__file__)))

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


mcp    = FastMCP("cmdb-cve")
db     = CMDB("cmdb.sqlite")
nvd    = NVDClient()
mailer = EmailSender()


@mcp.tool()
def list_assets() -> str:
    """
    List all assets in the CMDB as formatted text.
    Use this to show the inventory to the user.
    """
    assets = db.list_assets()
    if not assets:
        return "CMDB is empty."
    lines = ["# CMDB Assets\n"]
    for a in assets:
        lines.append(
            f"**[{a['id']}] {a['name']}**\n"
            f"  Type: {a['type']} | Env: {a['env']} | Owner: {a['owner']}\n"
            f"  OS: {a['os']}\n"
            f"  Software: {a['software'] or '—'}\n"
        )
    return "\n".join(lines)


@mcp.tool()
def get_assets_json() -> str:
    """
    Return all CMDB assets as a JSON array.
    Use this when you need to compare assets against CVEs yourself —
    each asset has: id, name, type, os, software, owner, env.
    The `software` field contains product names WITH versions (e.g. "nginx 1.24.0, openssl 3.0.2").
    When matching against CVEs, always parse and compare the version numbers — do not match
    on product name alone.
    """
    assets = db.list_assets()
    return json.dumps(assets, indent=2)


@mcp.tool()
async def get_cves_json(
    days_back: int = 7,
    min_cvss: float = 7.0,
    keyword: str = "",
) -> str:
    """
    Fetch recent CVEs from NIST NVD and return them as a JSON array.
    Use this when you need to compare CVEs against CMDB assets yourself —
    each CVE has: id, description, cvss, severity, cpes, published, url.
    The `cpes` field contains CPE strings encoding the affected vendor/product/version.
    Parse these to extract the vulnerable version range before matching against assets.

    Args:
        days_back: How many days back to search (default 7, max 90)
        min_cvss:  Minimum CVSS v3 base score (default 7.0)
        keyword:   Optional keyword filter, e.g. 'nginx' or 'openssl'
    """
    kw = keyword if keyword else None
    try:
        cves = await nvd.fetch_cves(days_back=days_back, min_cvss=min_cvss, keyword=kw)
    except ValueError as e:
        return f"Error: {e}"
    return json.dumps(cves, indent=2)


@mcp.tool()
async def fetch_latest_cves(
    days_back: int = 7,
    min_cvss: float = 7.0,
    keyword: str = "",
) -> str:
    """
    Fetch recent CVEs from NIST NVD and return them as formatted text (for display).
    Args:
        days_back: How many days back to search (default 7, max 90)
        min_cvss:  Minimum CVSS v3 base score (default 7.0)
        keyword:   Optional keyword filter, e.g. 'nginx' or 'openssl'
    """
    kw = keyword if keyword else None
    try:
        cves = await nvd.fetch_cves(days_back=days_back, min_cvss=min_cvss, keyword=kw)
    except ValueError as e:
        return f"Error: {e}"
    if not cves:
        return "No CVEs found matching the criteria."
    lines = [f"# CVEs (last {days_back} days, CVSS >= {min_cvss})\n"]
    for c in cves[:50]:
        lines.append(
            f"**{c['id']}** - CVSS {c['cvss']:.1f} ({c['severity']})\n"
            f"  {c['description'][:200]}{'...' if len(c['description']) > 200 else ''}\n"
            f"  CPEs: {', '.join(c['cpes'][:4]) or '-'}\n"
            f"  {c['url']}\n"
        )
    lines.append(f"\nTotal returned: {len(cves)}")
    return "\n".join(lines)


@mcp.tool()
def send_vulnerability_report(
    to_email: str,
    findings_json: str,
    total_cves_scanned: int,
) -> str:
    """
    Email a formatted vulnerability report based on matches YOU have already determined.

    Call this after you have compared get_cves_json() output against get_assets_json()
    and identified which assets are affected by which CVEs.

    ## VERSION-AWARE MATCHING — READ CAREFULLY

    When comparing CVEs to assets you MUST perform version-range checking, not just
    keyword matching. Follow these steps for each CVE:

    1. **Extract the affected version range** from the CVE's CPE strings and description.
       CPE format: `cpe:2.3:a:<vendor>:<product>:<version>:...`
       The NVD description and CPE `versionStartIncluding` / `versionEndExcluding` fields
       tell you the exact vulnerable range (e.g. "nginx < 1.25.3").

    2. **Extract the installed version** from the asset's `software` field.
       Example: `"nginx 1.24.0, openssl 3.0.2"` → nginx is at 1.24.0.

    3. **Compare versions semantically** (major.minor.patch).
       Only mark an asset as affected if its installed version falls WITHIN the
       vulnerable range. Do NOT flag an asset just because the product name matches.

    4. **Set `match_reason` precisely**, e.g.:
       - MATCH: "nginx 1.24.0 installed; CVE affects nginx < 1.25.3"
       - SKIP (no match): asset has nginx 1.26.0, CVE only affects < 1.25.3
       - UNCERTAIN: version not listed in software field → note as "version unknown,
         manual verification required"

    5. **Include UNCERTAIN matches** in the report with a clear note so the owner
       can manually verify. Do NOT silently drop them.

    Args:
        to_email:           Recipient email address.
        findings_json:      JSON array of match objects. Each object must have:
                              - asset_name   (str)  hostname from CMDB
                              - asset_env    (str)  e.g. "prod"
                              - asset_owner  (str)  team/person responsible
                              - cve_id       (str)  e.g. "CVE-2024-1234"
                              - cvss         (float)
                              - severity     (str)  e.g. "CRITICAL"
                              - description  (str)  CVE description
                              - match_reason (str)  REQUIRED: include installed version,
                                                    vulnerable version range, and verdict.
                                                    E.g. "nginx 1.24.0 installed; CVE affects
                                                    nginx <= 1.25.1 — CONFIRMED VULNERABLE"
                              - nvd_url      (str)  https://nvd.nist.gov/vuln/detail/...
        total_cves_scanned: Total number of CVEs fetched (for the report summary).
    """
    try:
        matches = json.loads(findings_json)
    except json.JSONDecodeError as e:
        return f"Error: findings_json is not valid JSON — {e}"

    total_assets = len(db.list_assets())
    subject, body = _build_email(matches, total_cves_scanned, total_assets)
    mailer.send(to_email=to_email, subject=subject, body=body)
    return f"Report sent to {to_email}. {len(matches)} finding(s) included."


def _build_email(matches: list, total_cves: int, total_assets: int) -> tuple[str, str]:
    from collections import defaultdict

    match_count = len(matches)
    subject = (
        f"[CVE Report] {match_count} {'vulnerability' if match_count == 1 else 'vulnerabilities'} found"
        f" — {total_cves} CVEs scanned"
    )

    lines = [
        "# CVE Vulnerability Report", "",
        f"- CVEs scanned: {total_cves}",
        f"- Assets checked: {total_assets}",
        f"- Potential matches: {match_count}", "",
    ]

    if not matches:
        lines += [
            "## No vulnerable assets found", "",
            "None of your CMDB assets appear to be affected by the scanned CVEs.",
        ]
    else:
        lines += ["## Affected Assets", ""]
        by_asset: dict = defaultdict(list)
        for m in matches:
            by_asset[m["asset_name"]].append(m)

        for asset_name, asset_matches in by_asset.items():
            m0 = asset_matches[0]
            lines.append(f"### {asset_name}  (env: {m0['asset_env']}, owner: {m0['asset_owner']})")
            for m in sorted(asset_matches, key=lambda x: x.get("cvss", 0), reverse=True):
                sev = m.get("severity", "UNKNOWN")
                lines.append(f"- **{m['cve_id']}** [{sev}] CVSS {m.get('cvss', '?')}")
                lines.append(f"  Match reason: {m.get('match_reason', '—')}")
                desc = m.get("description", "")
                lines.append(f"  {desc[:300]}{'...' if len(desc) > 300 else ''}")
                lines.append(f"  {m.get('nvd_url', '')}")
                lines.append("")

    lines += ["---", "Generated by CMDB-CVE MCP Server | NVD Data"]
    return subject, "\n".join(lines)


if __name__ == "__main__":
    mcp.run(transport="stdio")
