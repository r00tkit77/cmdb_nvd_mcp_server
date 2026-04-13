# CMDB-CVE-NESSUS MCP Server

A **Model Context Protocol (MCP) server** for vulnerability intelligence automation with Agentic AI. This system combines a Configuration Management Database (CMDB) with real-time CVE ingestion from NIST NVD and leverages **LLM-driven reasoning** for vulnerability correlation followed by Nessus scan to validate the issue.

---

## Overview

This MCP server enables an AI agent (e.g., Claude Desktop) to:

* Query a **read-only CMDB** (asset inventory)
* Fetch recent **CVE data from NVD** via the official REST API
* Perform **LLM-driven, version-aware correlation** between CVEs and assets
* Perform Nessus scan for the particular asset and CVE plugin
* Generate and send **structured, explainable vulnerability reports** via email

---

## Data Flow

1. Load assets from CMDB
2. Fetch latest CVEs from NVD
3. Pre-process and analyze CVEs + assets
4. LLM performs version-aware correlation
5. Call Nessus to validate the vulnerability present
6. Generate structured vulnerability findings
7. Send report via email

---

## Architecture

```
cmdb-cve-mcp/
├── server.py          # MCP server (tool definitions + orchestration)
├── cmdb.py            # SQLite-based read-only CMDB with sample assets
├── nvd_client.py      # Client to query NVD CVE API
├── email_sender.py    # SMTP email utility
├── requirements.txt
└── README.md
```

---

## Available MCP Tools

| Tool                        | Description                                         | Example Prompt                                               |
| --------------------------- | --------------------------------------------------- | ------------------------------------------------------------ |
| `list_assets`               | View all CMDB assets (read-only)                    | "Show me all assets in my CMDB"                              |
| `get_assets_json`           | Retrieve assets as structured JSON for LLM analysis | "Get assets in JSON format"                                  |
| `get_cves_json`             | Retrieve CVEs as structured JSON for LLM analysis   | "Fetch CVEs in JSON format"                 |
| `fetch_latest_cves`         | Retrieve CVEs in human-readable format              | "Show latest CVEs of last 3 days with CVSS > 9"                                           |
| `send_vulnerability_report` | Send report based on LLM-generated findings         | "Send report to [user@example.com](mailto:user@example.com)" |

---

## Guardrails

### Security Guardrails

* **Read-only CMDB** – prevents asset modification 
* **Trusted data source** – CVEs fetched only from official NVD API
* **Restricted tool scope** – no arbitrary command execution
* **Secure configuration** – credentials managed via environment variables

---

### Operational Guardrails

* **CVE window limits** – capped query range (max 90 days)
* **Rate-limit aware fetching** – respects NVD API constraints
* **Bounded outputs** – prevents excessive token usage
* **Guided LLM reasoning** – enforces structured, version-aware decisions

---


## Limitations

### ❗ No Native Version Parser

* Version extraction relies on LLM interpretation of strings
* May struggle with non-standard version formats and missing version data


### ❗ Scalability Issue

* All CVEs and assets may be passed to LLM for co-relation
* Can lead to increased latency, higher token usage and reduced efficiency at scale


### ❗ LLM Dependency

* Accuracy depends on prompt quality and model capability
* May cause hallucinations


### ❗ No Automated Validation 

* No programmatic verification of LLM decisions
* Incorrect reasoning may pass through if not reviewed


### ❗ No Exploit Intelligence

* Does not consider active exploitation, public exploit availability and threat prioritization

---



