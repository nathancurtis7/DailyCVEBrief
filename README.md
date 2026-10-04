# CVE Daily Brief

A lightweight Python script that pulls new CVEs from the NVD API, filters them against your own keyword list and a minimum CVSS score, cross-references against the CISA Known Exploited Vulnerabilities (KEV) catalogue, and writes a plain-text digest to disk.

Designed to run automatically each morning via Windows Task Scheduler (or any scheduler) so you have a relevant, filtered CVE list ready to action — without manually trawling NVD.

---

## Features

- Pulls CVEs published in the last 24 hours (configurable) from the NVD API
- Filters by your own keyword list — match against vendor names, product names, or any term in the CVE description
- Minimum CVSS v3.1 score filter to cut out low-severity noise
- Cross-references every matched CVE against the CISA KEV catalogue and flags actively exploited vulnerabilities
- Outputs a plain-text daily digest saved to disk
- Zero external dependencies beyond `requests`

---

## Prerequisites

- Python 3.8 or higher
- `requests` library

---

## Installation

**1. Clone the repository**

```bash
git clone https://github.com/YOUR_USERNAME/cve-daily-brief.git
cd cve-daily-brief
```

**2. Install the dependency**

```bash
pip install requests
```

**3. Create your config file**

Copy the example config and populate it with the vendors and products relevant to your environment:

```bash
cp config.example.json config.json
```

`config.json` is listed in `.gitignore` — your keyword list stays local and is never committed to the repository.

---

## Configuration

Edit `config.json`:

```json
{
  "lookback_hours": 24,
  "min_cvss_score": 7.0,
  "output_dir": "C:\\Users\\YourName\\Documents\\CVEBriefs",
  "keywords": [
    "Windows",
    "Microsoft",
    "Azure",
    "Cisco"
  ]
}
```

| Field | Description | Default |
|---|---|---|
| `lookback_hours` | How far back to search for new CVEs | `24` |
| `min_cvss_score` | Minimum CVSS v3.1 base score to include | `7.0` |
| `output_dir` | Folder to save the daily brief text file. Leave empty to save next to the script | `""` |
| `keywords` | List of terms to match against CVE descriptions. Case-insensitive. | `[]` |

If `keywords` is left empty, all CVEs above the score threshold are returned.

---

## Running Manually

```bash
python cve_brief.py
```

A dated text file (`DailyCVEBrief_YYYY-MM-DD.txt`) will be saved to your configured `output_dir`.

---

## Scheduling with Windows Task Scheduler

To run the script automatically each morning:

**Step 1 — Create a batch file**

Create a file called `run_cve_brief.bat` in the same folder as the script with the following content. Replace the paths with the actual locations on your machine:

```bat
@echo off
"C:\Users\YourName\AppData\Local\Programs\Python\Python311\python.exe" "C:\Path\To\cve_brief.py"
```

To find your Python path, open Command Prompt and run:
```
where python
```

**Step 2 — Open Task Scheduler**

Press `Win + S`, search for **Task Scheduler**, and open it.

**Step 3 — Create a new task**

1. In the right panel, click **Create Basic Task**
2. Name it `Daily CVE Brief` and click **Next**
3. Set trigger to **Daily** and click **Next**
4. Set the start time to your preferred morning time (e.g. `07:00:00 AM`) and click **Next**
5. Select **Start a program** and click **Next**
6. In **Program/script**, browse to your `run_cve_brief.bat` file
7. In **Start in**, enter the folder path where `cve_brief.py` lives (without quotes)
8. Click **Next**, then **Finish**

**Step 4 — Verify it works**

Right-click the task in Task Scheduler and select **Run**. Check your `output_dir` for the output file.

---

## Output Format

```
Daily CVE Brief — 2026-10-04
CVEs matched: 2
============================================================

CVE ID      : CVE-2026-XXXXX
Score       : 9.8 (CRITICAL)
In CISA KEV : YES — Actively exploited (CISA KEV)
Description : A remote code execution vulnerability in ...
Link        : https://nvd.nist.gov/vuln/detail/CVE-2026-XXXXX
------------------------------------------------------------

CVE ID      : CVE-2026-XXXXX
Score       : 7.5 (HIGH)
In CISA KEV : No
Description : An elevation of privilege vulnerability in ...
Link        : https://nvd.nist.gov/vuln/detail/CVE-2026-XXXXX
------------------------------------------------------------
```

---

## Data Sources

| Source | Purpose |
|---|---|
| [NVD (NIST)](https://nvd.nist.gov/) | Primary CVE database — new vulnerability disclosures |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Actively exploited vulnerability catalogue |

Both sources are free and require no API key.

---

## Notes

- NVD occasionally has API rate limits. If you receive HTTP 403 responses, wait a few minutes and re-run. For high-volume use, NVD offers API keys (free) at https://nvd.nist.gov/developers/request-an-api-key
- The script only matches CVEs that have a CVSS v3.1 score. CVEs published without a score yet (common in the first hours after disclosure) are excluded from score-based filtering but may still appear if they match keywords and have no score entry
