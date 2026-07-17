# 🔍 Subdomain Takeover Scanner

[![PyPI version](https://img.shields.io/pypi/v/subdomain-takeover-scanner)](https://pypi.org/project/subdomain-takeover-scanner/)
[![Publish to PyPI](https://github.com/adarshvardhansingh12/subdomain-takeover-scanner/actions/workflows/publish.yml/badge.svg)](https://github.com/adarshvardhansingh12/subdomain-takeover-scanner/actions/workflows/publish.yml)

A Python tool that discovers subdomains and checks them for takeover vulnerabilities against AWS S3, GitHub Pages, and Azure.

> ⚠️ **For authorized use only. Always obtain written permission before scanning.**

---

## ⚡ Quick Install

```bash
pip install subdomain-takeover-scanner
```

Then run it from anywhere:

```bash
subtakeover -d example.com
```

---

## 🧠 How It Works

1. **Passive recon** — Queries crt.sh (Certificate Transparency logs) for known subdomains
2. **Active brute-force** — Resolves subdomains from a wordlist via multi-threaded DNS
3. **CNAME matching** — Checks CNAME records against known vulnerable cloud service patterns
4. **HTTP fingerprinting** — Fetches each subdomain and looks for "unclaimed" error pages
5. **Reporting** — Outputs terminal table, HTML dashboard, and PDF report

---

## ⚙️ Setup (from source)

### 1. Clone the repository

```bash
git clone https://github.com/adarshvardhansingh12/subdomain-takeover-scanner.git
cd subdomain-takeover-scanner
```

### 2. Create virtual environment

```bash
python3 -m venv venv
```

### 3. Activate virtual environment

**Linux / Kali / macOS**
```bash
source venv/bin/activate
```

**Windows**
```bash
venv\Scripts\activate
```

### 4. Install dependencies

```bash
pip install -r requirements.txt
```

### 5. Verify installation (optional)

```bash
python3 main.py -h
```

---

## 🚀 Usage

```bash
# If installed via pip:
subtakeover -d example.com

# If running from source:
python3 main.py -d example.com

# Passive only (no brute-force)
subtakeover -d example.com --no-bruteforce

# Custom wordlist + output name
subtakeover -d example.com -w wordlists/subdomains.txt -o results/example_scan

# More threads for faster scanning
subtakeover -d example.com -t 50
```

---

## 📊 Output

Each run produces:

- 🖥️ **Terminal** — color-coded findings table with severity and confidence
- 🌐 **HTML report** — executive summary cards + full findings + all subdomains table
- 📄 **PDF report** — professional pentest-style report with remediation steps

---

## ☁️ Supported Takeover Services

| Service | Severity | Detection Method |
| --- | --- | --- |
| AWS S3 | Critical | CNAME + `NoSuchBucket` response |
| GitHub Pages | High | CNAME + `There isn't a GitHub Pages site here` |
| Azure | Critical | CNAME + `404 Web Site not found` |

---

## 📁 Project Structure

```
subdomain-takeover-scanner/
├── main.py
├── pyproject.toml
├── scanner/
│   ├── enumerator.py
│   ├── detector.py
│   ├── fingerprints.py
├── reports/
│   ├── html_report.py
│   ├── pdf_report.py
│   ├── terminal_report.py
├── wordlists/
├── requirements.txt
├── README.md
└── .gitignore
```

---

## 🛠️ Troubleshooting

**"subtakeover is not recognized as an internal or external command" (Windows)**

This means pip installed the tool successfully, but the folder containing `subtakeover.exe` isn't in your system PATH. This is a common Windows/Python setup issue, not a bug in the tool itself — it usually happens if Python was installed without checking "Add Python to PATH," or via the Microsoft Store.

1. **Find where it installed:**
   ```bash
   pip show -f subdomain-takeover-scanner
   ```
   Look for `subtakeover.exe` in the file list, and note the `Location:` line above it. The Scripts folder is one level up from that location, e.g.:
   ```
   ...\Python\pythoncore-3.14-64\Scripts
   ```

2. **Add that Scripts folder to your PATH:**
   - Press the Windows key → search **"Environment Variables"** → open **"Edit the system environment variables"**
   - Click **"Environment Variables..."**
   - Under **"User variables"**, select **Path** → click **Edit** → **New**
   - Paste the Scripts folder path → OK on all dialogs

3. **Close and reopen your terminal completely** (not just a new tab — the whole app), then try again:
   ```bash
   subtakeover -d example.com
   ```

**Quick workaround without editing PATH:**
Run the tool with its full path directly:
```bash
"<path-to-scripts-folder>\subtakeover.exe" -d example.com
```

**macOS / Linux users** essentially never hit this — pip installs console scripts into a location that's already on PATH by default (e.g. `~/.local/bin` or your virtualenv's `bin/`).

---

## ⚠️ Limitations

- Depends on external APIs (may fail or rate-limit)
- Possible false positives
- Limited fingerprint database
- No rate limiting (yet)

---

## 🚀 Roadmap

- [x] crt.sh passive enumeration
- [x] Multi-threaded DNS brute-force
- [x] AWS S3 / GitHub Pages / Azure detection
- [x] HTML + PDF + terminal reports
- [x] PyPI package + automated release pipeline
- [ ] Heroku / Netlify / Fastly fingerprints
- [ ] Slack/email alerting
- [ ] CI/CD integration mode

---

## 💼 Resume Line

> *Built a subdomain takeover scanner that combines passive CT log enumeration (crt.sh) with active DNS brute-forcing and HTTP fingerprinting to detect unclaimed AWS S3, GitHub Pages, and Azure resources. Generates PDF/HTML pentest reports with remediation guidance. Published as an installable Python package on PyPI with an automated GitHub Actions release pipeline.*

---

## 🤝 Contributors

- Adarsh Vardhan Singh
- Lincy Pandit

---

## ⭐ Support

If you found this useful:

- ⭐ Star the repo
- 🍴 Fork it
- 🛠️ Contribute improvements
