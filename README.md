# 🔍 Subdomain Takeover Scanner

A Python-based security tool that discovers subdomains and identifies potential **subdomain takeover vulnerabilities** caused by dangling CNAME records and misconfigured DNS.

> ⚠️ **For authorized security testing only. Always obtain proper permission before scanning any domain.**

---

## 🚀 Features

* 🔎 Multi-source subdomain enumeration (crt.sh, OTX, RapidDNS, subfinder)
* ⚠️ Detection of **dangling CNAMEs**
* 🧠 Fingerprint-based vulnerability detection (AWS, GitHub Pages, Azure, etc.)
* ⚡ Multithreaded scanning for faster performance
* 📊 HTML, PDF, and terminal report generation
* 🧩 Modular and extensible architecture

---

## ⚙️ Installation

```bash
git clone https://github.com/adarshvardhansingh12/subdomain-takeover-scanner.git
cd subdomain-takeover-scanner
pip install -r requirements.txt
```

---

## 🧪 Usage

### Basic Scan (Passive + Brute-force)

```bash
python3 main.py -d example.com
```

### Passive Only (No brute-force)

```bash
python3 main.py -d example.com --no-bruteforce
```

### Custom Wordlist + Output Name

```bash
python3 main.py -d example.com -w wordlists/subdomains.txt -o results/example_scan
```

### Faster Scan with More Threads

```bash
python3 main.py -d example.com -t 50
```

---

## 🧠 How It Works

```
Target Domain
      ↓
Subdomain Enumeration
(crt.sh, OTX, RapidDNS, subfinder)
      ↓
DNS Resolution (CNAME + A records)
      ↓
Dangling CNAME Detection
      ↓
Fingerprint Matching (AWS, GitHub, Azure, etc.)
      ↓
Report Generation (HTML, PDF, Terminal)
```

---

## 📂 Project Structure

```
subdomain-takeover-scanner/
├── main.py
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

## 📊 Output

The tool generates:

* 🖥️ Terminal output (live results)
* 🌐 HTML report (detailed dashboard)
* 📄 PDF report (for documentation)

---

## ⚠️ Limitations

* Depends on external APIs (may fail or rate limit)
* Possible false positives in detection
* Static fingerprint database
* No built-in rate limiting (yet)

---

## 🚀 Future Scope

* Async scanning for better performance
* Expand fingerprint database
* Integration with tools like Nuclei
* Real-time monitoring system

---

## 🤝 Contributors

* Adarsh Vardhan Singh
* *(Add your friend’s name here)*

---

## 📜 License

This project is for educational and ethical security research purposes only.

---

## ⭐ Support

If you found this useful:

* ⭐ Star the repo
* 🍴 Fork it
* 🛠️ Contribute improvements

---

## 💡 Inspiration

Inspired by real-world bug bounty methodologies and subdomain takeover research.
