# 🔐 SecScan – Security Scanning CLI Tool

SecScan is a Python-based, cross-platform cybersecurity command-line tool designed to perform multithreaded port scanning and web security analysis.

This is an **ongoing and actively evolving project**. I built it to deepen my understanding of networking, web security, and how real-world security scanning tools operate. As I continue learning, I will regularly enhance and expand its capabilities.

---

## 🚀 Current Features

### 🖥️ Multithreaded TCP Port Scanner
- Scans predefined common service ports (FTP, SSH, HTTP, HTTPS, MySQL, RDP, etc.)
- Supports user-defined custom port ranges (e.g., `1-1000`)
- Uses `ThreadPoolExecutor` for concurrent scanning and improved performance
- Detects and displays open ports with associated services

### 🌐 Web Security Analysis
- Detects HTTP/HTTPS targets
- Retrieves and analyzes HTTP response headers
- Identifies missing important security headers:
  - `Strict-Transport-Security`
  - `Content-Security-Policy`
  - `X-Frame-Options`
  - `X-XSS-Protection`
  - `X-Content-Type-Options`

### 🧩 Technology Fingerprinting
- Detects backend technologies such as:
  - Apache
  - Nginx
  - Cloudflare
  - PHP
  - ASP.NET
  - Node.js Express

### ⚠️ Version Disclosure Detection
- Identifies potential information leakage from HTTP headers containing version numbers

---

## 🛠️ Technologies Used

- Python 3
- `socket` (TCP networking)
- `argparse` (CLI argument parsing)
- `requests` (HTTP communication)
- `concurrent.futures` (Multithreading)

---

## 📂 Project Structure

```
SecScan/
│
├── secscan.py              # Main CLI entry point
├── modules/
│   └── http_scanner.py     # Web scanning module
├── requirements.txt        # Project dependencies
└── README.md
```

---

## ⚙️ Installation

### 1️⃣ Clone the Repository

```bash
git clone https://github.com/ParthKadiya/SecScan.git
cd SecScan
```

### 2️⃣ Install Dependencies

```bash
pip install -r requirements.txt
```

---

## 💻 Usage

### 🔎 Scan Common Ports

```bash
python secscan.py --target example.com --scan port
```

### 🔎 Scan Custom Port Range

```bash
python secscan.py --target example.com --scan port --ports 1-1000
```

### 🌐 Run Full Scan (Port + Web Analysis)

```bash
python secscan.py --target example.com --scan full
```

---

## 🎯 What I Learned From This Project

- How TCP port scanning works using low-level socket programming  
- How multithreading significantly improves scanning performance  
- How HTTP headers reveal security misconfigurations  
- How technology fingerprinting is performed in security tools  
- How to structure modular cybersecurity applications  
- How professional CLI-based security tools are architected  

This project strengthened my practical understanding of networking and security assessment methodologies.

---

## 🔄 Ongoing Development

This is an actively maintained project.

### Planned Future Improvements

- JSON and HTML report generation  
- CMS detection (WordPress, Django, Laravel)  
- SSL/TLS certificate analysis  
- CVE vulnerability mapping  
- Risk scoring system  
- Improved fingerprinting logic  
- Enhanced error handling and optimization  

I will continue updating and expanding this tool as I grow in cybersecurity expertise.

---

## ⚠️ Disclaimer

This tool is developed strictly for educational purposes.  
Only scan systems that you own or have explicit permission to test.
