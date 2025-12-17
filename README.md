# 🔍 Ultimate BBRecon Tool

Ultimate BBRecon Tool is a professional, autonomous bug bounty reconnaissance and vulnerability scanning framework.
It unifies attack surface discovery, deep infrastructure scanning, and focused vulnerability detection into a single, streamlined workflow with a central reporting dashboard.

## 📌 Project Information

- Version: 5.0.3 (Ultimate Edition)
- Author: Utsav Bheda
- License: MIT

## 🧠 What This Tool Does

Ultimate BBRecon is designed for bug bounty hunters, penetration testers, and security professionals who want:
- Automated reconnaissance
- Safe, scope-aware scanning
- High-signal vulnerability detection
- Clear, actionable reporting

It reduces tool sprawl by orchestrating multiple industry-standard tools under one command-line interface.

## 🌟 Key Features
### 🌐 Automated Reconnaissance

- Subdomain discovery using Subfinder
- Historical endpoint enumeration via Waybackurls
- Port discovery using Naabu
- Live host probing with Httpx
- Full attack surface mapping

### 📡 Deep Infrastructure Scanning

- Integrated Nmap engine
- Open port discovery
- Service and version detection

### ⚔️ Vulnerability Engines

- Advanced XSS
- Context-aware parameter fuzzing
- WAF bypass techniques
- SQL Injection
- Error-based SQLi detection
- Secrets Hunter
- Scans JavaScript and JSON files

### Detects leaks:

- AWS keys
- Stripe keys
- Google API keys

### 🛡️ Safety & Control

Scope Enforcer to prevent accidental out-of-scope scans
Stealth Mode for low-and-slow scanning to reduce WAF detection

### 📊 Smart Reporting

- Auto-generated HTML dashboard
- Direct links to:
- Raw scan outputs
- Verified proof-of-concept files
- Clean folder structure for each target and scan session

### 🚀 Installation

Prerequisites
- Python 3.9+
- Go (Golang)

## Quick Start
# 1. Clone the repository
```bash
git clone https://github.com/utsavbheda/Ultimate_BBRecon_Tool.git
cd Ultimate_BBRecon_Tool
```

# 2. Install Python dependencies
```bash
pip install -e .
```

# 3. Install external tools
```bash
chmod +x install_tools.sh
./install_tools.sh
```

# 4. Add Go binaries to PATH
```bash
export PATH=$PATH:$HOME/go/bin
```

## ⚙️ Configuration
### 1️⃣ API Keys (Recommended)

For better results with Subfinder, configure API keys:
```bash
nano ~/.config/subfinder/provider-config.yaml
```

### 2️⃣ Scope Definition (Highly Recommended)

Create a scope.txt file to prevent scanning restricted assets:
```bash
nano scope.txt
```
Example:
admin.target.com
internal.target.com

## 🎮 Usage Guide

### 💥 Full Ultimate Scan
Runs Recon + Nmap + XSS + Secrets + SQLi modules:
```bash
bbrecon scan target.com --nmap --xss --secrets --sqli --scope scope.txt
```

### 🕵️ Stealth Mode
Slower scanning to evade WAFs:
```bash
bbrecon scan target.com --stealth --xss
```

### 🛠️ Dependency Check
Verify that all required tools are installed:
```bash
bbrecon tools
```

### 📊 Output & Reporting

All results are stored in the bbrecon_output/ directory.
Example Structure

bbrecon_output/
└── target.com/
    └── 20251217_120000/
        ├── report.html        # Main dashboard
        ├── nmap_scan.nmap     # Raw Nmap output
        ├── subdomains.txt
        └── evidence/
            ├── xss_a1b2c3.txt
            └── ...
