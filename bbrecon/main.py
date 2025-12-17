#!/usr/bin/env python3
"""
BBRecon - Professional Bug Bounty Reconnaissance & Vulnerability Scanner
Version: 5.0.3 (Ultimate Edition + Tool Checker)
"""

import os
import sys
import asyncio
import argparse
import json
import logging
import shutil
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, field
from typing import Optional, List, Set

# Import Custom Modules
from bbrecon.modules.recon.nmap import NmapScanner
from bbrecon.modules.vuln.xss_scanner import XSSScanner
from bbrecon.modules.vuln.secrets_scanner import SecretsScanner
from bbrecon.modules.vuln.sqli_scanner import SQLiScanner

try:
    import aiohttp
except ImportError:
    print("[!] Missing dependency: aiohttp")
    sys.exit(1)

# === Constants ===
VERSION = "5.0.3"
DEFAULT_OUTPUT = Path("./bbrecon_output")
CONFIG_DIR = Path.home() / ".bbrecon"
CONFIG_FILE = CONFIG_DIR / "config.json"

# === Console Output ===
class Console:
    COLORS = {
        'red': '\033[91m', 'green': '\033[92m', 'blue': '\033[94m',
        'yellow': '\033[93m', 'magenta': '\033[95m', 'cyan': '\033[96m', 'reset': '\033[0m', 'bold': '\033[1m'
    }
    @classmethod
    def banner(cls):
        print(f"\n{cls.COLORS['blue']}{cls.COLORS['bold']}    BBRecon v{VERSION} (Ultimate Edition){cls.COLORS['reset']}\n")
    @classmethod
    def section(cls, title): print(f"\n{cls.COLORS['blue']}{cls.COLORS['bold']}=== {title.upper()} ==={cls.COLORS['reset']}")
    @classmethod
    def success(cls, msg): print(f"{cls.COLORS['green']}[+] {msg}{cls.COLORS['reset']}")
    @classmethod
    def error(cls, msg): print(f"{cls.COLORS['red']}[-] {msg}{cls.COLORS['reset']}")
    @classmethod
    def info(cls, msg): print(f"{cls.COLORS['cyan']}[*] {msg}{cls.COLORS['reset']}")
    @classmethod
    def warning(cls, msg): print(f"{cls.COLORS['yellow']}[!] {msg}{cls.COLORS['reset']}")

# === Tool Checker ===
class ToolChecker:
    """Checks if external dependencies are installed."""
    
    REQUIRED_TOOLS = ['subfinder', 'waybackurls', 'nuclei', 'nmap', 'naabu', 'httpx']
    
    @classmethod
    def check(cls):
        Console.section("Tool Availability Check")
        all_present = True
        
        for tool in cls.REQUIRED_TOOLS:
            path = shutil.which(tool)
            if path:
                print(f"{Console.COLORS['green']}[✓] {tool:<15} found at {path}{Console.COLORS['reset']}")
            else:
                print(f"{Console.COLORS['red']}[✗] {tool:<15} NOT FOUND{Console.COLORS['reset']}")
                all_present = False
        
        if not all_present:
            Console.warning("\nSome tools are missing. Make sure your PATH is correct:")
            print("export PATH=$PATH:$HOME/go/bin")
        else:
            Console.success("\nAll tools are ready for the Ultimate Scan!")

# === Configuration ===
@dataclass
class Config:
    output_dir: str = str(DEFAULT_OUTPUT)
    mode: str = "normal"
    out_of_scope: List[str] = field(default_factory=list)
    rate_limit: float = 0.1

    @classmethod
    def load(cls):
        if not CONFIG_FILE.exists():
            CONFIG_DIR.mkdir(exist_ok=True)
            default_conf = cls()
            with open(CONFIG_FILE, 'w') as f: json.dump(default_conf.__dict__, f)
        with open(CONFIG_FILE) as f:
            data = json.load(f)
            return cls(**data)

    def is_in_scope(self, target: str) -> bool:
        for blocked in self.out_of_scope:
            if blocked in target: return False
        return True

# === Target Data ===
@dataclass
class Target:
    domain: str
    output_dir: Path = None
    is_live: bool = False
    live_url: str = ""
    subdomains: Set[str] = field(default_factory=set)
    urls: Set[str] = field(default_factory=set)
    open_ports: List[int] = field(default_factory=list)
    nuclei_findings: List[dict] = field(default_factory=list)
    xss_findings: List[object] = field(default_factory=list)
    sqli_findings: List[object] = field(default_factory=list)
    secret_findings: List[object] = field(default_factory=list)
    nmap_file: str = ""
    
    def __post_init__(self):
        if self.output_dir is None:
            safe_name = self.domain.replace('/', '_')
            self.output_dir = DEFAULT_OUTPUT / safe_name / datetime.now().strftime("%Y%m%d_%H%M%S")

# === Report Generator ===
class ReportGenerator:
    @staticmethod
    def generate_html(target: Target, output_path: Path) -> str:
        # Secrets
        if target.secret_findings:
            secrets_html = ''.join(f'<div style="margin-bottom:5px"><span class="badge high">SECRET</span> <strong>{s.type}</strong> in {s.url}</div>' for s in target.secret_findings)
        else: secrets_html = "<p>No secrets found.</p>"

        # SQLi
        if target.sqli_findings:
            sqli_html = ''.join(f'<div style="margin-bottom:5px"><span class="badge critical">SQLi</span> <strong>{s.url}</strong> (Error: {s.error_msg})</div>' for s in target.sqli_findings)
        else: sqli_html = "<p>No SQLi found.</p>"

        # XSS
        if target.xss_findings:
            xss_html = ''.join(f'<div style="margin-bottom:5px"><span class="badge high">XSS</span> <strong>{x.url}</strong></div>' for x in target.xss_findings)
        else: xss_html = "<p>No XSS found.</p>"

        # Nuclei
        nuclei_html = ''.join(f'<p><span class="badge {v.get("info",{}).get("severity","low")}">{v.get("info",{}).get("severity","?").upper()}</span> {v.get("info",{}).get("name","Unknown")}</p>' for v in target.nuclei_findings[:20])

        status_symbol = '🟢 Live' if target.is_live else '🔴 Down'
        scan_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        html = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>BBRecon - {target.domain}</title>
<style>
body{{font-family:system-ui;background:#1a1a2e;color:#eee;padding:2rem}}
.container{{max-width:1100px;margin:0 auto}}
.card{{background:rgba(255,255,255,0.05);padding:1.5rem;margin-bottom:1rem;border-radius:10px;border:1px solid #333}}
h1{{color:#00d4ff}} h2{{color:#7b2cbf;border-bottom:1px solid #444;padding-bottom:0.5rem}}
.badge{{padding:3px 8px;border-radius:4px;font-size:0.8em;font-weight:bold}}
.critical{{background:#ff0000;color:white}} .high{{background:#ff6600;color:black}}
</style></head><body><div class="container">
<h1>🔍 BBRecon Report: {target.domain}</h1>
<div class="card">
    <p><strong>Scan Date:</strong> {scan_time}</p>
    <p><strong>Status:</strong> {status_symbol}</p>
    <p><strong>Stats:</strong> {len(target.subdomains)} Subs | {len(target.urls)} URLs | {len(target.open_ports)} Ports</p>
</div>
<div class="card"><h2>🔑 Secret Findings ({len(target.secret_findings)})</h2>{secrets_html}</div>
<div class="card"><h2>💉 SQL Injection ({len(target.sqli_findings)})</h2>{sqli_html}</div>
<div class="card"><h2>🚨 XSS Findings ({len(target.xss_findings)})</h2>{xss_html}</div>
<div class="card"><h2>☢️ Nuclei Findings ({len(target.nuclei_findings)})</h2>{nuclei_html}</div>
<div class="card"><h2>📡 Network</h2><p><strong>Nmap File:</strong> {target.nmap_file or "Not run"}</p></div>
</div></body></html>"""
        
        with open(output_path, 'w') as f: f.write(html)
        return str(output_path)

# === Main Engine ===
class BBReconEngine:
    def __init__(self, config: Config):
        self.config = config
    
    async def run_tool(self, cmd: list, timeout=300):
        try:
            proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            return (proc.returncode == 0, stdout.decode('utf-8', errors='ignore'))
        except: return (False, "")

    async def check_liveness(self, target: Target):
        if not self.config.is_in_scope(target.domain): return False
        async with aiohttp.ClientSession() as session:
            try:
                async with session.head(f"https://{target.domain}", timeout=10, ssl=False) as r:
                    if r.status < 500: target.is_live, target.live_url = True, str(r.url); return True
            except: pass
            try:
                async with session.head(f"http://{target.domain}", timeout=10) as r:
                    if r.status < 500: target.is_live, target.live_url = True, str(r.url); return True
            except: pass
        return False

    async def run_subdomains(self, target: Target):
        Console.section("Subdomain Enumeration")
        Console.progress("Running Subfinder...")
        success, out = await self.run_tool(['subfinder', '-d', target.domain, '-silent'])
        if success:
            subs = {line.strip() for line in out.split('\n') if line.strip()}
            target.subdomains = subs
            Console.success(f"Found {len(subs)} subdomains")

    async def run_urls(self, target: Target):
        Console.section("URL Discovery")
        Console.progress("Running Waybackurls...")
        success, out = await self.run_tool(['waybackurls', target.domain])
        if success:
            urls = {line.strip() for line in out.split('\n') if line.strip()}
            target.urls = urls
            Console.success(f"Found {len(urls)} URLs")

    async def run_nuclei(self, target: Target):
        Console.section("Nuclei Scan")
        json_out = target.output_dir / "nuclei.json"
        Console.progress("Running Nuclei...")
        await self.run_tool(['nuclei', '-u', target.live_url or target.domain, '-silent', '-json-export', str(json_out)])
        if json_out.exists():
            with open(json_out) as f:
                target.nuclei_findings = [json.loads(line) for line in f if line.strip()]
            Console.success(f"Findings: {len(target.nuclei_findings)}")

    async def run_nmap(self, target: Target):
        Console.section("Nmap Scan")
        scanner = NmapScanner(target.output_dir)
        if await scanner.check_availability():
            targets = [target.domain] + list(target.subdomains)
            targets = [t for t in targets if self.config.is_in_scope(t)][:5]
            res = await scanner.scan_targets(targets, mode=self.config.mode)
            if res: target.nmap_file = res; Console.success("Nmap Done")

    async def run_xss(self, target: Target):
        Console.section("XSS Scan")
        scanner = XSSScanner(target.output_dir, rate_limit=self.config.rate_limit)
        scan_list = [u for u in target.urls if "?" in u and "=" in u]
        if not scan_list and target.live_url: scan_list = [target.live_url]
        Console.info(f"Fuzzing {len(scan_list)} URLs...")
        target.xss_findings = await scanner.scan_targets(scan_list)
        if target.xss_findings: Console.success(f"Found {len(target.xss_findings)} XSS!")

    async def run_secrets(self, target: Target):
        Console.section("Secrets Hunt")
        scanner = SecretsScanner(target.output_dir)
        Console.info(f"Scanning {len(target.urls)} assets for keys...")
        target.secret_findings = await scanner.scan_targets(list(target.urls))
        if target.secret_findings:
            Console.success(f"CRITICAL: Found {len(target.secret_findings)} Secrets!")
            for s in target.secret_findings: print(f"    - {s.type}: {s.match} in {s.url}")
        else: Console.info("No secrets found.")

    async def run_sqli(self, target: Target):
        Console.section("SQL Injection Scan")
        scanner = SQLiScanner(target.output_dir)
        scan_list = [u for u in target.urls if "?" in u and "=" in u]
        if not scan_list and target.live_url: scan_list = [target.live_url]
        Console.info(f"Injecting SQL payloads into {len(scan_list)} URLs...")
        target.sqli_findings = await scanner.scan_targets(scan_list)
        if target.sqli_findings:
            Console.success(f"CRITICAL: Found {len(target.sqli_findings)} SQLi Vulnerabilities!")
            for s in target.sqli_findings: print(f"    - URL: {s.url} (Error: {s.error_msg})")
        else: Console.info("No SQLi found.")

    async def full_scan(self, target: Target, args):
        target.output_dir.mkdir(parents=True, exist_ok=True)
        Console.banner()
        Console.info(f"Starting Ultimate Scan on {target.domain}")
        
        if await self.check_liveness(target):
            await self.run_subdomains(target)
            await self.run_urls(target)
            if not args.skip_nuclei: await self.run_nuclei(target)
            if args.nmap: await self.run_nmap(target)
            if args.xss: await self.run_xss(target)
            if args.secrets: await self.run_secrets(target)
            if args.sqli: await self.run_sqli(target)
            ReportGenerator.generate_html(target, target.output_dir / "report.html")
            Console.success(f"Report: {target.output_dir}/report.html")

async def async_main():
    parser = argparse.ArgumentParser(description=f'BBRecon v{VERSION}')
    parser.add_argument('command', choices=['scan', 'tools'])
    parser.add_argument('target', nargs='?', help='Target domain')
    
    parser.add_argument('--nmap', action='store_true', help='Enable Nmap')
    parser.add_argument('--xss', action='store_true', help='Enable XSS')
    parser.add_argument('--secrets', action='store_true', help='Enable Secrets Hunt')
    parser.add_argument('--sqli', action='store_true', help='Enable SQLi')
    parser.add_argument('--stealth', action='store_true', help='Slow mode')
    parser.add_argument('--scope', type=str, help='Scope file')
    parser.add_argument('--skip-nuclei', action='store_true', help='Skip Nuclei')
    
    args = parser.parse_args()
    config = Config.load()
    if args.stealth: config.mode = "stealth"; config.rate_limit = 1.0
    if args.scope: 
        try:
            with open(args.scope) as f: config.out_of_scope = [l.strip() for l in f if l.strip()]
        except: pass

    engine = BBReconEngine(config)
    
    if args.command == 'scan':
        if not args.target: Console.error("Target required"); return
        await engine.full_scan(Target(domain=args.target), args)
    elif args.command == 'tools':
        ToolChecker.check()

def main(): asyncio.run(async_main())

if __name__ == "__main__": main()
