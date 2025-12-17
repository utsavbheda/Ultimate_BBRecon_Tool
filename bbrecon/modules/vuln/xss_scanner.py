#!/usr/bin/env python3
import asyncio
import aiohttp
import hashlib
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode, quote
from dataclasses import dataclass
from typing import List, Optional
from enum import Enum

class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

@dataclass
class XSSFinding:
    url: str
    parameter: str
    payload: str
    method: str
    severity: Severity
    confidence: float
    evidence_file: str = ""

class XSSScanner:
    def __init__(self, output_dir, timeout: int = 15, rate_limit: float = 0.1):
        self.output_dir = output_dir
        self.timeout = timeout
        self.rate_limit = rate_limit
        self.findings = []
        self.scan_id = hashlib.md5(str(datetime.now()).encode()).hexdigest()[:6]
        self.marker = f"XSS_{self.scan_id}"
        self.core_payloads = [f"<script>alert('{self.marker}')</script>", f"'\"><script>alert('{self.marker}')</script>"]
        self.waf_bypasses = [lambda p: p, lambda p: quote(p)]

    async def _save_evidence(self, url, payload, text):
        evidence_dir = self.output_dir / "evidence"
        evidence_dir.mkdir(parents=True, exist_ok=True)
        filename = f"xss_{hashlib.md5(url.encode()).hexdigest()[:8]}.txt"
        with open(evidence_dir / filename, "w") as f:
            f.write(f"URL: {url}\nPayload: {payload}\nMarker: {self.marker}\n\nRESPONSE:\n{text[:2000]}")
        return str(evidence_dir / filename)

    async def _test_payload(self, session, url, param, payload):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = [payload]
        test_url = parsed._replace(query=urlencode(params, doseq=True)).geturl()
        try:
            await asyncio.sleep(self.rate_limit)
            async with session.get(test_url, timeout=self.timeout, ssl=False) as resp:
                text = await resp.text()
                if self.marker in text:
                    ev = await self._save_evidence(test_url, payload, text)
                    return XSSFinding(test_url, param, payload, "GET", Severity.HIGH, 1.0, ev)
        except: pass
        return None

    async def scan_targets(self, urls: List[str]):
        tasks = []
        for url in [u for u in urls if "?" in u and "=" in u]:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            async with aiohttp.ClientSession() as session:
                for param in params:
                    for core in self.core_payloads:
                        tasks.append(self._test_payload(session, url, param, core))
        results = await asyncio.gather(*tasks)
        return [r for r in results if r]
