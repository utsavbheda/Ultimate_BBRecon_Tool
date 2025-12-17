#!/usr/bin/env python3
import asyncio
import aiohttp
import re
from dataclasses import dataclass

@dataclass
class SecretFinding:
    url: str
    type: str
    match: str

class SecretsScanner:
    PATTERNS = {
        'AWS Key': r'(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}',
        'Google Key': r'AIza[0-9A-Za-z\\-_]{35}',
    }
    def __init__(self, output_dir):
        self.output_dir = output_dir
        self.findings = []
        self.scanned = set()

    async def scan_targets(self, urls):
        target_urls = [u for u in urls if u.endswith('.js') or u.endswith('.json')]
        async with aiohttp.ClientSession() as session:
            await asyncio.gather(*[self._scan(session, u) for u in target_urls])
        return self.findings

    async def _scan(self, session, url):
        if url in self.scanned: return
        self.scanned.add(url)
        try:
            async with session.get(url, timeout=10, ssl=False) as resp:
                text = await resp.text()
                for name, pat in self.PATTERNS.items():
                    for match in re.findall(pat, text):
                        self.findings.append(SecretFinding(url, name, str(match)[:15]))
        except: pass
