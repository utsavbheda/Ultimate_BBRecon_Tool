#!/usr/bin/env python3
import asyncio
import aiohttp
from dataclasses import dataclass
from urllib.parse import urlparse, parse_qs, urlencode

@dataclass
class SQLiFinding:
    url: str
    parameter: str
    payload: str
    error_msg: str

class SQLiScanner:
    PAYLOADS = ["'", '"']
    ERRORS = ["SQL syntax", "mysql_fetch", "ORA-01756", "PostgreSQL query failed"]
    def __init__(self, output_dir): self.output_dir = output_dir

    async def scan_targets(self, urls):
        findings = []
        async with aiohttp.ClientSession() as session:
            tasks = []
            for url in [u for u in urls if "?" in u and "=" in u]:
                parsed = urlparse(url)
                for param in parse_qs(parsed.query):
                    for pl in self.PAYLOADS:
                        tasks.append(self._test(session, url, param, pl))
            results = await asyncio.gather(*tasks)
            findings = [r for r in results if r]
        return findings

    async def _test(self, session, url, param, payload):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = [payload]
        test_url = parsed._replace(query=urlencode(params, doseq=True)).geturl()
        try:
            async with session.get(test_url, timeout=10, ssl=False) as resp:
                text = await resp.text()
                for err in self.ERRORS:
                    if err in text: return SQLiFinding(test_url, param, payload, err)
        except: pass
        return None
