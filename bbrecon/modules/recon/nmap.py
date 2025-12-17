
import asyncio
import shutil
from typing import List
from pathlib import Path

class NmapScanner:
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.nmap_path = shutil.which("nmap")

    async def check_availability(self) -> bool: return self.nmap_path is not None

    async def scan_targets(self, targets: List[str], mode: str = "normal") -> str:
        if not targets: return ""
        timing = "-T2" if mode == "stealth" else "-T4"
        output_base = self.output_dir / "nmap_scan"
        target_file = self.output_dir / "nmap_targets.txt"
        with open(target_file, "w") as f:
            for t in targets: f.write(f"{t}\n")
        cmd = ["nmap", "-sC", "-sV", "-Pn", timing, "--open", "-iL", str(target_file), "-oA", str(output_base)]
        print(f"\n[INFO] Starting Nmap ({mode} mode)...")
        try:
            proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            stdout, stderr = await proc.communicate()
            if proc.returncode == 0: return str(output_base) + ".nmap"
        except: pass
        return ""
