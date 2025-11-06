# New files and updated modules to split WHOIS/OSINT into separate CRT and Shodan agents.
# The canvas contains 4 file blocks. Save each into your project accordingly.

# ===== File: agents/crt_agent.py =====
from __future__ import annotations
from typing import List
import requests

from agents.base import BaseAgent
from models import CrtResult


class CrtAgent(BaseAgent):
    """Agent that queries crt.sh for passive certificate-based enumeration.

    Methods:
    passive_subdomains(domain) -> list[str]
    run(domain) -> OSINTResult
    """

    name = "crtsh"

    def passive_subdomains(self, domain: str) -> List[str]:
        """Return list of domains discovered via crt.sh (best-effort).
        Uses the public crt.sh JSON endpoint: https://crt.sh/?q=%25<domain>&output=json
        """
        try:
            # ВАЖЛИВО: використовуємо params, щоб requests сам закодував % як %25
            params = {"q": f"%.{domain}", "output": "json"}
            headers = {"User-Agent": "Mozilla/5.0 (compatible; DomainIntellect/1.0)", "Accept": "application/json"}

            r = requests.get("https://crt.sh/", params=params, headers=headers, timeout=60)
            ct = r.headers.get("Content-Type", "")

            # деякі відповіді можуть містити службовий префікс у body; підстрахуємось
            text = r.text.strip()
            if "json" not in ct.lower():
                # спроба вирізати JSON, якщо crt.sh вивів службові рядки
                if "[" in text and "]" in text:
                    import json, re
                    m = re.search(r"(\[.*\])", text, re.S)
                    if m:
                        data = json.loads(m.group(1))
                    else:
                        print("crt.sh returned non-JSON response:", text[:200])
                        return []
                else:
                    print("crt.sh returned non-JSON response:", text[:200])
                    return []
            else:
                data = r.json()

            names = set()
            for item in data:
                name = item.get("name_value") or item.get("common_name")
                if not name:
                    continue
                for n in str(name).split("\n"):
                    n = n.strip().lower()
                    if n:
                        names.add(n)
            return sorted(names)
        except Exception as e:
            print("crt.sh error:", e)
            return []

    def run(self, domain: str) -> CrtResult:
        names = self.passive_subdomains(domain)
        return CrtResult(domain=domain, crtsh_names=names)
