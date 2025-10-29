from __future__ import annotations
from typing import List, Dict


import dns.resolver


from models import DNSResult
from agents.base import BaseAgent
from settings import DNS_TIMEOUT, DEFAULT_SUBDOMAIN_WORDLIST, MAX_SUBDOMAIN_BRUTE

class DNSAgent(BaseAgent):
    name = "dns"


    def _q(self, resolver: dns.resolver.Resolver, domain: str, rtype: str) -> List[str]:
        try:
            ans = resolver.resolve(domain, rtype, lifetime=DNS_TIMEOUT)
            out: List[str] = []
            for r in ans:
                s = r.to_text()
                if rtype == "TXT":
                    # TXT може бути в лапках і з кількох частин
                    s = s.replace('"', '').strip()
                    out.append(s)
            return out
        except Exception:
            return []


    def _bruteforce_subdomains(self, resolver: dns.resolver.Resolver, domain: str) -> List[str]:
        found: List[str] = []
        for i, sub in enumerate(DEFAULT_SUBDOMAIN_WORDLIST):
            if i >= MAX_SUBDOMAIN_BRUTE:
                break
            fqdn = f"{sub}.{domain}"
            try:
                ans = resolver.resolve(fqdn, "A", lifetime=DNS_TIMEOUT)
                if ans: # якщо є відповідь — фіксуємо субдомен
                    found.append(fqdn)
            except Exception:
                pass
        # Унікалізація із збереженням порядку
        seen = set()
        uniq: List[str] = []
        for x in found:
            if x not in seen:
                uniq.append(x)
                seen.add(x)
        return uniq


    def run(self, domain: str) -> DNSResult:
        resolver = dns.resolver.Resolver()
        resolver.timeout = DNS_TIMEOUT
        resolver.lifetime = DNS_TIMEOUT


        records: Dict[str, List[str]] = {}
        for rtype in ["A", "AAAA", "NS", "MX", "TXT", "CNAME", "SOA"]:
            vals = self._q(resolver, domain, rtype)
            if vals:
                records[rtype] = vals


        subdomains = self._bruteforce_subdomains(resolver, domain)
        return DNSResult(records=records, subdomains_found=subdomains)