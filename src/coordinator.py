from __future__ import annotations

import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed

from agents.dns_agent import DNSAgent
from agents.ssl_agent import SSLAgent
from agents.whois_agent import WhoisAgent
from agents.crt_agent import CrtAgent
from agents.shodan_agent import ShodanAgent
from agents.virustotal_agent import VirusTotalAgent

from models import DomainResult, CrtResult, ShodanResult
from settings import ENABLE_CREWAI

import socket

def _resolve_ipv4_bulk(hosts: list[str]) -> list[str]:
    """Резолвить список хостів у IPv4 через системний резолвер (getaddrinfo)."""
    ips = set()
    for h in hosts:
        try:
            for info in socket.getaddrinfo(h, None):
                ip = info[4][0]
                if ip and ip.count(".") == 3:
                    ips.add(ip)
        except Exception:
            continue
    return list(ips)

class Coordinator:
    """Координатор: запускає підлеглі агенти паралельно та агрегує результати."""


    def __init__(self, use_crewai: bool | None = None, max_workers: int = 4) -> None:
        self.use_crewai = ENABLE_CREWAI if use_crewai is None else use_crewai
        self.max_workers = max_workers

    def run_for_domain(self, domain: str) -> DomainResult:
        result = DomainResult(domain=domain)

        whois_agent = WhoisAgent()
        dns_agent = DNSAgent()
        ssl_agent = SSLAgent()
        crt_agent = CrtAgent()
        shodan_agent = ShodanAgent()
        virustotal_agent = VirusTotalAgent()

        # 1) пасивні субдомени через crt.sh (один раз)
        try:
            passive_subs = crt_agent.passive_subdomains(domain)
        except Exception as e:
            result.add_error("crt.passive_subdomains", e)
            passive_subs = []

        dns_agent.set_shared("passive_subs", passive_subs)

        # 2) Тепер паралельно запускаємо whois/dns/ssl
        with ThreadPoolExecutor(max_workers=self.max_workers) as ex:
            futures = {
                ex.submit(whois_agent.run, domain): "whois",
                ex.submit(dns_agent.run, domain): "dns",
                ex.submit(ssl_agent.run, domain): "ssl",
            }
            intermediate = {}
            for fut in as_completed(futures):
                name = futures[fut]
                try:
                    intermediate[name] = fut.result()
                except Exception as e:
                    result.add_error(name, e)

        dns_res = intermediate.get("dns")

        a_ips = [ip for ip in dns_res.records.get("A", []) if ip and ip.count(".") == 3]

        # прокинемо IP у OSINT-агент
        shodan_agent.set_shared("a_records", a_ips)

        print("DEBUG A_IPS:", a_ips)

        # 3) запускаємо shodan
        try:
            shodan_res: ShodanResult | None = shodan_agent.run(domain)
        except Exception as e:
            result.add_error("shodan", e)
            shodan_res = None

        # 4) запускаємо crt (повний run)
        try:
            crt_res: CrtResult | None = crt_agent.run(domain)
        except Exception as e:
            tb = traceback.format_exc()
            print("ERROR crt_agent.run:", tb)  # виведе повний traceback у лог
            result.add_error("crt", tb)
            crt_res = None

        # 5) запускаємо VirusTotal
        try:
            vt_res = virustotal_agent.run(domain)
        except Exception as e:
            result.add_error("virustotal", e)
            vt_res = None

        # Записуємо окремі результати
        result.whois = intermediate.get("whois")
        result.dns = intermediate.get("dns")
        result.ssl = intermediate.get("ssl")
        result.crt = crt_res
        result.shodan = shodan_res
        result.virustotal = vt_res

        return result