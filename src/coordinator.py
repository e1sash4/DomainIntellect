from __future__ import annotations
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict

from models import DomainResult
from agents.whois_agent import WhoisAgent
from agents.dns_agent import DNSAgent
from agents.ssl_agent import SSLAgent
from agents.osint_agent import OSINTAgent
from settings import ENABLE_CREWAI


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
        osint_agent = OSINTAgent()

        # Паралельний запуск основних агентів
        with ThreadPoolExecutor(max_workers=self.max_workers) as ex:
            futures = {
                ex.submit(whois_agent.run, domain): "whois",
                ex.submit(dns_agent.run, domain): "dns",
                ex.submit(ssl_agent.run, domain): "ssl",
            }
            intermediate: Dict[str, object] = {}
            for fut in as_completed(futures):
                name = futures[fut]
                try:
                    intermediate[name] = fut.result()
                except Exception as e:
                    result.add_error(name, e)

        # Передаємо A‑записи в OSINT‑агент для Shodan (якщо будуть ключі)
        try:
            a_records = []
            dns_res = intermediate.get("dns")
            if dns_res and getattr(dns_res, "records", None):
                a_records = [r.split()[0] if " " in r else r for r in dns_res.records.get("A", [])]
            osint_agent.set_shared("a_records", a_records)
            osint_res = osint_agent.run(domain)
        except Exception as e:
            result.add_error("osint", e)
            osint_res = None

        # Записуємо часткові результати в підсумкову структуру
        result.whois = intermediate.get("whois")
        result.dns = intermediate.get("dns")
        result.ssl = intermediate.get("ssl")
        result.osint = osint_res

        return result