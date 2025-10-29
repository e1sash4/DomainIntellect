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

        # 1) Збираємо пасивні субдомени ОДИН РАЗ
        try:
            passive_subs = osint_agent.passive_subdomains(domain)
        except Exception:
            passive_subs = []

        # Передаємо в DNSAgent (і за бажанням в OSINTAgent)
        dns_agent.set_shared("passive_subs", passive_subs)
        osint_agent.set_shared("passive_subs", passive_subs)  # опціонально

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

        # 3) Після цього запускаємо повноцінний osint (який може робити shodan та ін.)
        try:
            # osint_agent вже має passive_subs у shared для використання
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