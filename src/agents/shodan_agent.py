from __future__ import annotations
from typing import List

from agents.base import BaseAgent
from models import ShodanResult, ShodanHost

import os


class ShodanAgent(BaseAgent):
    """Agent that queries Shodan for given IPv4 addresses.

    Expects a shared value "a_records" (list of IPv4 strings) to be set by the
    Coordinator or another agent. If no API key is configured, the agent returns
    an empty result (fails gracefully).
    """

    name = "shodan"

    def _get_a_records(self) -> List[str]:
        try:
            val = self.get_shared("a_records")
            if isinstance(val, (list, tuple)):
                return [str(x) for x in val if isinstance(x, str)]
        except Exception:
            pass
        return []

    def run(self, domain: str) -> ShodanResult:
        # lazy import to avoid hard dependency if user hasn't installed shodan
        try:
            import shodan
        except Exception:
            return ShodanResult(domain=domain, hosts=[])

        api_key = os.getenv("SHODAN_API_KEY")
        if not api_key:
            return ShodanResult(domain=domain, hosts=[])

        a_records = self._get_a_records()
        if not a_records:
            return ShodanResult(domain=domain, hosts=[])

        api = shodan.Shodan(api_key)
        hosts = []
        for ip in a_records:
            try:
                info = api.host(ip)
                host = ShodanHost(
                    ip=ip,
                    ports=[int(p) for p in info.get("ports", [])],
                    org=info.get("org"),
                    hostnames=info.get("hostnames", []),
                    country=info.get("country_name"),
                    city=info.get("city"),
                    asn=info.get("asn"),
                    isp=info.get("isp"),
                    os=info.get("os"),
                    tags=info.get("tags", []),
                    vulns=info.get("vulns", []),
                    cpes=info.get("cpes", []),
                    services=info.get("data", []),
                )
                hosts.append(host)
            except Exception:
                # ignore failures for individual IPs
                continue

        return ShodanResult(domain=domain, hosts=hosts)