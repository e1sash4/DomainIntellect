from __future__ import annotations
from typing import List, Set

from models import OSINTResult, ShodanHost
from agents.base import BaseAgent
from util import fetch_json
from settings import SHODAN_API_KEY

class OSINTAgent(BaseAgent):
    name = "osint"

    # Пасивні субдомени: тільки crt.sh (без ключів, безкоштовно)
    def passive_subdomains(self, domain: str) -> List[str]:
        return self._crtsh(domain)

    def _crtsh(self, domain: str) -> List[str]:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        try:
            data = fetch_json(url)
        except Exception:
            return []
        names: Set[str] = set()
        if isinstance(data, list):
            for row in data:
                nv = row.get("name_value")
                if not nv:
                    continue
                for n in str(nv).split("\n"):
                    n = n.strip().lower().strip(".")
                    if n.endswith("." + domain) or n == domain:
                        names.add(n)
        return sorted(names)

    def _shodan_hosts_by_ips(self, ips: List[str]) -> List[ShodanHost]:
        """Збирає розширену інформацію з shodan.host(ip) і мапить у модель ShodanHost."""
        if not SHODAN_API_KEY:
            return []
        try:
            import shodan
        except Exception:
            return []

        api = shodan.Shodan(SHODAN_API_KEY)
        out: List[ShodanHost] = []

        for ip in ips:
            try:
                # request full host info (minify False щоб отримати банери)
                info = api.host(ip, history=False, minify=False)
            except Exception as e:
                # Якщо Shodan відповів, що хост не проіндексований — додаємо "порожній" хост з тегом
                msg = str(e).lower()
                if "no information available for that host" in msg or "not found" in msg:
                    out.append(ShodanHost(
                        ip=ip,
                        ports=[],
                        org=None,
                        hostnames=[],
                        country=None,
                        city=None,
                        asn=None,
                        isp=None,
                        os=None,
                        tags=["shodan:not_indexed"],
                        vulns=[],
                        cpes=[],
                        services=[]
                    ))
                # інші помилки — пропускаємо
                continue

            # збираємо сервіси/банери
            services = []
            for item in info.get("data", []) or []:
                svc = {
                    "port": item.get("port"),
                    "transport": (item.get("_shodan") or {}).get("module"),
                    "product": item.get("product"),
                    "version": item.get("version"),
                    "cpe": item.get("cpe") or item.get("cpe23"),
                    "banner": item.get("data"),
                }

                # HTTP specific
                http = item.get("http") or {}
                if http:
                    svc["http"] = {
                        "host": http.get("host"),
                        "title": http.get("title"),
                        "status": http.get("status"),
                        "server": http.get("server"),
                        "location": http.get("location"),
                        "robots": http.get("robots"),
                    }

                # SSL specific
                ssl = item.get("ssl") or {}
                if ssl:
                    cert = (ssl.get("cert") or {}) or {}
                    svc["ssl"] = {
                        "versions": ssl.get("versions"),
                        "ja3s": ssl.get("ja3s"),
                        "cert_issuer": cert.get("issuer"),
                        "cert_subject": cert.get("subject"),
                    }

                services.append(svc)

            # зібрати cpes, vulns (якщо є)
            cpes = []
            vulns = []
            for item in info.get("data", []) or []:
                if item.get("cpe"):
                    if isinstance(item.get("cpe"), list):
                        cpes.extend(item.get("cpe"))
                    else:
                        cpes.append(item.get("cpe"))
                # інколи cpe23 або cpe23Uri
                if item.get("cpe23"):
                    if isinstance(item.get("cpe23"), list):
                        cpes.extend(item.get("cpe23"))
                    else:
                        cpes.append(item.get("cpe23"))

            if isinstance(info.get("vulns"), dict):
                vulns = list(info.get("vulns").keys())

            out.append(ShodanHost(
                ip=info.get("ip_str") or ip,
                ports=sorted(info.get("ports", []) or []),
                org=info.get("org"),
                hostnames=info.get("hostnames", []) or [],
                country=info.get("country_name"),
                city=info.get("city"),
                asn=info.get("asn"),
                isp=info.get("isp"),
                os=info.get("os"),
                tags=info.get("tags") or [],
                vulns=vulns,
                cpes=list(dict.fromkeys(cpes)),  # унікалізуємо
                services=services
            ))

        return out

    def run(self, domain: str) -> OSINTResult:
        # 1) crt.sh (free)
        crt = self._crtsh(domain)

        # 2) Shodan: ТІЛЬКИ по IPv4 A-адресах із DNS-агента (free)
        a_records = self.get_shared("a_records", []) or []
        shodan_hosts = self._shodan_hosts_by_ips(a_records)

        return OSINTResult(crtsh_names=crt, shodan_hosts=shodan_hosts)