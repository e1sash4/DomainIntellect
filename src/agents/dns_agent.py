# src/agents/dns_agent.py
from __future__ import annotations

import concurrent.futures
import os
from typing import List, Dict, Set, Optional

import dns.exception
import dns.message
import dns.name
import dns.query
import dns.resolver
from agents.base import BaseAgent
from models import DNSResult
from settings import (
    DNS_TIMEOUT,
    DEFAULT_SUBDOMAIN_WORDLIST,
    MAX_SUBDOMAIN_BRUTE,
)
from util import fetch_json, make_retry, unique_keep_order

# Додаткові (опційні) налаштування, які можуть бути визначені в settings.py або .env
# Якщо їх немає — використовуються безпечні дефолти
try:
    from settings import SUBDOMAIN_WORDLIST_PATH
except Exception:
    SUBDOMAIN_WORDLIST_PATH = None

RESOLVERS = getattr(__import__("settings"), "RESOLVERS", ["8.8.8.8", "1.1.1.1", "9.9.9.9"])
MAX_BRUTE_THREADS = getattr(__import__("settings"), "MAX_BRUTE_THREADS", 40)


def _load_wordlist() -> List[str]:
    """
    Якщо вказаний SUBDOMAIN_WORDLIST_PATH — зчитаємо його (по одному слову на рядок),
    інакше повертаємо DEFAULT_SUBDOMAIN_WORDLIST зі settings.
    """
    if SUBDOMAIN_WORDLIST_PATH and os.path.isfile(SUBDOMAIN_WORDLIST_PATH):
        try:
            with open(SUBDOMAIN_WORDLIST_PATH, "r", encoding="utf-8", errors="ignore") as fh:
                words = [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]
                return words
        except Exception:
            pass
    return DEFAULT_SUBDOMAIN_WORDLIST


class DNSAgent(BaseAgent):
    name = "dns"

    def __init__(self) -> None:
        # Підготовка резолвера з явними nameservers (щоб не залежати від локального провайдера)
        self.resolver = dns.resolver.Resolver(configure=False)
        # Якщо в settings вказано RESOLVERS — використаємо їх, інакше дефолтні
        self.resolver.nameservers = RESOLVERS
        self.resolver.timeout = DNS_TIMEOUT
        self.resolver.lifetime = DNS_TIMEOUT
        # Завантажуємо словник субдоменів (можна великий файл)
        self.wordlist = _load_wordlist()

    def _q(self, resolver: dns.resolver.Resolver, domain: str, rtype: str) -> List[str]:
        """
        Безпечна обгортка для одного DNS-запиту. Повертає список рядків або порожній список.
        """
        try:
            answers = resolver.resolve(domain, rtype, lifetime=DNS_TIMEOUT)
            out: List[str] = []
            for r in answers:
                txt = r.to_text()
                if rtype == "TXT":
                    # TXT може розбиватися на кілька частин, прибираємо лапки
                    txt = txt.replace('"', '').strip()
                out.append(txt)
            return out
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout, dns.resolver.NoNameservers):
            return []
        except Exception:
            # будь-яка інша помилка — просто пропускаємо
            return []

    def _from_crtsh(self, domain: str) -> List[str]:
        """
        Пасивний збір субдоменів із crt.sh (публічний інтерфейс, output=json).
        Повертає унікальну відсортовану множину піддоменів, що належать до domain.
        """
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        try:
            data = fetch_json(url)
        except Exception:
            return []
        names: Set[str] = set()
        if isinstance(data, list):
            for row in data:
                nv = row.get("name_value") or ""
                for n in str(nv).split("\n"):
                    n = n.strip().lower().strip(".")
                    if not n:
                        continue
                    # приймаємо тільки ті, що належать до кінцевого домену
                    if n == domain or n.endswith("." + domain):
                        names.add(n)
        return sorted(names)

    def _probe_a(self, fqdn: str) -> Optional[str]:
        """
        Пробуємо отримати A-запис для fqdn. Повертає fqdn якщо вдалося, інакше None.
        Використовується в багатопоточному брютфорсі.
        """
        try:
            answers = self.resolver.resolve(fqdn, "A", lifetime=DNS_TIMEOUT)
            if answers:
                # Якщо є відповідь — повертаємо сам fqdn (знайдений)
                return fqdn
        except Exception:
            return None
        return None

    def _bruteforce_subdomains(self, domain: str, limit: int = MAX_SUBDOMAIN_BRUTE) -> List[str]:
        """
        Багатопотоковий брютфорс субдоменів за словником self.wordlist.
        Обмежуємося параметром limit (щоб не посилати 10k запитів за замовчанням).
        Повертаємо список унікальних піддоменів.
        """
        out: List[str] = []
        # Обмежуємо довжину словника
        words = self.wordlist[:limit]
        fqdns = [f"{w}.{domain}" for w in words]

        found: Set[str] = set()
        # Використовуємо ThreadPoolExecutor для паралельних DNS-запитів
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(MAX_BRUTE_THREADS, len(fqdns) or 1)) as ex:
            future_to_fqdn = {ex.submit(self._probe_a, fqdn): fqdn for fqdn in fqdns}
            for fut in concurrent.futures.as_completed(future_to_fqdn):
                try:
                    res = fut.result()
                    if res:
                        found.add(res)
                except Exception:
                    # пропускаємо індивідуальні помилки
                    continue

        # Зберігаємо порядок згідно появи у словнику (keep order by filtering)
        ordered = [fq for fq in fqdns if fq in found]
        return ordered

    def _check_spf(self, domain: str, txt_records: List[str]) -> Optional[str]:
        """
        Шукаємо SPF рядок серед TXT записів. Повертаємо повний рядок SPF або None.
        """
        for t in txt_records:
            t_low = t.lower()
            if t_low.startswith("v=spf1"):
                return t
        return None

    def _check_dmarc(self, domain: str) -> Optional[str]:
        """
        Перевіряємо наявність DMARC у _dmarc.domain TXT.
        Повертаємо запис або None.
        """
        try:
            recs = self.resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=DNS_TIMEOUT)
            out = []
            for r in recs:
                s = r.to_text().replace('"', '').strip()
                if s:
                    out.append(s)
            # Повертаємо перший знайдений DMARC рядок
            for s in out:
                if s.lower().startswith("v=dmarc1"):
                    return s
            return out[0] if out else None
        except Exception:
            return None

    def _check_dnssec(self, domain: str) -> Dict[str, List[str]]:
        """
        Спроба отримати DNSKEY та DS записи (як індикатори DNSSEC).
        Повертає словник з полями 'DNSKEY' і 'DS' (можуть бути порожні).
        """
        res: Dict[str, List[str]] = {"DNSKEY": [], "DS": []}
        try:
            dnskey = self._q(self.resolver, domain, "DNSKEY")
            if dnskey:
                res["DNSKEY"] = dnskey
        except Exception:
            pass
        try:
            ds = self._q(self.resolver, domain, "DS")
            if ds:
                res["DS"] = ds
        except Exception:
            pass
        return res

    def run(self, domain: str) -> DNSResult:
        """
        Головний метод: збирає багато типів записів, об'єднує пасивні та активні піддомени,
        перевіряє SPF/DMARC і DNSSEC.
        """


        resolver = self.resolver  # вже налаштований у __init__

        records: Dict[str, List[str]] = {}

        # Розширений перелік типів записів для опитування
        rtypes = ["A", "AAAA", "NS", "MX", "TXT", "CNAME", "SOA", "CAA", "DNSKEY", "DS"]

        for rtype in rtypes:
            vals = []
            try:
                vals = self._q(resolver, domain, rtype)
            except Exception:
                vals = []
            if vals:
                records[rtype] = vals

        # Додатково: перевірки SPF серед TXT та DMARC
        txts = records.get("TXT", []) or []
        spf = self._check_spf(domain, txts)
        if spf:
            # Додаємо окремий ключ для зручності
            records["SPF"] = [spf]

        dmarc = self._check_dmarc(domain)
        if dmarc:
            records["DMARC"] = [dmarc]

        # DNSSEC (DNSKEY/DS вже могли бути у records)
        dnssec = self._check_dnssec(domain)
        if dnssec.get("DNSKEY"):
            records.setdefault("DNSKEY", dnssec["DNSKEY"])
        if dnssec.get("DS"):
            records.setdefault("DS", dnssec["DS"])

        # Активний брютфорс субдоменів (A-записи) з багатопоточністю
        active_subs = self._bruteforce_subdomains(domain, limit=MAX_SUBDOMAIN_BRUTE)

        # Пасивний збір з crt.sh
        passive_subs = self.get_shared("passive_subs", []) or []

        # Об'єднуємо та унікалізуємо збереження порядку: пасивні першими (часто більш повні)
        combined = list(unique_keep_order(passive_subs + active_subs))

        # Також варто зберегти перелік A-записів як plain-список
        # (якщо потрібен список IP, він в DNSResult.records['A'])
        return DNSResult(records=records, subdomains_found=combined)
