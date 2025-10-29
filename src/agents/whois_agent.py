from __future__ import annotations
from datetime import datetime
from typing import Any, List

import whois

from models import WhoisResult
from agents.base import BaseAgent


def _to_iso(value: Any) -> str | None:
    # whois може повертати datetime, список datetime або None/str
    if value is None:
        return None
    if isinstance(value, list):
        value = value[0] if value else None
    if isinstance(value, datetime):
        return value.replace(tzinfo=None).isoformat()
    if isinstance(value, str):
        try:
            # намагаємося пропарсити
            return datetime.fromisoformat(value).isoformat()
        except Exception:
            return value
    return str(value)


class WhoisAgent(BaseAgent):
    name = "whois"


    def run(self, domain: str) -> WhoisResult:
        data = whois.whois(domain)
        name_servers: List[str] = []
        ns = data.get("name_servers")
        if isinstance(ns, (list, set, tuple)):
            name_servers = sorted({str(x).lower() for x in ns})
        elif isinstance(ns, str):
            name_servers = [ns.lower()]


        statuses: List[str] = []
        st = data.get("status")
        if isinstance(st, (list, set, tuple)):
            statuses = [str(x) for x in st]
        elif isinstance(st, str):
            statuses = [st]


        emails: List[str] = []
        em = data.get("emails")
        if isinstance(em, (list, set, tuple)):
            emails = sorted({str(x).lower() for x in em})
        elif isinstance(em, str):
            emails = [em.lower()]


        return WhoisResult(
            registrar = data.get("registrar"),
            creation_date = _to_iso(data.get("creation_date")),
            expiration_date = _to_iso(data.get("expiration_date")),
            updated_date = _to_iso(data.get("updated_date")),
            name_servers = name_servers,
            statuses = statuses,
            emails = emails,
            raw = {k: (str(v) if not isinstance(v, (dict, list)) else v) for k, v in data.items()},
        )