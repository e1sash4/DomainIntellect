from __future__ import annotations
from datetime import datetime
from typing import Any, List, Optional
import re
import socket

import whois

from models import WhoisResult
from agents.base import BaseAgent


def _to_iso(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, list):
        value = value[0] if value else None
    if isinstance(value, datetime):
        return value.replace(tzinfo=None).isoformat()
    if isinstance(value, str):
        val = value.strip()

        # UANIC-подібні формати: "0-UANIC 20061120164504" або "1-UANIC 20240101010203"
        m = re.search(r"\bUANIC\b.*?(\d{14})", val, flags=re.IGNORECASE)
        if m:
            try:
                dt = datetime.strptime(m.group(1), "%Y%m%d%H%M%S")
                return dt.isoformat()
            except Exception:
                pass

        # Спробуємо ISO та інші варіанти, інакше повернемо як є
        try:
            return datetime.fromisoformat(val).isoformat()
        except Exception:
            return val
    return str(value)


def _raw_whois_query(server: str, domain: str, timeout: float = 8.0) -> Optional[str]:
    """Простий WHOIS клієнт для порту 43."""
    try:
        with socket.create_connection((server, 43), timeout=timeout) as s:
            s.sendall((domain + "\r\n").encode("utf-8", errors="ignore"))
            data = b""
            s.settimeout(timeout)
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
        return data.decode("utf-8", errors="ignore")
    except Exception:
        return None


def _parse_uanic_text(text: str) -> WhoisResult:
    """
    Парсер сирого WHOIS з UANIC/UA-реєстрів.
    Витягуємо ключові поля: registrar, creation/expiration/updated, NS, emails (якщо є).
    """
    # деякі реєстри пишуть 'created:', 'changed:', 'expires:' або схожі
    def _extract_datetime(tag_names: List[str]) -> Optional[str]:
        for tag in tag_names:
            # приклади рядків:
            # "created:  0-UANIC 20061120164504"
            # "changed:  1-UANIC 20231101000000"
            # "expires:  20251120000000"   (інколи без префікса UANIC)
            pat = rf"^{tag}\s*:\s*(.+)$"
            m = re.search(pat, text, flags=re.IGNORECASE | re.MULTILINE)
            if m:
                raw = m.group(1).strip()
                # 1) UANIC + 14 цифр
                m2 = re.search(r"\bUANIC\b.*?(\d{14})", raw, flags=re.IGNORECASE)
                if m2:
                    try:
                        return datetime.strptime(m2.group(1), "%Y%m%d%H%M%S").isoformat()
                    except Exception:
                        pass
                # 2) голі 14 цифр
                m3 = re.search(r"\b(\d{14})\b", raw)
                if m3:
                    try:
                        return datetime.strptime(m3.group(1), "%Y%m%d%H%M%S").isoformat()
                    except Exception:
                        pass
                # 3) як є (може трапитися інший формат)
                return _to_iso(raw)
        return None

    registrar = None
    # зустрічаються "registrar:", "registrant:" (але це власник), інколи "nserver:" для NS
    m_reg = re.search(r"^registrar\s*:\s*(.+)$", text, flags=re.IGNORECASE | re.MULTILINE)
    if m_reg:
        registrar = m_reg.group(1).strip()

    creation_date = _extract_datetime(["created", "creation date", "registered"])
    expiration_date = _extract_datetime(["expires", "expiration date", "expire"])
    updated_date = _extract_datetime(["changed", "updated", "update date"])

    # NS:
    name_servers: List[str] = []
    for m_ns in re.finditer(r"^nserver\s*:\s*([^\s]+)", text, flags=re.IGNORECASE | re.MULTILINE):
        name_servers.append(m_ns.group(1).strip().lower())

    # E-mail (може не бути)
    emails: List[str] = []
    for m_em in re.finditer(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", text, flags=re.IGNORECASE):
        emails.append(m_em.group(0).lower())
    emails = sorted(set(emails))

    return WhoisResult(
        registrar=registrar,
        creation_date=creation_date,
        expiration_date=expiration_date,
        updated_date=updated_date,
        name_servers=sorted(set(name_servers)),
        statuses=[],  # UANIC часто не дає у стандартизованому полі
        emails=emails,
        raw={"raw_text": text},
    )


class WhoisAgent(BaseAgent):
    name = "whois"

    def run(self, domain: str) -> WhoisResult:
        # 1) Пробуємо стандартну бібліотеку
        try:
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
                registrar=data.get("registrar"),
                creation_date=_to_iso(data.get("creation_date")),
                expiration_date=_to_iso(data.get("expiration_date")),
                updated_date=_to_iso(data.get("updated_date")),
                name_servers=name_servers,
                statuses=statuses,
                emails=emails,
                raw={k: (str(v) if not isinstance(v, (dict, list)) else v) for k, v in data.items()},
            )
        except Exception:
            # 2) Резерв: raw WHOIS (UANIC та ін.)
            # Список серверів — спробуємо кілька
            for server in ["whois.ua", "whois.net.ua", "whois.uanic.net"]:
                txt = _raw_whois_query(server, domain)
                if txt and ("UANIC" in txt or "nserver" in txt.lower() or "created" in txt.lower()):
                    return _parse_uanic_text(txt)

            # Якщо нічого не вийшло — повернемо мінімальне
            return WhoisResult(
                registrar=None, creation_date=None, expiration_date=None, updated_date=None,
                name_servers=[], statuses=[], emails=[], raw={"error": "WHOIS fallback failed"}
            )
