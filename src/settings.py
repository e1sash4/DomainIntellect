# src/settings.py
from __future__ import annotations
import os
from dotenv import load_dotenv
from typing import List

load_dotenv()

# --------------------
# Загальні налаштування
# --------------------
USER_AGENT: str = os.getenv(
    "USER_AGENT",
    "OSINT-Domain-Analyzer/1.0 (+https://example.local)"
)

# HTTP/DNS таймаути (секунди)
HTTP_TIMEOUT: float = float(os.getenv("HTTP_TIMEOUT", "6"))
DNS_TIMEOUT: float = float(os.getenv("DNS_TIMEOUT", "2"))

# Скільки перевірок субдоменів робити за замовчуванням у bruteforce (мінімум/максимум можна налаштувати)
MAX_SUBDOMAIN_BRUTE: int = int(os.getenv("MAX_SUBDOMAIN_BRUTE", "1000"))

# Обмеження потоків для брютфорсу (щоб не створювати занадто багато потоків)
MAX_BRUTE_THREADS: int = int(os.getenv("MAX_BRUTE_THREADS", "40"))

# Чи використовувати CrewAI за замовчуванням (строкові значення: "1","true","yes")
ENABLE_CREWAI: bool = os.getenv("ENABLE_CREWAI", "false").lower() in {"1", "true", "yes"}

# --------------------
# Ключі для зовнішніх сервісів (опційно)
# --------------------
SHODAN_API_KEY: str | None = os.getenv("SHODAN_API_KEY")

OPENAI_API_KEY: str | None = os.getenv("OPENAI_API_KEY")  # для CrewAI/LLM, якщо потрібен

VIRUSTOTAL_API_KEY: str | None = os.getenv("VIRUSTOTAL_API_KEY") or os.getenv("VT_API_KEY")

# --------------------
# Словник субдоменів: або вбудований короткий список, або шлях до великого файлу
# --------------------
# Шлях до великого wordlist'а субдоменів (одне слово на рядок). Якщо пусто — використаємо DEFAULT_SUBDOMAIN_WORDLIST.
SUBDOMAIN_WORDLIST_PATH: str | None = os.getenv("SUBDOMAIN_WORDLIST_PATH") or None

DEFAULT_SUBDOMAIN_WORDLIST: List[str] = [
    "www", "mail", "api", "dev", "test", "stage", "staging", "beta",
    "admin", "portal", "vpn", "blog", "shop", "m", "static", "cdn",
    "assets", "img", "files", "panel", "cpanel", "office", "intranet",
    "app", "dashboard", "sso", "owa", "gateway", "db", "support",
    "smtp", "webmail", "imap", "pop", "ftp", "status", "auth", "login",
    "api1", "api2", "edge", "edge1", "cdn1", "download", "uploads",
]

# --------------------
# Резолвери (nameservers) для DNS-запитів — можемо задати через ENV як коми-розділений рядок
# --------------------
_resolvers_env = os.getenv("RESOLVERS", "")
if _resolvers_env:
    # підтримуємо формат "8.8.8.8,1.1.1.1" або пробіли
    RESOLVERS: List[str] = [x.strip() for x in _resolvers_env.replace(" ", ",").split(",") if x.strip()]
else:
    # безпечні публічні резолвери
    RESOLVERS = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]

# --------------------
# Ліміти виводу/логування
# --------------------
# Максимальна кількість записів (наприклад для UI) які виводимо у повному вигляді без скорочення
UI_MAX_LIST_ITEMS: int = int(os.getenv("UI_MAX_LIST_ITEMS", "500"))

# --------------------
# Логи й дебаг (не чутливі)
# --------------------
LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO").upper()

# --------------------
# Зручні функції для відладки/інформування
# --------------------
def as_env_summary() -> dict:
    """Коротке резюме основних налаштувань (для логування при старті)."""
    return {
        "USER_AGENT": USER_AGENT,
        "HTTP_TIMEOUT": HTTP_TIMEOUT,
        "DNS_TIMEOUT": DNS_TIMEOUT,
        "MAX_SUBDOMAIN_BRUTE": MAX_SUBDOMAIN_BRUTE,
        "MAX_BRUTE_THREADS": MAX_BRUTE_THREADS,
        "ENABLE_CREWAI": ENABLE_CREWAI,
        "SUBDOMAIN_WORDLIST_PATH": SUBDOMAIN_WORDLIST_PATH,
        "RESOLVERS": RESOLVERS,
        "LOG_LEVEL": LOG_LEVEL,
    }
