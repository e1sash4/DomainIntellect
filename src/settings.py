from __future__ import annotations
import os
from dotenv import load_dotenv


load_dotenv()


# Загальні налаштування
USER_AGENT = os.getenv("USER_AGENT", "OSINT-Domain-Analyzer/1.0 (+https://example.local)")
HTTP_TIMEOUT = float(os.getenv("HTTP_TIMEOUT", 12))
DNS_TIMEOUT = float(os.getenv("DNS_TIMEOUT", 5))
MAX_SUBDOMAIN_BRUTE = int(os.getenv("MAX_SUBDOMAIN_BRUTE", 100))
ENABLE_CREWAI = os.getenv("ENABLE_CREWAI", "false").lower() in {"1", "true", "yes"}


# Ключі для зовнішніх сервісів (опційно)
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
CENSYS_API_ID = os.getenv("CENSYS_API_ID")
CENSYS_API_SECRET = os.getenv("CENSYS_API_SECRET")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")


# Словник субдоменів за замовчуванням (невеликий, безпечний)
DEFAULT_SUBDOMAIN_WORDLIST = [
    "www", "mail", "api", "dev", "test", "stage", "staging", "beta",
    "admin", "portal", "vpn", "blog", "shop", "m", "static", "cdn",
    "assets", "img", "files", "panel", "cpanel", "office", "intranet",
    "app", "dashboard", "sso", "owa", "gateway", "db", "support"
]