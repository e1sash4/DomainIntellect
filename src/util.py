from __future__ import annotations
import time
import socket
import idna
import requests
from typing import Any, Callable, Iterable, Optional
from settings import USER_AGENT, HTTP_TIMEOUT

class RetryError(Exception):
    pass

def retry(
    tries: int = 3,
    delay: float = 0.5,
    backoff: float = 2.0,
    exceptions: tuple[type[BaseException], ...] = (Exception,),
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Простий декоратор для повторних спроб з експоненційною затримкою."""

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            _tries, _delay = tries, delay
            last_exc: Optional[BaseException] = None
            while _tries > 0:
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    last_exc = e
                    _tries -= 1
                    if _tries == 0:
                        break
                    time.sleep(_delay)
                    _delay *= backoff
                raise RetryError(f"Retries exhausted for {func.__name__}") from last_exc
            return wrapper
        return decorator

@retry(tries=3, delay=0.4, backoff=2.0, exceptions=(requests.RequestException,))
def fetch_json(url: str, params: Optional[dict[str, Any]] = None, timeout: float = HTTP_TIMEOUT) -> Any:
    headers = {"User-Agent": USER_AGENT}
    r = requests.get(url, params=params, headers=headers, timeout=timeout)
    r.raise_for_status()
    if "application/json" in r.headers.get("Content-Type", "") or url.endswith("output=json"):
        return r.json()
    return r.text

def to_idna(domain: str) -> str:
    """Нормалізація домену до IDNA (punycode)."""
    domain = domain.strip().strip('.')
    if not domain:
        return domain
    # Розбиваємо на labels і кодуємо кожну
    labels = [idna.encode(label).decode('ascii') for label in domain.split('.')]
    return '.'.join(labels)

def unique_keep_order(items: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for x in items:
        if x not in seen:
            seen.add(x)
            result.append(x)
    return result

def port_open(host: str, port: int, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False