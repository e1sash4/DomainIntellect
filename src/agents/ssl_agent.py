# src/agents/ssl_agent.py
from __future__ import annotations

import hashlib
import socket
import ssl
from typing import Optional, List, Tuple

from agents.base import BaseAgent
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from models import SSLResult
from settings import DNS_TIMEOUT

# Набір портів, які ми пробуємо (443 + поширені альтернативи)
DEFAULT_TLS_PORTS = [443, 8443, 9443]

# Простий список таймаутів (socket connect timeout)
CONNECT_TIMEOUT = 6.0
READ_TIMEOUT = 6.0


def _parse_cert_der(der_bytes: bytes) -> SSLResult:
    """
    Парсимо DER-байти сертифіката та будуємо SSLResult.
    """
    cert = x509.load_der_x509_certificate(der_bytes, default_backend())

    subject_cn: Optional[str] = None
    try:
        attrs = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        if attrs:
            subject_cn = attrs[0].value
    except Exception:
        subject_cn = None

    issuer_cn: Optional[str] = None
    try:
        attrs = cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        if attrs:
            issuer_cn = attrs[0].value
    except Exception:
        issuer_cn = None

    not_before = None
    not_after = None
    try:
        if cert.not_valid_before:
            not_before = cert.not_valid_before.replace(tzinfo=None).isoformat()
        if cert.not_valid_after:
            not_after = cert.not_valid_after.replace(tzinfo=None).isoformat()
    except Exception:
        pass

    san: List[str] = []
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san = ext.value.get_values_for_type(x509.DNSName)
    except Exception:
        san = []

    serial_number = None
    try:
        serial_number = hex(cert.serial_number)
    except Exception:
        serial_number = None

    fingerprint_sha256 = None
    try:
        fingerprint_sha256 = cert.fingerprint(hashlib.sha256()).hex()
    except Exception:
        fingerprint_sha256 = None

    return SSLResult(
        subject_cn=subject_cn,
        issuer_cn=issuer_cn,
        not_before=not_before,
        not_after=not_after,
        san=san or [],
        serial_number=serial_number,
        fingerprint_sha256=fingerprint_sha256,
        negotiated_protocol=None,  # цю інформацію заповнюємо в момент TLS-стікування
    )


class SSLAgent(BaseAgent):
    name = "ssl"

    def _connect_and_get_der(
        self, host: str, port: int, server_hostname: Optional[str] = None
    ) -> Tuple[Optional[bytes], Optional[str]]:
        """
        Підключаємось по TCP -> TLS (SNI = server_hostname, якщо задано).
        Повертаємо (der_bytes, negotiated_protocol) або (None, None).
        """
        ctx = ssl.create_default_context()
        # Ми не хотіли б кидати помилку валідації сертифіката при знятті — просто знімаємо сертифікат
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        try:
            # create_connection дозволяє використовувати таймаут
            with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT) as sock:
                sock.settimeout(READ_TIMEOUT)
                try:
                    with ctx.wrap_socket(sock, server_hostname=server_hostname) as ssock:
                        # Отримуємо сертифікат у бінарному вигляді (DER)
                        der = ssock.getpeercert(binary_form=True)
                        proto = None
                        try:
                            proto = ssock.version()
                        except Exception:
                            proto = None
                        return der, proto
                except ssl.SSLError as e:
                    # Можливий варіант: сервер вимагає SNI або відкидає SNI.
                    # Якщо SNI був заданий і ми отримали SSLError, пробуємо ще раз без SNI
                    # (wrap_socket з server_hostname=None).
                    if server_hostname:
                        try:
                            # Повторна спроба без SNI
                            with ctx.wrap_socket(sock, server_hostname=None) as ssock2:
                                der2 = ssock2.getpeercert(binary_form=True)
                                proto2 = None
                                try:
                                    proto2 = ssock2.version()
                                except Exception:
                                    proto2 = None
                                return der2, proto2
                        except Exception:
                            # Якщо і це впало — повертаємо None
                            return None, None
                    return None, None
        except (socket.timeout, ConnectionRefusedError, OSError):
            return None, None
        except Exception:
            return None, None

    def _iter_candidate_targets(self, domain: str) -> List[Tuple[str, int, Optional[str]]]:
        """
        Повертає список кандидатів (host_or_ip, port, server_hostname),
        яких ми спробуємо підключити в порядку пріоритету.
        - спочатку пробуємо сам hostname:port з SNI=hostname
        - потім A/AAAA адреси (якщо є) з SNI=hostname
        - для кожної адреси також пробуємо без SNI (server_hostname=None)
        """
        candidates: List[Tuple[str, int, Optional[str]]] = []
        # Спробуємо hostname (ваш домен) на кожному порту з SNI = hostname
        for p in DEFAULT_TLS_PORTS:
            candidates.append((domain, p, domain))

        # Резолвимо A/AAAA локально (через socket.getaddrinfo) — даємо час на DNS_TIMEOUT
        try:
            infos = socket.getaddrinfo(domain, None)
            addrs = []
            for info in infos:
                addr = info[4][0]
                # унікалізуємо IP
                if addr not in addrs:
                    addrs.append(addr)
            for ip in addrs:
                # пробуємо IP з SNI = domain (класичний варіант)
                for p in DEFAULT_TLS_PORTS:
                    candidates.append((ip, p, domain))
                # пробуємо IP без SNI (server_hostname=None)
                for p in DEFAULT_TLS_PORTS:
                    candidates.append((ip, p, None))
        except Exception:
            # якщо резолв не вдався — нічого страшного, продовжимо з hostname
            pass

        # Декілька унікальних кандидатів (зберегти порядок)
        seen = set()
        uniq: List[Tuple[str, int, Optional[str]]] = []
        for c in candidates:
            key = (c[0], c[1], c[2] or "")
            if key not in seen:
                seen.add(key)
                uniq.append(c)
        return uniq

    def run(self, domain: str) -> SSLResult:
        """
        Основний метод: по черзі пробуємо кандидати, якщо знайшли DER сертифікат — парсимо і повертаємо результат.
        Якщо нічого не вдалося — повертаємо порожній SSLResult().
        """
        # Якщо домен містить порт (наприклад example.com:8443) — розпарсимо його
        host = domain
        port_override: Optional[int] = None
        if ":" in domain and not domain.count(":") > 1:
            # формат hostname:port
            try:
                h, p = domain.rsplit(":", 1)
                port_override = int(p)
                host = h
            except Exception:
                host = domain
                port_override = None

        # Якщо користувач вказав порт явно — використовуємо лише його
        ports_to_try = [port_override] if port_override else DEFAULT_TLS_PORTS

        # Побудуємо кандидатів
        candidates: List[Tuple[str, int, Optional[str]]] = []
        # стартовий: hostname + порти з SNI
        for p in ports_to_try:
            candidates.append((host, p, host))

        # Додаткові кандидати (IP-адреси + варіанти без SNI)
        try:
            infos = socket.getaddrinfo(host, None)
            addrs = []
            for info in infos:
                addr = info[4][0]
                if addr not in addrs:
                    addrs.append(addr)
            for ip in addrs:
                for p in ports_to_try:
                    candidates.append((ip, p, host))   # SNI=host
                    candidates.append((ip, p, None))   # без SNI
        except Exception:
            # резолв не вдався — пропускаємо
            pass

        # Унікалізація кандидатів
        seen = set()
        uniq_candidates: List[Tuple[str, int, Optional[str]]] = []
        for c in candidates:
            key = (c[0], c[1], c[2] or "")
            if key not in seen:
                seen.add(key)
                uniq_candidates.append(c)

        # Пробуємо підключення по кандидатам
        for target_host, target_port, server_hostname in uniq_candidates:
            der, proto = self._connect_and_get_der(target_host, target_port, server_hostname)
            if der:
                # Парсимо DER і повертаємо SSLResult з negotiated_protocol
                res = _parse_cert_der(der)
                # Якщо вдалося взяти версію протоколу — додаємо її
                try:
                    res.negotiated_protocol = proto
                except Exception:
                    res.negotiated_protocol = None
                return res

        # Якщо нічого не спрацювало — повертаємо порожній результат
        return SSLResult()
