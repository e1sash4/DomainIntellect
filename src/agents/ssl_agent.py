from __future__ import annotations
import hashlib
from datetime import datetime
from typing import Optional, List

from cryptography import x509
from cryptography.hazmat.backends import default_backend

from models import SSLResult
from agents.base import BaseAgent


class SSLAgent(BaseAgent):
    name = "ssl"


    def _fetch_cert(self, hostname: str, port: int = 443, timeout: float = 6.0) -> bytes:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                der = ssock.getpeercert(True)
                self.negotiated_protocol = ssock.version()
                return der


    def run(self, domain: str) -> SSLResult:
        try:
            der = self._fetch_cert(domain)
        except Exception as e:
            # Якщо немає TLS на 443 — повертаємо порожній результат
            return SSLResult()

        cert = x509.load_der_x509_certificate(der, default_backend())

        subject_cn: Optional[str] = None
        try:
            subject = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
            if subject:
                subject_cn = subject[0].value
        except Exception:
            pass

        issuer_cn: Optional[str] = None
        try:
            issuer = cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
            if issuer:
                issuer_cn = issuer[0].value
        except Exception:
            pass

        san: List[str] = []
        try:
            ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            san = ext.value.get_values_for_type(x509.DNSName)
        except Exception:
            san = []

        not_before = cert.not_valid_before.replace(tzinfo=None).isoformat()
        not_after = cert.not_valid_after.replace(tzinfo=None).isoformat()

        serial_number = hex(cert.serial_number)
        fingerprint_sha256 = cert.fingerprint(hashlib.sha256()).hex()

        return SSLResult(
            subject_cn=subject_cn,
            issuer_cn=issuer_cn,
            not_before=not_before,
            not_after=not_after,
            san=san,
            serial_number=serial_number,
            fingerprint_sha256=fingerprint_sha256,
            negotiated_protocol=getattr(self, "negotiated_protocol", None),
        )