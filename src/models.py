from __future__ import annotations
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


class ErrorInfo(BaseModel):
    agent: str
    message: str


class WhoisResult(BaseModel):
    registrar: Optional[str] = None
    creation_date: Optional[str] = None
    expiration_date: Optional[str] = None
    updated_date: Optional[str] = None
    name_servers: List[str] = Field(default_factory=list)
    statuses: List[str] = Field(default_factory=list)
    emails: List[str] = Field(default_factory=list)
    raw: Dict[str, Any] = Field(default_factory=dict)


class DNSResult(BaseModel):
    records: Dict[str, List[str]] = Field(default_factory=dict) # тип -> значення
    subdomains_found: List[str] = Field(default_factory=list) # перелік знайдених субдоменів


class SSLResult(BaseModel):
    subject_cn: Optional[str] = None
    issuer_cn: Optional[str] = None
    not_before: Optional[str] = None
    not_after: Optional[str] = None
    san: List[str] = Field(default_factory=list)
    serial_number: Optional[str] = None
    fingerprint_sha256: Optional[str] = None
    negotiated_protocol: Optional[str] = None


class CrtResult(BaseModel):
    domain: Optional[str] = None
    crtsh_names: List[str] = Field(default_factory=list)

# --- SHODAN (окремий результат) ---
class ShodanHost(BaseModel):
    ip: str
    ports: List[int] = []
    org: Optional[str] = None
    hostnames: List[str] = []

    country: Optional[str] = None
    city: Optional[str] = None
    asn: Optional[str] = None
    isp: Optional[str] = None
    os: Optional[str] = None
    tags: List[str] = []
    vulns: List[str] = []
    cpes: List[str] = []
    services: List[dict] = []

class ShodanResult(BaseModel):
    domain: Optional[str] = None
    hosts: List[ShodanHost] = []

# --- VIRUSTOTAL ---
class VTStats(BaseModel):
    harmless: int = 0
    malicious: int = 0
    suspicious: int = 0
    undetected: int = 0
    timeout: int = 0

class VirusTotalResult(BaseModel):
    domain: Optional[str] = None
    reputation: Optional[int] = None                # -100..100
    categories: Dict[str, str] = Field(default_factory=dict)
    last_analysis_stats: VTStats = Field(default_factory=VTStats)
    last_analysis_date: Optional[str] = None        # ISO8601
    total_votes: Dict[str, int] = Field(default_factory=dict)  # {"harmless": X, "malicious": Y}
    whois: Optional[str] = None
    registrar: Optional[str] = None
    tags: List[str] = Field(default_factory=list)

    related_ips: List[str] = Field(default_factory=list)
    related_subdomains: List[str] = Field(default_factory=list)

    # NEW: повний сирий JSON від /domains/{domain}
    raw: Optional[Dict[str, Any]] = None
    # (необов’язково) “сирі” відповіді інших рілейшнів:
    raw_subdomains: Optional[Dict[str, Any]] = None
    raw_resolutions: Optional[Dict[str, Any]] = None



class DomainResult(BaseModel):
    domain: str
    whois: Optional[WhoisResult] = None
    dns: Optional[DNSResult] = None
    ssl: Optional[SSLResult] = None
    crt: Optional[CrtResult] = None
    shodan: Optional[ShodanResult] = None
    virustotal: Optional[VirusTotalResult] = None

    errors: List[ErrorInfo] = Field(default_factory=list)


    def add_error(self, agent: str, exc: Exception | str) -> None:
        msg = str(exc) if isinstance(exc, Exception) else exc
        self.errors.append(ErrorInfo(agent=agent, message=msg))