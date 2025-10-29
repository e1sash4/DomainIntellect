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


class ShodanHost(BaseModel):
    ip: str
    ports: List[int] = Field(default_factory=list)
    org: Optional[str] = None
    hostnames: List[str] = Field(default_factory=list)


class OSINTResult(BaseModel):
    crtsh_names: List[str] = Field(default_factory=list)
    shodan_hosts: List[ShodanHost] = Field(default_factory=list)


class DomainResult(BaseModel):
    domain: str
    whois: Optional[WhoisResult] = None
    dns: Optional[DNSResult] = None
    ssl: Optional[SSLResult] = None
    osint: Optional[OSINTResult] = None
    errors: List[ErrorInfo] = Field(default_factory=list)


    def add_error(self, agent: str, exc: Exception | str) -> None:
        msg = str(exc) if isinstance(exc, Exception) else exc
        self.errors.append(ErrorInfo(agent=agent, message=msg))