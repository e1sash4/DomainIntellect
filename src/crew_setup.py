from __future__ import annotations
"""
Приклад інтеграції з CrewAI. Це НЕ обовʼязково для роботи додатку.
Щоб запустити справжнє оркестрування через CrewAI, встанови бібліотеку crewai
та додай OPENAI_API_KEY (або іншу LLM‑конфігурацію).


Наведений приклад показує, як огорнути наші детерміновані агенти в ролі CrewAI
та сформувати завдання. У більшості випадків практичні запити до WHOIS/DNS/SSL/OSINT
краще виконувати напряму (як у coordinator.py), а CrewAI використати для високорівневого
"зведеного звіту" мовою користувача.
"""

try:
    from crewai import Agent, Task, Crew
except Exception: # якщо CrewAI не встановлено
    Agent = Task = Crew = None

from typing import Optional
from models import DomainResult

def build_summary_prompt(domain_result: DomainResult) -> str:
    """Створює промпт для LLM зі зведенням зібраних фактів."""
    lines = [f"Домен: {domain_result.domain}"]

    if domain_result.whois:
        lines.append("\nWHOIS:")
        if domain_result.whois.registrar:
            lines.append(f" Registrar: {domain_result.whois.registrar}")
        if domain_result.whois.creation_date:
            lines.append(f" Created: {domain_result.whois.creation_date}")
        if domain_result.whois.expiration_date:
            lines.append(f" Expires: {domain_result.whois.expiration_date}")

    if domain_result.dns:
        lines.append("\nDNS:")
        records = domain_result.dns.records or {}
        for k, vs in records.items():
            vs = vs or []
            lines.append(f" {k}: {', '.join(vs[:10])}{'…' if len(vs) > 10 else ''}")
        if domain_result.dns.subdomains_found:
            lines.append(f" Subdomains: {len(domain_result.dns.subdomains_found)} found")

    if domain_result.ssl:
        lines.append("\nSSL:")
        if domain_result.ssl.issuer_cn:
            lines.append(f" Issuer: {domain_result.ssl.issuer_cn}")
        if domain_result.ssl.not_after:
            lines.append(f" Valid till: {domain_result.ssl.not_after}")

    # ✅ Замість неіснуючого domain_result.osint — окремо CRT і Shodan
    if getattr(domain_result, "crt", None):
        names = domain_result.crt.crtsh_names or []
        lines.append("\nCRT.sh:")
        lines.append(f" crt.sh names: {len(names)}")

    if getattr(domain_result, "shodan", None):
        hosts = domain_result.shodan.hosts or []
        lines.append("\nShodan:")
        lines.append(f" Shodan hosts: {len(hosts)}")

    if domain_result.errors:
        lines.append("\nПомилки:")
        for e in domain_result.errors:
            lines.append(f" {e.agent}: {e.message}")

    lines.append("\nСформуй короткий (5–8 речень) технічний підсумок і можливі ризики.")
    return "\n".join(lines)


def make_crew() -> Optional[Crew]:
    if Crew is None:
        return None

    analyst = Agent(
        role="OSINT Analyst",
        goal=(
            "Зробити коротке зведення результатів аналізу домену та виділити ризики "
            "(експозиція субдоменів, слабкі шифри/TLS, витік CN/SAN тощо)."
        ),
        backstory=(
            "Досвідчений фахівець з мережевої безпеки, який вміє читати "
            "низькорівневі дані DNS/WHOIS/SSL і давати практичні рекомендації."
        ),
        allow_delegation=False,
        verbose=True,
    )

    # Завдання: на вході — текстовий промпт із фактами, на виході — Markdown‑звіт
    summarize_task = Task(
        description=(
            "Отримай фактологічний конспект (нижче) і згенеруй стислий звіт з рекомендаціями.\n\n"
            "{{facts}}"
        ),
        agent=analyst,
        expected_output= (
            "Стислий Markdown‑звіт (короткий підсумок, ключові ризики, рекомендації)."
        ),
    )

    crew = Crew(
        agents=[analyst],
        tasks=[summarize_task],
        verbose=True,
        )
    return crew