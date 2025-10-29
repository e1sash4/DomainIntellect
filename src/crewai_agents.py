from __future__ import annotations
import json
from typing import Tuple, Dict

from pydantic import BaseModel, Field
from crewai import Agent, Task, Crew, Process
from crewai.tools import BaseTool # офіційний спосіб створення кастом‑Tool

from models import WhoisResult, DNSResult, SSLResult, OSINTResult, DomainResult
from agents.whois_agent import WhoisAgent
from agents.dns_agent import DNSAgent
from agents.ssl_agent import SSLAgent
from agents.osint_agent import OSINTAgent

# ---------- Input schema для інструментів ----------
class DomainInput(BaseModel):
    domain: str = Field(..., description="Цільовий домен, напр. example.com")

# ---------- Кастомні CrewAI Tools (викликають наш детермінований код) ----------
class WhoisTool(BaseTool):
    name: str = "whois_lookup"
    description: str = "Виконай WHOIS‑запит і поверни структурований JSON (WhoisResult)."
    args_schema: type[BaseModel] = DomainInput

    def _run(self, domain: str) -> dict:
        return WhoisAgent().run(domain).model_dump()

class DNSTool(BaseTool):
    name: str = "dns_enumeration"
    description: str = "Збери DNS‑записи (A/AAAA/NS/MX/TXT/CNAME/SOA) та легкий bruteforce субдоменів."
    args_schema: type[BaseModel] = DomainInput

    def _run(self, domain: str) -> dict:
        return DNSAgent().run(domain).model_dump()

class SSLTool(BaseTool):
    name: str = "ssl_cert_intel"
    description: str = "Зчитай TLS‑сертифікат з 443 і поверни деталі (CN/Issuer/SAN/validity/fingerprint)."
    args_schema: type[BaseModel] = DomainInput

    def _run(self, domain: str) -> dict:
        return SSLAgent().run(domain).model_dump()

class OSINTTool(BaseTool):
    name: str = "osint_passive"
    description: str = "Пасивний OSINT (crt.sh, Shodan* якщо є ключ) — повертає OSINTResult."
    args_schema: type[BaseModel] = DomainInput

    def _run(self, domain: str) -> dict:
        return OSINTAgent().run(domain).model_dump()


# ---------- Побудова команди та задач ----------

def make_domain_crew() -> Tuple[Crew, Dict[str, Task]]:
    """Створює Crew з 5 агентів: координатор + 4 спеціалісти; повертає (crew, tasks)."""
    whois_tool = WhoisTool()
    dns_tool = DNSTool()
    ssl_tool = SSLTool()
    osint_tool = OSINTTool()

    whois_specialist = Agent(
        role="WHOIS Specialist",
        goal=("Отримати валідний WhoisResult у JSON без вільного тексту."),
        backstory=("Реєстри доменів — твоє все; вмієш обходити дивні поля та формати."),
        tools=[whois_tool], allow_delegation=False, verbose=True,
    )
    dns_specialist = Agent(
        role="DNS Specialist",
        goal="Побудувати повну картину DNS‑записів і знайдених субдоменів (JSON).",
        backstory="Майстер dnspython і пасивного виявлення; не вигадуй — повертай дані інструмента.",
        tools=[dns_tool], allow_delegation=False, verbose=True,
    )
    ssl_specialist = Agent(
        role="TLS/SSL Specialist",
        goal="Зняти сертифікат і повернути структуровані поля (JSON).",
        backstory="Сертифікати — твоя стихія; орієнтуєшся в SAN/issuer/термінах дії.",
        tools=[ssl_tool], allow_delegation=False, verbose=True,
    )
    osint_specialist = Agent(
        role="OSINT Specialist",
        goal="Пасивно зібрати назви з crt.sh та хости Shodan (JSON).",
        backstory="Полюєш за артефактами з відкритих джерел, дотримуючись лімітів.",
        tools=[osint_tool], allow_delegation=False, verbose=True,
    )

    coordinator = Agent(
        role="Coordinator",
        goal=(
            "Скоординувати підзадачі WHOIS/DNS/SSL/OSINT, зібрати частини у єдину відповідь."),
        backstory=(
            "Дієш як технічний менеджер: делегуєш, перевіряєш, просиш рівно JSON без води."),
        allow_delegation=True, verbose=True,
    )

    # Завдання для кожного спеціаліста; просимо повернути ЛИШЕ JSON інструмента
    t_whois = Task(
        description=(
            "Для домену {domain}: виклич whois_lookup та поверни ЛИШЕ його JSON (WhoisResult)."),
        agent = whois_specialist,
        expected_output = "Валідний JSON WhoisResult без додаткового тексту.",
        output_pydantic = WhoisResult,
        tools = [whois_tool],
    )
    t_dns = Task(
        description = (
            "Для домену {domain}: виклич dns_enumeration та поверни ЛИШЕ його JSON (DNSResult)."),
        agent = dns_specialist,
        expected_output = "Валідний JSON DNSResult без додаткового тексту.",
        output_pydantic = DNSResult,
        tools = [dns_tool],
    )
    t_ssl = Task(
        description = (
            "Для домену {domain}: виклич ssl_cert_intel та поверни ЛИШЕ його JSON (SSLResult)."),
        agent = ssl_specialist,
        expected_output = "Валідний JSON SSLResult без додаткового тексту.",
        output_pydantic = SSLResult,
        tools = [ssl_tool],
    )
    t_osint = Task(
        description = (
            "Для домену {domain}: виклич osint_passive та поверни ЛИШЕ його JSON (OSINTResult)."),
        agent = osint_specialist,
        expected_output = "Валідний JSON OSINTResult без додаткового тексту.",
        output_pydantic = OSINTResult,
        tools = [osint_tool],
    )

    crew = Crew(
        agents = [coordinator, whois_specialist, dns_specialist, ssl_specialist, osint_specialist],
        tasks = [t_whois, t_dns, t_ssl, t_osint],
        process = Process.hierarchical,  # менеджер делегує підзадачі
        manager_agent = coordinator,  # або manager_llm=...
        verbose = True,
    )

    return crew, {
        "whois": t_whois, "dns": t_dns, "ssl": t_ssl, "osint": t_osint
    }

def run_domain_with_crewai(domain: str) -> DomainResult:
    crew, tasks = make_domain_crew()
    # inputs доступні у {domain} в описах Tasks
    _ = crew.kickoff(inputs={"domain": domain})


    # Дістаємо структуровані виходи кожної задачі (CrewAI зберігає їх у task.output)
    def _load(task: Task, model):
        try:
            # у більшості версій є .output.json()
            data = json.loads(task.output.json())
            return model(**data)
        except Exception:
            try:
                # іноді .output.raw або вже dict/str
                raw = getattr(task.output, "raw", None)
                if isinstance(raw, dict):
                    return model(**raw)
                if isinstance(raw, str):
                    return model(**json.loads(raw))
            except Exception:
                return None
        return None

    whois = _load(tasks["whois"], WhoisResult)
    dns = _load(tasks["dns"], DNSResult)
    ssl = _load(tasks["ssl"], SSLResult)
    osint = _load(tasks["osint"], OSINTResult)

    return DomainResult(domain=domain, whois=whois, dns=dns, ssl=ssl, osint=osint)
