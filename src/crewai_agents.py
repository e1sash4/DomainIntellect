from __future__ import annotations
import json
from typing import Tuple, Dict

from pydantic import BaseModel, Field
from crewai import Agent, Task, Crew, Process
from crewai.tools import BaseTool # офіційний спосіб створення кастом‑Tool

from models import WhoisResult, DNSResult, SSLResult, CrtResult, ShodanResult, DomainResult, VirusTotalResult
from agents.whois_agent import WhoisAgent
from agents.dns_agent import DNSAgent
from agents.ssl_agent import SSLAgent
from agents.crt_agent import CrtAgent
from agents.shodan_agent import ShodanAgent
from agents.virustotal_agent import VirusTotalAgent


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

class CrtTool(BaseTool):
    name: str = "crt_passive"
    description: str = "Збери пасивні домени через crt.sh."
    args_schema: type[BaseModel] = DomainInput

    def _run(self, domain: str) -> dict:
        return CrtAgent().run(domain).model_dump()

class ShodanTool(BaseTool):
    name: str = "shodan_scan"
    description: str = "Отримай інформацію про хости через Shodan (за API key)."
    args_schema: type[BaseModel] = DomainInput

    def _run(self, domain: str) -> dict:
        return ShodanAgent().run(domain).model_dump()


class VirusTotalTool(BaseTool):
    name: str = "virustotal_lookup"
    description: str = "Отримай VirusTotal репутацію та артефакти для домену."
    args_schema: type[BaseModel] = DomainInput

    def _run(self, domain: str) -> dict:
        return VirusTotalAgent().run(domain).model_dump()
# ---------- Побудова команди та задач ----------

def make_domain_crew() -> Tuple[Crew, Dict[str, Task]]:
    """Створює Crew з 5 агентів: координатор + 4 спеціалісти; повертає (crew, tasks)."""
    whois_tool = WhoisTool()
    dns_tool = DNSTool()
    ssl_tool = SSLTool()
    crt_tool = CrtTool()
    shodan_tool = ShodanTool()
    vt_tool = VirusTotalTool()

    whois_specialist = Agent(
        role="WHOIS Specialist",
        goal=("Отримати повну, валідну та структуровану інформацію WHOIS про домен "
              "у форматі JSON, включаючи дані про реєстратора, дати створення/закінчення, "
              "стани домену, контактну інформацію (якщо доступна) та технічні поля."),
        backstory=("Ти — досвідчений аналітик доменних реєстрів, який розуміє специфіку "
                   "WHOIS-запитів для різних TLD та уміє інтерпретувати нетипові формати "
                   "відповідей. Знаєш, що частина полів може бути прихована, а деякі — подані "
                   "в іншому кодуванні або структурі. "),
        tools=[whois_tool], allow_delegation=False, verbose=True,
    )
    dns_specialist = Agent(
        role="DNS Specialist",
        goal=("Побудувати повну та достовірну картину DNS-структури досліджуваного домену, "
              "включаючи A, AAAA, NS, MX, TXT, CNAME-записи та знайдені субдомени. "
              "Всі результати повинні бути повернуті у форматі JSON."),
        backstory=("Ти — аналітик DNS-інфраструктури, який чудово знає принципи роботи DNS, "
                   "уміє відрізняти реальні записи від кешованих або застарілих, "
                   "і здатний інтегрувати результати як активного, так і пасивного збору. "
                   "Ти не вигадуєш, а точно відображаєш дані, які повертає інструмент."),
        tools=[dns_tool], allow_delegation=False, verbose=True,
    )
    ssl_specialist = Agent(
        role="SSL/TLS Specialist",
        goal=("Отримати з сервера цільового домену дійсний SSL/TLS-сертифікат, "
              "розібрати його структуру та повернути усі релевантні поля у форматі JSON: "
              "subject, issuer, serial_number, fingerprints, SAN, not_before, not_after тощо."),
        backstory=("Ти — криптоаналітик, який спеціалізується на сертифікатах безпеки. "
                   "Знаєш структуру X.509, умієш працювати із закінченими або недійсними "
                   "сертифікатами, розумієш важливість ланцюга довіри та полів SAN. "
                   "Твоя задача — надати достовірну технічну інформацію про сертифікат."),
        tools=[ssl_tool], allow_delegation=False, verbose=True,
    )
    crt_specialist = Agent(
        role="crt.sh Specialist",
        goal=("Зібрати перелік доменів/піддоменів пов'язаних з цільовим доменом на основі crt.sh."),
        backstory=("Ти — аналітик сертифікатів, який вміє працювати з базою crt.sh."),
        tools=[crt_tool], allow_delegation=False, verbose=True,
    )

    shodan_specialist = Agent(
        role="Shodan Specialist",
        goal=("Отримати інформацію про публічні хости (по IP) через Shodan API."),
        backstory=("Ти — мережевий аналітик, що знає структуру Shodan результатів."),
        tools=[shodan_tool], allow_delegation=False, verbose=True,
    )

    vt_specialist = Agent(
        role="VirusTotal Specialist",
        goal=("Отримати репутаційні метрики домену у VirusTotal та пов’язані артефакти, "
              "повернути строго JSON за моделлю VirusTotalResult."),
        backstory=("Ти знаєш обмеження тарифів VT і дбаєш про валідність JSON."),
        tools=[vt_tool], allow_delegation=False, verbose=True,
    )

    coordinator = Agent(
        role="Coordinator",
        goal=("Організувати послідовне та узгоджене виконання підзадач "
              "WHOIS, DNS, SSL і OSINT-агентами. Забезпечити збір їх результатів, "
              "перевірку цілісності, формування єдиного інтегрованого JSON-звіту "
              "для подальшого аналізу кіберзагроз."),
        backstory=("Ти — координатор мультиагентної системи. Маєш навички технічного "
                   "керівництва, плануєш виконання завдань, контролюєш коректність "
                   "повернених результатів і об’єднуєш їх у єдину структуру. "
                   "Твоя мета — забезпечити точність, повноту і єдність формату результату."),
        allow_delegation=True, verbose=True,
    )

    # Завдання для кожного спеціаліста; просимо повернути ЛИШЕ JSON інструмента
    t_whois = Task(
        description=(
            "Виконай повний WHOIS-запит для домену {domain}. "
            "Використай інструмент whois_lookup, оброби всі отримані дані та "
            "поверни результат у вигляді строго структурованого JSON-об’єкта, "
            "що відповідає моделі WhoisResult. Не додавай текстових коментарів, "
            "описів або пояснень. Якщо певні поля відсутні — поверни null."),
        agent = whois_specialist,
        expected_output=(
            "JSON-об’єкт типу WhoisResult, який містить повний набір доступних даних WHOIS "
            "(домен, реєстратор, creation_date, expiry_date, status, emails, name_servers тощо) "
            "без додаткових текстових вставок."),
        output_pydantic = WhoisResult,
        tools = [whois_tool],
    )
    t_dns = Task(
        description=(
            "Для домену {domain} здійсни повне отримання DNS-записів усіх основних типів "
            "(A, AAAA, MX, NS, TXT, CNAME) за допомогою інструмента dns_enumeration. "
            "За можливості виконай пасивне виявлення субдоменів. "
            "Результат представ у вигляді строго структурованого JSON (DNSResult)."),
        agent = dns_specialist,
        expected_output=(
            "JSON-об’єкт типу DNSResult, що містить усі виявлені записи DNS для домену "
            "та знайдені субдомени (якщо доступні), без текстових коментарів або описів."),
        output_pydantic = DNSResult,
        tools = [dns_tool],
    )
    t_ssl = Task(
        description=(
            "Виконай з’єднання з доменом {domain} через SSL/TLS та зніми сертифікат. "
            "Проаналізуй отриманий X.509-сертифікат, вилучи всі основні поля "
            "(subject, issuer, SAN, not_before, not_after, fingerprints, serial_number тощо). "
            "Результат представ у вигляді валідного JSON відповідно до моделі SSLResult."),
        agent = ssl_specialist,
        expected_output=(
            "JSON-об’єкт типу SSLResult, який містить усі ключові атрибути SSL/TLS-сертифіката "
            "без додаткових коментарів чи текстових вставок."),
        output_pydantic = SSLResult,
        tools = [ssl_tool],
    )

    t_crt = Task(
        description=("Збери пасивні домени через crt.sh for {domain}."),
        agent=crt_specialist,
        expected_output=(
            "JSON-об’єкт типу CrtResult: масив знайдених імен (crtsh_names) "
            "та службові поля; без жодних текстових коментарів."
        ),
        output_pydantic=CrtResult,
        tools=[crt_tool],
    )

    t_shodan = Task(
        description=("Отримай дані Shodan по IP для {domain}."),
        agent=shodan_specialist,
        expected_output=(
            "JSON-об’єкт типу ShodanResult: список хостів з IP, портами, "
            "банерами/сервісами та метаданими; без текстових вставок."
        ),
        output_pydantic=ShodanResult,
        tools=[shodan_tool],
    )

    t_vt = Task(
        description=("Отримай у VirusTotal репутацію та пов’язані дані для {domain}. "
                     "Поверни строго валідний JSON за моделлю VirusTotalResult."),
        agent=vt_specialist,
        expected_output=("JSON-об’єкт типу VirusTotalResult без вільного тексту."),
        output_pydantic=VirusTotalResult,
        tools=[vt_tool],
    )

    crew = Crew(
        agents=[whois_specialist, dns_specialist, ssl_specialist, crt_specialist, shodan_specialist, vt_specialist],
        tasks = [t_whois, t_dns, t_ssl, t_crt, t_shodan, t_vt],
        process = Process.hierarchical,
        manager_agent = coordinator,
        verbose = True,
    )

    return crew, {
        "whois": t_whois, "dns": t_dns, "ssl": t_ssl, "crt": t_crt, "shodan": t_shodan, "vt": t_vt
    }

def run_domain_with_crewai(domain: str) -> DomainResult:
    crew, tasks = make_domain_crew()
    # inputs доступні у {domain} в описах Tasks
    _ = crew.kickoff(inputs={"domain": domain})


    def _load(task: Task, model):
        try:
            data = json.loads(task.output.json)
            return model(**data)
        except Exception:
            try:
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
    crt = _load(tasks["crt"], CrtResult)
    shodan = _load(tasks["shodan"], ShodanResult)
    vt = _load(tasks["vt"], VirusTotalResult)

    return DomainResult(domain=domain, whois=whois, dns=dns, ssl=ssl, crt=crt, shodan=shodan, virustotal=vt)
