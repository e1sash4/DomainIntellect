from __future__ import annotations

import json
from typing import List

import streamlit as st

from coordinator import Coordinator
from models import DomainResult
from settings import ENABLE_CREWAI
from crew_setup import make_crew, build_summary_prompt

try:
    from crewai_agents import run_domain_with_crewai
    CREW_AVAILABLE = True
except Exception:
    CREW_AVAILABLE = False

st.set_page_config(page_title="OSINT Multi‑Agent Domain Analyzer", layout="wide")

st.title("🔎 OSINT Multi‑Agent Domain Analyzer")
st.caption("WHOIS • DNS • SSL • OSINT (crt.sh / Shodan) — паралельне виконання агентів")

with st.sidebar:
    st.header("Налаштування")
    enable_crewai = st.toggle("Використовувати CrewAI для зведення", value=ENABLE_CREWAI)
    use_crewai_agents = st.toggle("Запускати усі агенти як CrewAI", value=False,
                                  help="WHOIS/DNS/SSL/OSINT через CrewAI‑агентів") if CREW_AVAILABLE else False
    max_workers = st.slider("Макс. паралельних агентів", 2, 16, 6)
    st.divider()
    st.markdown("**Порада:** залиш порожнім CrewAI, якщо не маєш LLM‑ключів — все працюватиме і без нього.")

st.markdown("Введи домени (по одному в рядок або через кому):")
raw_input = st.text_area("Домен(и)", placeholder="example.com\nexample.org")

run_btn = st.button("Запустити аналіз", type="primary")

def analyze_domains(domains: List[str], use_crewai: bool, max_workers: int) -> List[DomainResult]:
    coord = Coordinator(use_crewai=use_crewai, max_workers=max_workers)
    out: List[DomainResult] = []
    prog = st.progress(0.0)
    for i, d in enumerate(domains, 1):
        prog.progress(i/len(domains), text=f"Аналіз {d} ({i}/{len(domains)})")
        res = coord.run_for_domain(d)
        out.append(res)
    prog.empty()
    return out

def _domain_list_from_text(text: str) -> List[str]:
    items = []
    for line in (text or "").replace(",", "\n").splitlines():
        d = line.strip().strip('.')
        if d:
            items.append(d)
    # Унікалізація зі збереженням порядку
    seen = set()
    uniq = []
    for x in items:
        if x not in seen:
            uniq.append(x)
            seen.add(x)
    return uniq

if run_btn and raw_input.strip():
    domains = _domain_list_from_text(raw_input)
    results = []
    prog = st.progress(0.0)
    for i, d in enumerate(domains, 1):
        prog.progress(i/len(domains), text=f"Аналіз {d} ({i}/{len(domains)})")
        if use_crewai_agents:
            # запуск через CrewAI-агентів (усі 4 агенти як CrewAI)
            res = run_domain_with_crewai(d)
        else:
            # звичайний детермінований координатор (ThreadPool)
            res = Coordinator(use_crewai=enable_crewai, max_workers=max_workers).run_for_domain(d)
        results.append(res)
    prog.empty()

    for res in results:
        with st.expander(f"Результат: {res.domain}", expanded=True):
            cols = st.columns(5)
            # Короткі метрики
            created = res.whois.creation_date if res.whois else None
            expires = res.whois.expiration_date if res.whois else None
            ca = res.ssl.issuer_cn if res.ssl and res.ssl.issuer_cn else "—"
            a_count = len((res.dns.records.get("A", []) if res.dns and res.dns.records else []))
            sub_count = len(res.dns.subdomains_found) if res.dns else 0

            cols[0].metric("Створено", created or "—")
            cols[1].metric("Закінчення", expires or "—")
            cols[2].metric("CA (Issuer)", ca)
            cols[3].metric("A‑записів", a_count)
            cols[4].metric("Субдоменів", sub_count)

            tab_over, tab_whois, tab_dns, tab_ssl, tab_osint, tab_json = st.tabs(
                ["Огляд", "WHOIS", "DNS", "SSL", "OSINT", "JSON"]
            )

            with tab_over:
                st.write("### Короткий огляд")
                if res.whois and res.whois.registrar:
                    st.write(f"**Registrar:** {res.whois.registrar}")
                if res.ssl and res.ssl.not_after:
                    st.write(f"**SSL дійсний до:** {res.ssl.not_after}")
                st.write(f"**A‑записів:** {a_count}")
                st.write(f"**Субдоменів знайдено:** {sub_count}")
                if res.errors:
                    st.error("\n".join(f"{e.agent}: {e.message}" for e in res.errors))

            with tab_whois:
                st.write(res.whois.model_dump() if res.whois else "—")

            with tab_dns:
                if res.dns and res.dns.records:
                    for rtype, vals in res.dns.records.items():
                        st.write(f"**{rtype}**: ")
                        st.code("\n".join(vals) if vals else "—")
                    if res.dns.subdomains_found:
                        st.write("**Субдомени (брют‑форс):**")
                        st.code("\n".join(res.dns.subdomains_found))
                else:
                    st.write("—")

            with tab_ssl:
                st.write(res.ssl.model_dump() if res.ssl else "—")

            with tab_osint:
                if res.osint:
                    st.write(f"**crt.sh** (імен): {len(res.osint.crtsh_names)}")
                    if res.osint.crtsh_names:
                        st.code("\n".join(res.osint.crtsh_names[:200]))
                    if res.osint.shodan_hosts:
                        st.subheader("Shodan hosts:")
                        for h in res.osint.shodan_hosts:
                            st.markdown(f"**{h.ip}** — {', '.join(map(str, h.ports)) if h.ports else 'no ports'}")
                            st.write({
                                "org": h.org,
                                "hostnames": h.hostnames,
                                "country": h.country,
                                "city": h.city,
                                "asn": h.asn,
                                "isp": h.isp,
                                "os": h.os,
                                "tags": h.tags,
                                "vulns": h.vulns,
                                "cpes": h.cpes,
                            })
                            # серіалізація services
                            if h.services:
                                st.markdown("**Services / banners:**")
                                for s in h.services:
                                    st.write(s)
                else:
                    st.write("—")

            with tab_json:
                blob = json.dumps(res.model_dump(mode="json"), ensure_ascii=False, indent=2)
                st.code(blob, language="json")
                st.download_button(
                    label="⬇️ Завантажити JSON",
                    file_name=f"{res.domain}.osint.json",
                    mime="application/json",
                    data=blob.encode("utf-8"),
                )

    if enable_crewai:
        crew = make_crew()
        if crew:
            result = crew.kickoff(inputs={"facts": build_summary_prompt(res)})
            # Прагматично пробуємо обидва шляхи доступу до тексту:
            text = None
            # 1) новіші/поширені білди: CrewOutput має .raw
            if hasattr(result, "raw") and result.raw:
                text = result.raw
            # 2) інколи зручно читати з об’єкта crew після виконання (crew.output.raw)
            elif hasattr(crew, "output") and crew.output:
                # crew.output теж CrewOutput
                text = getattr(crew.output, "raw", None) or str(crew.output)

            st.markdown("### 🤖 AI-Звіт (CrewAI аналітик)")
            st.markdown(text or "Немає результату.")

else:
    st.info("Введи один або кілька доменів і натисни **Запустити аналіз**.")

