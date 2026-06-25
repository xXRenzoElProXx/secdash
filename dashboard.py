import json
import os
import subprocess

import pandas as pd
import streamlit as st

from styles import inject_styles, inject_canvas, inject_clock, inject_chat_panel

st.set_page_config(
    page_title="SecDash AI SOC",
    page_icon="🛡",
    layout="wide",
    initial_sidebar_state="expanded"
)

inject_styles()
inject_canvas()
inject_chat_panel()

def load_json(n):
    p = os.path.join("shared_data", f"ag{n}.json")
    try:
        with open(p, encoding='utf-8') as f: return json.load(f)
    except: return None


def normalize_for_dataframe(value):
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)
    return value


def dataframe_from_records(records):
    if not records:
        return pd.DataFrame()

    if not isinstance(records, list):
        records = [records]

    normalized = []
    for record in records:
        if isinstance(record, dict):
            normalized.append({k: normalize_for_dataframe(v) for k, v in record.items()})
        else:
            normalized.append({"value": normalize_for_dataframe(record)})
    return pd.DataFrame(normalized)


def risk_icon(lvl):
    return {"alto":"⬤","medio":"◆","bajo":"▲","critico":"✕"}.get((lvl or "").lower(),"·")

def asset_row(a):
    lvl = (a.get("riesgo") or "").lower()
    c   = {"alto":"#ff6464","medio":"#ffcc44","bajo":"#00ff6a"}.get(lvl,"#4dcc7a")
    return (
        f'<div style="display:flex;gap:9px;padding:8px 10px;margin-bottom:5px;'
        f'border:1px solid {c}18;border-left:3px solid {c};background:#030a04;">'
        f'<span style="color:{c};font-size:.66rem;margin-top:2px;flex-shrink:0;">{risk_icon(lvl)}</span>'
        f'<div>'
        f'<div style="font-family:JetBrains Mono,monospace;color:{c};font-size:.72rem;font-weight:500;">'
        f'{a.get("nombre","")}</div>'
        f'<div style="font-family:JetBrains Mono,monospace;color:#4dcc7a;font-size:.64rem;margin-top:1px;opacity:.85;">'
        f'{a.get("razon","")}</div>'
        f'</div></div>'
    )

def ioc_row(ioc):
    rep = ioc.get("reputacion","")
    c   = "#ff6464" if rep=="malicioso" else "#ffcc44" if rep=="sospechoso" else "#00ff6a"
    lbl = rep.upper() if rep else "UNKNOWN"
    return (
        f'<div style="display:flex;align-items:center;justify-content:space-between;'
        f'padding:7px 10px;margin-bottom:5px;'
        f'border:1px solid {c}18;border-left:3px solid {c};background:#030a04;">'
        f'<span style="font-family:JetBrains Mono,monospace;color:#7dffb0;font-size:.7rem;">'
        f'{ioc.get("ip","")}</span>'
        f'<div style="text-align:right;">'
        f'<span style="font-family:Orbitron,monospace;color:{c};font-size:.58rem;">{lbl}</span><br>'
        f'<span style="font-family:JetBrains Mono,monospace;color:#4dcc7a;font-size:.6rem;">'
        f'SCORE: {ioc.get("abuse_score","?")}/100</span>'
        f'</div></div>'
    )

ag = {i: load_json(i) for i in range(1, 13)}

activos_list = (ag[3] or {}).get("activos_criticos", [])
altos = sum(1 for a in activos_list if a.get("riesgo") == "alto")
riesgo = "ALTO" if altos >= 2 else ("MEDIO" if altos == 1 else "BAJO")

if ag[9]:
    score = ag[9].get("score_total", 0)
    nivel = ag[9].get("nivel", "BAJO")
elif ag[2] and ag[3]:
    svc = len(ag[2].get("services", []))
    score = min(100,
        svc * 5 + altos * 15 +
        (20 if svc > 5 else 0) +
        (10 if any("ssh" in str(s).lower() for s in ag[2].get("services",[])) else 0)
    )
    nivel = riesgo
else:
    score, nivel = "—", "—"

agentes_ok = sum(1 for i in range(1,13) if ag[i])
target      = (ag[1] or ag[2] or {}).get("target", "sin_objetivo")

AGENT_LABELS = {
    1:"DISCOVERY", 2:"NETWORK",  3:"SURFACE",  4:"NIKTO",
    5:"NUCLEI",    6:"OWASP",    7:"CVE",       8:"THREAT",
    9:"RISK",      10:"COMPLY",  11:"EXPLOITS", 12:"CHATBOT"
}
NAV = [
    ("OVERVIEW",    "Métricas / Agentes 1-3"),
    ("NETWORK",     "Agente 2 — Servicios expuestos"),
    ("WEB SCANS",   "Agentes 4-5 — Nikto & Nuclei"),
    ("OWASP",       "Agente 6 — Clasificación Top 10"),
    ("CVE INTEL",   "Agente 7 — Vulnerabilidades"),
    ("THREAT INTEL","Agente 8 — Reputación IOCs"),
    ("RISK SCORE",  "Agente 9 — Correlación 0-100"),
    ("COMPLIANCE",  "Agente 10 — Controles"),
    ("EXPLOITS",    "Agente 11 — Metasploit"),
]

with st.sidebar:
    st.markdown(f"""
    <div style="padding:1.1rem 1rem .8rem;border-bottom:1px solid rgba(0,255,106,.1);">
        <div style="font-family:Orbitron,monospace;font-size:.95rem;font-weight:900;
                    color:#00ff6a;letter-spacing:.1em;text-shadow:0 0 12px rgba(0,255,106,.45);">
            ▶ SECDASH</div>
        <div style="font-family:JetBrains Mono,monospace;font-size:.55rem;
                    color:#265c36;letter-spacing:.18em;margin-top:3px;">AI SOC PLATFORM</div>
    </div>""", unsafe_allow_html=True)

    sc = "#00ff6a" if agentes_ok else "#ffcc00"
    sl = "OPERATIONAL" if agentes_ok else "STANDBY"
    st.markdown(f"""
    <div style="padding:.75rem 1rem;border-bottom:1px solid rgba(0,255,106,.1);">
        <div style="font-family:JetBrains Mono,monospace;font-size:.55rem;
                    color:#265c36;letter-spacing:.14em;margin-bottom:5px;">SYSTEM STATUS</div>
        <div style="display:flex;align-items:center;gap:7px;">
            <span class="live-dot" style="background:{sc};"></span>
            <span style="font-family:Orbitron,monospace;font-size:.62rem;
                         font-weight:700;color:{sc};">{sl}</span>
        </div>
        <div style="font-family:JetBrains Mono,monospace;font-size:.58rem;
                    color:#265c36;margin-top:5px;">
            AGENTS: <span style="color:#4dcc7a;">{agentes_ok}</span>/11
        </div>
    </div>""", unsafe_allow_html=True)

    ip_line = f'IP: <span style="color:#4dcc7a;">{ag[1]["ip"]}</span>' if ag[1] else ""
    st.markdown(f"""
    <div style="padding:.75rem 1rem;border-bottom:1px solid rgba(0,255,106,.1);">
        <div style="font-family:JetBrains Mono,monospace;font-size:.55rem;
                    color:#265c36;letter-spacing:.14em;margin-bottom:5px;">ACTIVE TARGET</div>
        <div style="font-family:JetBrains Mono,monospace;font-size:.7rem;
                    color:#7dffb0;word-break:break-all;">{target}</div>
        <div style="font-family:JetBrains Mono,monospace;font-size:.58rem;
                    color:#265c36;margin-top:3px;">{ip_line}</div>
    </div>""", unsafe_allow_html=True)

    st.markdown('<div style="padding:.6rem 1rem .2rem;">'
                '<div style="font-family:JetBrains Mono,monospace;font-size:.55rem;'
                'color:#265c36;letter-spacing:.16em;">NAVIGATION</div></div>',
                unsafe_allow_html=True)

    for label, hint in NAV:
        st.markdown(f"""
        <div style="padding:5px 1rem;border-left:2px solid transparent;">
            <div style="font-family:Orbitron,monospace;font-size:.58rem;
                        font-weight:700;color:#4dcc7a;letter-spacing:.07em;">{label}</div>
            <div style="font-family:JetBrains Mono,monospace;font-size:.53rem;
                        color:#265c36;margin-top:1px;">{hint}</div>
        </div>""", unsafe_allow_html=True)

    st.markdown('<div style="padding:.7rem 1rem .2rem;border-top:1px solid rgba(0,255,106,.08);">'
                '<div style="font-family:JetBrains Mono,monospace;font-size:.55rem;'
                'color:#265c36;letter-spacing:.16em;margin-bottom:5px;">AGENT STATUS</div>',
                unsafe_allow_html=True)
    for i in range(1, 12):  # Solo hasta AG11, AG12 es el chat en el panel lateral
        ok  = ag[i] is not None
        c   = "#00ff6a" if ok else "#1e3a26"
        mrk = "▶" if ok else "·"
        st.markdown(
            f'<div style="display:flex;gap:6px;align-items:center;padding:2px 1rem;">'
            f'<span style="color:{c};font-size:.58rem;">{mrk}</span>'
            f'<span style="font-family:JetBrains Mono,monospace;color:{c};'
            f'font-size:.56rem;letter-spacing:.05em;">AG{i:02d} {AGENT_LABELS[i]}</span>'
            f'</div>', unsafe_allow_html=True)
    st.markdown('</div>', unsafe_allow_html=True)

st.markdown(f"""
<div class="anim-up" style="
    border:1px solid rgba(0,255,106,.2); border-top:2px solid #00ff6a;
    background:linear-gradient(135deg,#030e05,#040d06 70%,#050f07);
    padding:1rem 1.3rem; margin-bottom:1.1rem;
    position:relative; overflow:hidden;">
    <div style="display:flex;align-items:center;justify-content:space-between;
                flex-wrap:wrap;gap:.6rem;position:relative;">
        <div>
            <div style="font-family:Orbitron,monospace;font-size:1.35rem;font-weight:900;
                        color:#00ff6a;letter-spacing:.1em;line-height:1;
                        text-shadow:0 0 16px rgba(0,255,106,.48),0 0 36px rgba(0,255,106,.15);">
                ▶ SECDASH AI SOC
            </div>
            <div style="font-family:JetBrains Mono,monospace;font-size:.58rem;
                        color:#265c36;letter-spacing:.2em;margin-top:5px;">
                SECURITY OPERATIONS CENTER &nbsp;/&nbsp; AUTOMATED THREAT INTELLIGENCE
            </div>
        </div>
        <div style="display:flex;gap:1.4rem;align-items:center;flex-wrap:wrap;">
            <div style="text-align:right;">
                <div style="font-family:JetBrains Mono,monospace;font-size:.58rem;color:#265c36;">
                    <span class="live-dot"></span>ONLINE
                </div>
                <div id="soc-clock" style="font-family:Orbitron,monospace;font-size:.72rem;
                            color:#4dcc7a;margin-top:2px;letter-spacing:.06em;">--:--:-- UTC</div>
            </div>
            <div style="text-align:right;">
                <div style="font-family:JetBrains Mono,monospace;font-size:.56rem;color:#265c36;">TARGET</div>
                <div style="font-family:JetBrains Mono,monospace;font-size:.68rem;
                            color:#7dffb0;margin-top:2px;">{target}</div>
            </div>
        </div>
    </div>
</div>
""", unsafe_allow_html=True)

inject_clock()

st.markdown('<div class="sec-hdr anim-up d1">// TARGET ACQUISITION</div>', unsafe_allow_html=True)

col_inp, col_btn = st.columns([4, 1])
with col_inp:
    target_input = st.text_input("DOMAIN / IP", value="scanme.nmap.org",
                                  placeholder="example.com or 192.168.1.1")
with col_btn:
    st.markdown("<br>", unsafe_allow_html=True)
    run_btn = st.button("▶ EXECUTE ALL AGENTS")

if run_btn:
    try:
        bar = st.progress(0)
        status_text = st.empty()
        
        steps = [
            ("AG1: Asset discovery",           ["python","integrante1/agent1_discovery.py", target_input], 9),
            ("AG2: Network scan",              ["python","integrante1/agent2_network.py"],                 18),
            ("AG3: Attack surface",            ["python","integrante1/agent3_surface.py"],                 27),
            ("AG4: Nikto scan (mock)",         ["python","integrante2/agent4_nikto.py", "--mock"],         36),
            ("AG5: Nuclei scan (mock)",        ["python","integrante2/agent5_nuclei.py", "--mock"],        45),
            ("AG6: OWASP classifier",          ["python","integrante2/agent6_owasp_classifier.py"],        54),
            ("AG7: CVE intelligence",          ["python","integrante3/agent7_cve_intelligence.py"],        63),
            ("AG8: Threat intelligence",       ["python","integrante3/agent8_threat_intel.py"],            72),
            ("AG9: Risk correlation",          ["python","integrante3/agent9_risk_correlation.py"],        81),
            ("AG10: Compliance check",         ["python","integrante4/agent10_compliance.py"],             90),
            ("AG11: Metasploit advisory",      ["python","integrante4/agent11_metasploit.py"],            100),
        ]
        
        success_count = 0
        failed_agents = []
        
        for msg, cmd, pct in steps:
            status_text.text(f"🔄 Ejecutando {msg}...")
            try:
                result = subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=120)  # Aumentado a 120 segundos
                bar.progress(pct)
                success_count += 1
            except subprocess.TimeoutExpired:
                failed_agents.append(f"{msg} (timeout > 2min)")
                bar.progress(pct)
            except subprocess.CalledProcessError as e:
                error_msg = e.stderr[:100] if e.stderr else str(e)[:100]
                failed_agents.append(f"{msg} (error: {error_msg})")
                bar.progress(pct)
            except Exception as e:
                failed_agents.append(f"{msg} ({str(e)[:50]})")
                bar.progress(pct)
        
        status_text.empty()
        
        if failed_agents:
            st.warning(f"⚠️ {success_count}/11 agentes completados. Fallos: {', '.join(failed_agents)}")
        else:
            st.success(f"✅ {success_count}/11 AGENTES COMPLETADOS — DATOS ACTUALIZADOS")
        
        st.info("🔄 Recargando dashboard en 2 segundos...")
        import time
        time.sleep(2)
        st.rerun()
        
    except Exception as e:
        st.error(f"❌ ERROR: {e}")

if ag[1]:
    st.markdown(
        f'<div class="anim-up d2" style="font-family:JetBrains Mono,monospace;'
        f'font-size:.68rem;color:#4dcc7a;margin-top:5px;">'
        f'<span style="color:#265c36;">►</span> '
        f'IP: <strong style="color:#00ff6a;">{ag[1]["ip"]}</strong>'
        f'&nbsp;|&nbsp;SUBDOMAINS: <strong style="color:#00ff6a;">{len(ag[1]["subdominios"])}</strong>'
        f'&nbsp;|&nbsp;REGISTRAR: <span style="color:#4dcc7a;">{ag[1].get("whois_registrar","—")}</span>'
        f'</div>', unsafe_allow_html=True)

st.divider()

# ── Raw JSON
st.markdown('<div class="sec-hdr">// RAW AGENT OUTPUT</div>', unsafe_allow_html=True)
c1, c2, c3 = st.columns(3)
for col, n, lbl in [(c1,1,"AG1 :: DISCOVERY"),(c2,2,"AG2 :: NETWORK"),(c3,3,"AG3 :: SURFACE")]:
    with col:
        with st.expander(f"[ {lbl} ]"):
            if ag[n]:
                st.json(ag[n])
            else:
                st.info(f"ag{n}.json not found")

st.divider()

#  MÉTRICAS

st.markdown('<div class="sec-hdr">// THREAT METRICS</div>', unsafe_allow_html=True)
m1, m2, m3, m4 = st.columns(4)
m1.metric("RISK SCORE",    f"{score}/100" if score != "—" else score, nivel if nivel != "—" else None)
m2.metric("CVEs DETECTED", len((ag[7] or {}).get("cves_encontrados", [])))
m3.metric("WEB FINDINGS",  len((ag[4] or {}).get("hallazgos", [])) + len((ag[5] or {}).get("hallazgos", [])))
m4.metric("OPEN PORTS",    len((ag[2] or {}).get("services", [])))

st.divider()

#  NETWORK & OWASP

cn, co = st.columns(2)
with cn:
    st.markdown('<div class="sec-hdr">// EXPOSED SERVICES</div>', unsafe_allow_html=True)
    svcs = (ag[2] or {}).get("services", [])
    if svcs:
        st.dataframe(dataframe_from_records(svcs), width='stretch', hide_index=True)
    else:
        st.info("PENDING — run agent 2")

with co:
    st.markdown('<div class="sec-hdr">// OWASP TOP 10 HEATMAP</div>', unsafe_allow_html=True)
    hmap = (ag[6] or {}).get("heatmap_owasp", {})
    if hmap:
        st.bar_chart(hmap)
    else:
        st.info("PENDING — awaiting agent 6 (Integrante 2/3)")

st.divider()

#  WEB VULNERABILITY SCANS (AGENTS 4 & 5)

st.markdown('<div class="sec-hdr">// WEB VULNERABILITY ASSESSMENT</div>', unsafe_allow_html=True)

w1, w2 = st.columns(2)
with w1:
    st.markdown('<div style="font-family:Orbitron,monospace;font-size:.7rem;color:#00ff6a;margin-bottom:.5rem;">[ NIKTO SCAN ]</div>', unsafe_allow_html=True)
    hallazgos_ag4 = (ag[4] or {}).get("hallazgos", [])
    if hallazgos_ag4:
        st.dataframe(dataframe_from_records(hallazgos_ag4), width="stretch", hide_index=True)
        total_ag4 = len(hallazgos_ag4)
        st.caption(f"✓ {total_ag4} hallazgos detectados por Nikto")
    else:
        st.info("PENDING — run agent 4 (Nikto scan)")

with w2:
    st.markdown('<div style="font-family:Orbitron,monospace;font-size:.7rem;color:#00ff6a;margin-bottom:.5rem;">[ NUCLEI TEMPLATES ]</div>', unsafe_allow_html=True)
    hallazgos_ag5 = (ag[5] or {}).get("hallazgos", [])
    if hallazgos_ag5:
        st.dataframe(dataframe_from_records(hallazgos_ag5), width="stretch", hide_index=True)
        total_ag5 = len(hallazgos_ag5)
        st.caption(f"✓ {total_ag5} hallazgos detectados por Nuclei")
    else:
        st.info("PENDING — run agent 5 (Nuclei scan)")

st.divider()

#  CVEs & ACTIVOS CRÍTICOS

cc, ca = st.columns(2)
with cc:
    st.markdown('<div class="sec-hdr">// CVE INTELLIGENCE</div>', unsafe_allow_html=True)
    cves = (ag[7] or {}).get("cves_encontrados", [])
    if cves:
        st.dataframe(dataframe_from_records(cves), width="stretch", hide_index=True)
    else:
        st.info("PENDING — awaiting agent 7 (Integrante 3)")

with ca:
    st.markdown('<div class="sec-hdr">// CRITICAL ASSETS</div>', unsafe_allow_html=True)
    if activos_list:
        st.markdown("".join(asset_row(a) for a in activos_list), unsafe_allow_html=True)
    else:
        st.info("PENDING — run agent 3")

#  SECURITY ANALYSIS (AG2 & AG3 ENHANCEMENTS)

st.divider()
st.markdown('<div class="sec-hdr">// FIREWALL & IDS DETECTION</div>', unsafe_allow_html=True)

if ag[2]:
    fw_data = ag[2].get('firewall_ids_detection', {})
    ssl_services = ag[2].get('ssl_tls_services', [])
    security_issues = ag[2].get('security_issues', [])
    
    # Métricas de firewall/IDS
    f1, f2, f3, f4 = st.columns(4)
    f1.metric("FIREWALL", "DETECTED" if fw_data.get('firewall_present') else "NOT DETECTED", 
              delta="Active" if fw_data.get('firewall_present') else None)
    f2.metric("IDS/IPS", "DETECTED" if fw_data.get('ids_ips_detected') else "NOT DETECTED",
              delta="Active" if fw_data.get('ids_ips_detected') else None)
    f3.metric("FILTERED PORTS", fw_data.get('filtered_ports', 0))
    f4.metric("SSL/TLS SERVICES", len(ssl_services))
    
    # Evidencia de firewall
    if fw_data.get('evidence'):
        st.markdown(
            f'<div style="border:1px solid rgba(0,255,106,.15);background:#030e05;'
            f'padding:10px 12px;font-family:JetBrains Mono,monospace;font-size:.68rem;'
            f'color:#7dffb0;margin-top:.8rem;">'
            f'<span style="color:#00ff6a;font-size:.6rem;letter-spacing:.1em;">🔥 FIREWALL EVIDENCE</span><br>'
            f'<span style="margin-top:4px;display:block;">{fw_data.get("evidence", "")}</span>'
            f'</div>',
            unsafe_allow_html=True
        )
    
    # Servicios SSL/TLS
    if ssl_services:
        st.markdown('<div style="font-family:Orbitron,monospace;font-size:.7rem;color:#00ff6a;margin-top:1rem;margin-bottom:.5rem;">[ SSL/TLS CONFIGURATION ]</div>', unsafe_allow_html=True)
        st.dataframe(dataframe_from_records(ssl_services), width="stretch", hide_index=True)
    
    # Security Issues
    if security_issues:
        st.markdown('<div style="font-family:Orbitron,monospace;font-size:.7rem;color:#ff6464;margin-top:1rem;margin-bottom:.5rem;">[ SECURITY ISSUES DETECTED ]</div>', unsafe_allow_html=True)
        for issue in security_issues:
            st.markdown(
                f'<div style="padding:8px 12px;margin-bottom:5px;'
                f'border:1px solid rgba(255,100,100,.2);border-left:3px solid #ff6464;'
                f'background:#0a0404;font-family:JetBrains Mono,monospace;font-size:.68rem;color:#ff9999;">'
                f'⚠️ {issue}</div>',
                unsafe_allow_html=True
            )
else:
    st.info("PENDING — awaiting agent 2 (Network Scan)")

st.divider()
st.markdown('<div class="sec-hdr">// ACCESS CONTROL & HARDENING ANALYSIS</div>', unsafe_allow_html=True)

if ag[3]:
    ctrl_data = ag[3].get('control_acceso', {})
    hard_data = ag[3].get('hardening_analysis', {})
    post_exp = ag[3].get('post_exploitation_vectors', [])
    
    # Sección de Control de Acceso
    st.markdown('<div style="font-family:Orbitron,monospace;font-size:.7rem;color:#00ff6a;margin-bottom:.5rem;">[ ACCESS CONTROL MODEL ]</div>', unsafe_allow_html=True)
    
    c1, c2 = st.columns(2)
    with c1:
        modelo = ctrl_data.get('modelo_detectado', 'desconocido')
        st.markdown(
            f'<div style="border:1px solid rgba(0,255,106,.15);background:#030e05;'
            f'padding:10px 12px;font-family:JetBrains Mono,monospace;font-size:.72rem;color:#7dffb0;">'
            f'<span style="color:#265c36;font-size:.6rem;">MODEL DETECTED</span><br>'
            f'<span style="color:#00ff6a;font-size:.85rem;font-weight:600;">{modelo.upper()}</span>'
            f'</div>',
            unsafe_allow_html=True
        )
        
        # Servicios sin autenticación
        sin_auth = ctrl_data.get('servicios_sin_autenticacion', [])
        if sin_auth:
            st.markdown('<div style="margin-top:.8rem;font-family:JetBrains Mono,monospace;font-size:.65rem;color:#ff6464;">🔓 SERVICES WITHOUT AUTH:</div>', unsafe_allow_html=True)
            for srv in sin_auth:
                st.markdown(f'<div style="font-family:JetBrains Mono,monospace;font-size:.62rem;color:#ff9999;padding-left:1rem;">• {srv}</div>', unsafe_allow_html=True)
    
    with c2:
        # Puertos administrativos expuestos
        admin_ports = ctrl_data.get('puertos_administrativos_expuestos', [])
        if admin_ports:
            st.markdown(
                f'<div style="border:1px solid rgba(255,204,0,.2);background:#0a0800;'
                f'padding:10px 12px;font-family:JetBrains Mono,monospace;font-size:.68rem;color:#ffcc00;">'
                f'<span style="color:#7a6600;font-size:.6rem;">⚠️ ADMIN PORTS EXPOSED</span><br>'
                f'<span style="color:#ffcc00;font-size:.75rem;">{", ".join(map(str, admin_ports))}</span>'
                f'</div>',
                unsafe_allow_html=True
            )
    
    # Recomendaciones ACL
    acl_recs = ctrl_data.get('recomendaciones_acl', [])
    if acl_recs:
        st.markdown('<div style="font-family:Orbitron,monospace;font-size:.7rem;color:#00ff6a;margin-top:1rem;margin-bottom:.5rem;">[ ACL RECOMMENDATIONS ]</div>', unsafe_allow_html=True)
        for rec in acl_recs:
            st.markdown(
                f'<div style="padding:7px 12px;margin-bottom:4px;'
                f'border-left:2px solid #00ff6a;background:#030e05;'
                f'font-family:JetBrains Mono,monospace;font-size:.66rem;color:#7dffb0;">'
                f'✓ {rec}</div>',
                unsafe_allow_html=True
            )
    
    # Hardening Analysis
    st.markdown('<div style="font-family:Orbitron,monospace;font-size:.7rem;color:#ffcc00;margin-top:1.2rem;margin-bottom:.5rem;">[ HARDENING STATUS ]</div>', unsafe_allow_html=True)
    
    h1, h2, h3 = st.columns(3)
    with h1:
        srv_innec = hard_data.get('servicios_innecesarios', [])
        st.metric("UNNECESSARY SERVICES", len(srv_innec))
        if srv_innec:
            for srv in srv_innec[:3]:
                st.caption(f"• {srv}")
    
    with h2:
        proto_inseg = hard_data.get('protocolos_inseguros', [])
        st.metric("INSECURE PROTOCOLS", len(proto_inseg))
        if proto_inseg:
            for proto in proto_inseg[:3]:
                st.caption(f"• {proto}")
    
    with h3:
        seg_status = "NO" if hard_data.get('falta_segmentacion') else "YES"
        seg_color = "#ff6464" if hard_data.get('falta_segmentacion') else "#00ff6a"
        st.markdown(
            f'<div style="font-family:JetBrains Mono,monospace;font-size:.65rem;color:#7a7a7a;">NETWORK SEGMENTATION</div>'
            f'<div style="font-family:Orbitron,monospace;font-size:1.2rem;color:{seg_color};font-weight:700;">{seg_status}</div>',
            unsafe_allow_html=True
        )
    
    # Medidas de hardening sugeridas
    medidas = hard_data.get('medidas_sugeridas', [])
    if medidas:
        st.markdown('<div style="font-family:JetBrains Mono,monospace;font-size:.65rem;color:#ffcc00;margin-top:.8rem;">📋 HARDENING MEASURES:</div>', unsafe_allow_html=True)
        for medida in medidas:
            st.markdown(
                f'<div style="padding:6px 10px;margin-bottom:3px;'
                f'border-left:2px solid #ffcc00;background:#0a0800;'
                f'font-family:JetBrains Mono,monospace;font-size:.64rem;color:#ffdd77;">'
                f'→ {medida}</div>',
                unsafe_allow_html=True
            )
    
    # Post-Exploitation Vectors
    if post_exp:
        st.markdown('<div style="font-family:Orbitron,monospace;font-size:.7rem;color:#ff6464;margin-top:1.2rem;margin-bottom:.5rem;">[ POST-EXPLOITATION VECTORS ]</div>', unsafe_allow_html=True)
        for i, vector in enumerate(post_exp, 1):
            st.markdown(
                f'<div style="padding:9px 12px;margin-bottom:5px;'
                f'border:1px solid rgba(255,100,100,.2);border-left:3px solid #ff6464;'
                f'background:#0a0404;font-family:JetBrains Mono,monospace;font-size:.68rem;color:#ff9999;">'
                f'<span style="color:#ff6464;font-weight:600;">#{i}</span> {vector}</div>',
                unsafe_allow_html=True
            )
else:
    st.info("PENDING — awaiting agent 3 (Attack Surface)")

if ag[3]:
    rec = ag[3].get("recomendacion_inmediata","")
    if rec:
        st.markdown('<div class="sec-hdr" style="margin-top:1rem;">// PRIORITY RECOMMENDATION</div>',
                    unsafe_allow_html=True)
        st.markdown(
            f'<div style="border:1px solid rgba(255,204,0,.22);border-left:3px solid #ffcc00;'
            f'background:#0a0800;padding:11px 15px;font-family:JetBrains Mono,monospace;'
            f'font-size:.74rem;color:#ffcc00;">'
            f'<span style="opacity:.5;font-size:.6rem;letter-spacing:.1em;">⚠ ACTION REQUIRED</span>'
            f'<br><span style="margin-top:4px;display:block;">{rec}</span>'
            f'</div>', unsafe_allow_html=True)

st.divider()

#  INTEGRANTE 3 — CVE & THREAT INTEL DASHBOARD

st.markdown('<div class="sec-hdr">// INTEGRANTE 3 — INTELLIGENCE & RISK ANALYSIS</div>', unsafe_allow_html=True)

# CVE Analysis Metrics (Agent 7)
if ag[7]:
    st.markdown('<div style="font-family:Orbitron,monospace;font-size:.75rem;color:#00ff6a;margin-bottom:.7rem;">[ CVE INTELLIGENCE SUMMARY ]</div>', unsafe_allow_html=True)
    
    analisis_cvss = ag[7].get("analisis_cvss", {})
    vuln_especiales = ag[7].get("vulnerabilidades_especiales", {})
    
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("CRITICAL", analisis_cvss.get("critical", 0))
    c2.metric("HIGH", analisis_cvss.get("high", 0))
    c3.metric("MEDIUM", analisis_cvss.get("medium", 0))
    c4.metric("AVG SCORE", analisis_cvss.get("avg_score", 0))
    c5.metric("TOTAL CVEs", ag[7].get("total_cves", 0))
    
    # Zero-day y Supply Chain
    if vuln_especiales.get("zero_day_count", 0) > 0 or vuln_especiales.get("supply_chain_count", 0) > 0:
        st.markdown('<div style="font-family:JetBrains Mono,monospace;font-size:.65rem;color:#ff6464;margin-top:.8rem;">🚨 SPECIAL VULNERABILITIES:</div>', unsafe_allow_html=True)
        
        s1, s2 = st.columns(2)
        with s1:
            if vuln_especiales.get("zero_day_count", 0) > 0:
                st.markdown(
                    f'<div style="padding:8px 12px;margin-bottom:5px;'
                    f'border:1px solid rgba(255,100,100,.3);border-left:3px solid #ff6464;'
                    f'background:#0a0404;font-family:JetBrains Mono,monospace;font-size:.68rem;color:#ff9999;">'
                    f'🔥 ZERO-DAY: {vuln_especiales.get("zero_day_count", 0)}<br>'
                    f'<span style="font-size:.6rem;color:#ff6464;opacity:.8;">{", ".join(vuln_especiales.get("zero_day_ids", []))}</span>'
                    f'</div>',
                    unsafe_allow_html=True
                )
        
        with s2:
            if vuln_especiales.get("supply_chain_count", 0) > 0:
                st.markdown(
                    f'<div style="padding:8px 12px;margin-bottom:5px;'
                    f'border:1px solid rgba(255,204,0,.3);border-left:3px solid #ffcc00;'
                    f'background:#0a0800;font-family:JetBrains Mono,monospace;font-size:.68rem;color:#ffdd77;">'
                    f'⛓️ SUPPLY CHAIN: {vuln_especiales.get("supply_chain_count", 0)}<br>'
                    f'<span style="font-size:.6rem;color:#ffcc00;opacity:.8;">{", ".join(vuln_especiales.get("supply_chain_ids", []))}</span>'
                    f'</div>',
                    unsafe_allow_html=True
                )

# Threat Intelligence (Agent 8)
if ag[8]:
    st.markdown('<div style="font-family:Orbitron,monospace;font-size:.75rem;color:#ffcc00;margin-top:1.2rem;margin-bottom:.7rem;">[ THREAT INTELLIGENCE SUMMARY ]</div>', unsafe_allow_html=True)
    
    resumen_amenazas = ag[8].get("resumen_amenazas", {})
    
    t1, t2, t3, t4, t5, t6 = st.columns(6)
    t1.metric("MALICIOUS", resumen_amenazas.get("maliciosos", 0))
    t2.metric("SUSPICIOUS", resumen_amenazas.get("sospechosos", 0))
    t3.metric("CLEAN", resumen_amenazas.get("limpios", 0))
    t4.metric("CAMPAIGNS", resumen_amenazas.get("campanas_activas", 0))
    t5.metric("ACTORS", resumen_amenazas.get("threat_actors_unicos", 0))
    t6.metric("MITRE TTPs", resumen_amenazas.get("mitre_tactics_detected", 0))
    
    # Mostrar IOCs con detalles expandidos
    iocs = ag[8].get("iocs", [])
    if iocs:
        st.markdown('<div style="font-family:JetBrains Mono,monospace;font-size:.65rem;color:#7dffb0;margin-top:.8rem;">📊 IOC DETAILS:</div>', unsafe_allow_html=True)
        for ioc in iocs:
            rep = ioc.get("reputacion", "")
            color = "#ff6464" if rep == "malicioso" else "#ffcc44" if rep == "sospechoso" else "#00ff6a"
            
            with st.expander(f"🔍 {ioc.get('ip', 'N/A')} — {rep.upper()}"):
                col1, col2 = st.columns(2)
                with col1:
                    st.markdown(f"**Abuse Score:** {ioc.get('abuse_score', 0)}/100")
                    st.markdown(f"**Reputación:** {rep}")
                    st.markdown(f"**Fuente:** {ioc.get('fuente', 'N/A')}")
                
                with col2:
                    campanas = ioc.get("campanas_malware", [])
                    if campanas:
                        st.markdown("**Campañas Malware:**")
                        for camp in campanas:
                            st.markdown(f"- {camp.get('nombre', 'N/A')} ({camp.get('tipo', 'N/A')})")
                
                # MITRE ATT&CK
                mitre_tactics = ioc.get("mitre_attack_tactics", [])
                if mitre_tactics:
                    st.markdown("**MITRE ATT&CK Tactics:**")
                    for tactic in mitre_tactics:
                        st.markdown(f"- **{tactic.get('tactic_id', 'N/A')}:** {tactic.get('tactic_name', 'N/A')}")
                        for tech in tactic.get('techniques', []):
                            st.markdown(f"  - {tech}")

# Risk Correlation (Agent 9)
if ag[9]:
    st.markdown('<div style="font-family:Orbitron,monospace;font-size:.75rem;color:#ff6464;margin-top:1.2rem;margin-bottom:.7rem;">[ RISK CORRELATION ANALYSIS ]</div>', unsafe_allow_html=True)
    
    desglose = ag[9].get("desglose", {})
    factores = ag[9].get("factores_criticos", [])
    analisis_ia = ag[9].get("analisis_ia", "")
    
    r1, r2, r3, r4, r5 = st.columns(5)
    r1.metric("RED/NETWORK", desglose.get("red", 0))
    r2.metric("WEB/OWASP", desglose.get("web_owasp", 0))
    r3.metric("CVEs", desglose.get("cves", 0))
    r4.metric("THREAT INTEL", desglose.get("threat_intel", 0))
    r5.metric("TOTAL", ag[9].get("score_total", 0), ag[9].get("nivel", ""))
    
    # Factores críticos
    if factores:
        st.markdown('<div style="font-family:JetBrains Mono,monospace;font-size:.65rem;color:#ff6464;margin-top:.8rem;">⚠️ CRITICAL RISK FACTORS:</div>', unsafe_allow_html=True)
        for factor in factores[:5]:  # Mostrar top 5
            st.markdown(
                f'<div style="padding:6px 10px;margin-bottom:3px;'
                f'border-left:2px solid #ff6464;background:#0a0404;'
                f'font-family:JetBrains Mono,monospace;font-size:.64rem;color:#ff9999;">'
                f'→ {factor}</div>',
                unsafe_allow_html=True
            )
    
    # Análisis IA
    if analisis_ia:
        st.markdown('<div style="font-family:Orbitron,monospace;font-size:.7rem;color:#00ff6a;margin-top:1rem;margin-bottom:.5rem;">[ AI RISK ANALYSIS ]</div>', unsafe_allow_html=True)
        st.markdown(
            f'<div style="border:1px solid rgba(0,255,106,.15);background:#030e05;'
            f'padding:12px 15px;font-family:JetBrains Mono,monospace;font-size:.70rem;'
            f'color:#7dffb0;line-height:1.5;">'
            f'{analisis_ia}'
            f'</div>',
            unsafe_allow_html=True
        )

st.divider()

#  COMPLIANCE (INTEGRANTE 4)

st.markdown('<div class="sec-hdr">// COMPLIANCE STATUS</div>', unsafe_allow_html=True)

cmp = ag[10]
if cmp:
    checks = cmp.get("compliance_checks", [])
    res10  = cmp.get("resumen", {})
    por_framework = cmp.get("por_framework", {})
    
    # Métricas generales
    if res10:
        r1, r2, r3, r4, r5 = st.columns(5)
        r1.metric("TOTAL CHECKS", res10.get("total_checks", "—"))
        r2.metric("✓ PASS", res10.get("cumple", "—"))
        r3.metric("✕ FAIL", res10.get("falla", "—"))
        r4.metric("⚠ PARTIAL", res10.get("parcial", "—"))
        pct = res10.get("porcentaje_cumplimiento", 0)
        r5.metric("COMPLIANCE %", f"{pct:.1f}%")
    
    # Resumen por framework
    if por_framework:
        st.markdown('<div style="font-family:Orbitron,monospace;font-size:.7rem;color:#00ff6a;margin-top:1rem;margin-bottom:.5rem;">[ COMPLIANCE BY FRAMEWORK ]</div>', unsafe_allow_html=True)
        
        fw_cols = st.columns(min(len(por_framework), 4))
        for idx, (fw_name, fw_data) in enumerate(por_framework.items()):
            if idx < len(fw_cols):
                with fw_cols[idx]:
                    total_fw = fw_data.get("total", 0)
                    falla_fw = fw_data.get("falla", 0)
                    cumple_fw = fw_data.get("cumple", 0)
                    
                    # Color según nivel de fallo
                    if total_fw > 0:
                        fail_pct = (falla_fw / total_fw) * 100
                        if fail_pct > 60:
                            color = "#ff6464"
                        elif fail_pct > 30:
                            color = "#ffcc44"
                        else:
                            color = "#4dcc7a"
                    else:
                        color = "#7dffb0"
                    
                    st.markdown(
                        f'<div style="padding:8px 10px;border:1px solid {color}22;border-left:3px solid {color};background:#030a04;margin-bottom:8px;">'
                        f'<div style="font-family:Orbitron,monospace;color:{color};font-size:.64rem;font-weight:600;margin-bottom:4px;">{fw_name}</div>'
                        f'<div style="font-family:JetBrains Mono,monospace;font-size:.58rem;color:#7dffb0;">'
                        f'<span style="color:#4dcc7a;">✓ {cumple_fw}</span> / '
                        f'<span style="color:#ff6464;">✕ {falla_fw}</span> / '
                        f'<span style="color:#ffcc44;">⚠ {fw_data.get("parcial", 0)}</span>'
                        f'</div>'
                        f'</div>',
                        unsafe_allow_html=True
                    )
    
    # Tabla de checks de compliance
    if checks:
        st.markdown('<div style="font-family:Orbitron,monospace;font-size:.7rem;color:#00ff6a;margin-top:1rem;margin-bottom:.5rem;">[ COMPLIANCE CHECKS DETAIL ]</div>', unsafe_allow_html=True)
        
        # Crear DataFrame con columnas específicas
        checks_df = dataframe_from_records(checks)
        if not checks_df.empty:
            # Seleccionar columnas relevantes para mostrar
            display_cols = ["framework", "control", "hallazgo", "estado", "severidad", "accion_correctiva"]
            available_cols = [col for col in display_cols if col in checks_df.columns]
            st.dataframe(checks_df[available_cols], width="stretch", hide_index=True, height=300)
    
    # Excepciones
    excepciones = cmp.get("excepciones", [])
    if excepciones:
        st.markdown('<div style="font-family:Orbitron,monospace;font-size:.7rem;color:#ffcc44;margin-top:1rem;margin-bottom:.5rem;">[ ⚠ COMPLIANCE EXCEPTIONS ]</div>', unsafe_allow_html=True)
        for exc in excepciones:
            st.markdown(
                f'<div style="padding:8px 12px;margin-bottom:6px;border:1px solid rgba(255,204,0,.2);'
                f'border-left:3px solid #ffcc00;background:#0a0800;">'
                f'<div style="font-family:JetBrains Mono,monospace;font-size:.68rem;color:#ffcc00;margin-bottom:3px;">'
                f'<span style="font-weight:600;">{exc.get("hallazgo_id", "N/A")}</span> - {exc.get("control", "N/A")}</div>'
                f'<div style="font-family:JetBrains Mono,monospace;font-size:.62rem;color:#d4a600;line-height:1.4;">'
                f'Justificación: {exc.get("justificacion", "N/A")}<br>'
                f'Aprobador: {exc.get("aprobador", "N/A")} | Expira: {exc.get("fecha_expiracion", "N/A")}<br>'
                f'Riesgo Residual: {exc.get("riesgo_residual", "N/A").upper()}'
                f'</div>'
                f'</div>',
                unsafe_allow_html=True
            )
    
    # Controles compensatorios
    controles_comp = cmp.get("controles_compensatorios", [])
    if controles_comp:
        st.markdown('<div style="font-family:Orbitron,monospace;font-size:.7rem;color:#4dcc7a;margin-top:1rem;margin-bottom:.5rem;">[ 🛡️ COMPENSATING CONTROLS ]</div>', unsafe_allow_html=True)
        for ctrl in controles_comp:
            efectividad = ctrl.get("efectividad", "N/A")
            st.markdown(
                f'<div style="padding:8px 12px;margin-bottom:6px;border:1px solid rgba(77,204,122,.2);'
                f'border-left:3px solid #4dcc7a;background:#030a04;">'
                f'<div style="font-family:JetBrains Mono,monospace;font-size:.68rem;color:#4dcc7a;margin-bottom:3px;">'
                f'Original: <span style="color:#7dffb0;">{ctrl.get("control_original", "N/A")}</span></div>'
                f'<div style="font-family:JetBrains Mono,monospace;font-size:.62rem;color:#5a8a6a;line-height:1.4;">'
                f'Compensatorio: {ctrl.get("control_compensatorio", "N/A")}<br>'
                f'Efectividad: <span style="color:#4dcc7a;font-weight:600;">{efectividad}</span> | '
                f'Nivel: {ctrl.get("nivel_compensacion", "N/A")}'
                f'</div>'
                f'</div>',
                unsafe_allow_html=True
            )
else:
    st.info("PENDING — awaiting agent 10 (Integrante 4)")

st.divider()

#  EXPLOIT INTELLIGENCE (AGENT 11)

st.markdown('<div class="sec-hdr">// EXPLOIT INTELLIGENCE & PATCH PRIORITIZATION</div>', unsafe_allow_html=True)

if ag[11]:
    recomendaciones = ag[11].get("recomendaciones", [])
    resumen11 = ag[11].get("resumen", {})
    analisis_pri = ag[11].get("analisis_prioridades", {})
    att_ck_sum = ag[11].get("att_ck_summary", {})
    
    # Métricas principales
    if resumen11:
        m1, m2, m3, m4, m5, m6 = st.columns(6)
        m1.metric("TOTAL CVEs", resumen11.get("total_cves", "—"))
        m2.metric("MSF EXPLOIT", resumen11.get("con_modulo_msf", "—"))
        m3.metric("EXPLOITDB", resumen11.get("con_exploitdb", "—"))
        m4.metric("GITHUB POC", resumen11.get("con_github_poc", "—"))
        m5.metric("HIGH PROB", resumen11.get("alta_probabilidad", "—"), 
                  delta="Critical" if resumen11.get("alta_probabilidad", 0) > 0 else None,
                  delta_color="inverse")
        m6.metric("NO EXPLOIT", resumen11.get("sin_exploit_publico", "—"), 
                  delta="Safe" if resumen11.get("sin_exploit_publico", 0) > 0 else None)
    
    # Priorización de parcheo
    if resumen11:
        st.markdown('<div style="font-family:Orbitron,monospace;font-size:.7rem;color:#00ff6a;margin-top:1rem;margin-bottom:.5rem;">[ 🎯 PATCH PRIORITY MATRIX ]</div>', unsafe_allow_html=True)
        
        pri_cols = st.columns(4)
        priorities = [
            ("P0", "prioridad_p0", "#ff3333", "CRITICAL"),
            ("P1", "prioridad_p1", "#ff6464", "HIGH"),
            ("P2", "prioridad_p2", "#ffcc44", "MEDIUM"),
            ("P3", "prioridad_p3", "#4dcc7a", "LOW")
        ]
        
        for idx, (pri_label, pri_key, pri_color, pri_text) in enumerate(priorities):
            if idx < len(pri_cols):
                with pri_cols[idx]:
                    count = resumen11.get(pri_key, 0)
                    st.markdown(
                        f'<div style="padding:10px 12px;border:1px solid {pri_color}22;'
                        f'border-left:3px solid {pri_color};background:#030a04;text-align:center;">'
                        f'<div style="font-family:Orbitron,monospace;color:{pri_color};font-size:.85rem;font-weight:700;">{pri_label}</div>'
                        f'<div style="font-family:JetBrains Mono,monospace;color:{pri_color};font-size:1.4rem;font-weight:600;">{count}</div>'
                        f'<div style="font-family:Orbitron,monospace;color:{pri_color};font-size:.54rem;opacity:.7;">{pri_text}</div>'
                        f'</div>',
                        unsafe_allow_html=True
                    )
    
    # MITRE ATT&CK Summary
    if att_ck_sum:
        st.markdown('<div style="font-family:Orbitron,monospace;font-size:.7rem;color:#00ff6a;margin-top:1rem;margin-bottom:.5rem;">[ 🎭 MITRE ATT&CK COVERAGE ]</div>', unsafe_allow_html=True)
        
        att_c1, att_c2 = st.columns(2)
        with att_c1:
            st.markdown(
                f'<div style="padding:8px 12px;border:1px solid rgba(0,255,106,.15);background:#030a04;">'
                f'<div style="font-family:JetBrains Mono,monospace;font-size:.68rem;color:#7dffb0;">'
                f'<span style="color:#4dcc7a;font-weight:600;">Tactics:</span> {att_ck_sum.get("total_tactics", 0)} | '
                f'<span style="color:#4dcc7a;font-weight:600;">Techniques:</span> {att_ck_sum.get("total_techniques", 0)}'
                f'</div>'
                f'<div style="font-family:JetBrains Mono,monospace;font-size:.62rem;color:#5a8a6a;margin-top:4px;">'
                f'Most Common: {att_ck_sum.get("most_common_tactic", "N/A")}'
                f'</div>'
                f'</div>',
                unsafe_allow_html=True
            )
        with att_c2:
            tactics_list = att_ck_sum.get("tactics_coverage", [])
            if tactics_list:
                tactics_str = ", ".join([t.split(" - ")[0] for t in tactics_list[:5]])
                st.markdown(
                    f'<div style="padding:8px 12px;border:1px solid rgba(0,255,106,.15);background:#030a04;">'
                    f'<div style="font-family:JetBrains Mono,monospace;font-size:.62rem;color:#5a8a6a;">'
                    f'Covered: {tactics_str}'
                    f'</div>'
                    f'</div>',
                    unsafe_allow_html=True
                )
    
    # Recomendaciones detalladas
    if recomendaciones:
        st.markdown('<div style="font-family:Orbitron,monospace;font-size:.7rem;color:#00ff6a;margin-top:1.2rem;margin-bottom:.5rem;">[ 💀 EXPLOIT INTELLIGENCE DETAILS ]</div>', unsafe_allow_html=True)
        
        # Ordenar por prioridad
        recomendaciones_sorted = sorted(recomendaciones, 
            key=lambda x: (x.get("prioridad_parcheo") or {}).get("score_total", 0), 
            reverse=True)
        
        for rec in recomendaciones_sorted:
            cve_id = rec.get("cve_id", "N/A")
            servicio = rec.get("servicio", "")
            puerto = rec.get("puerto", "")
            cvss = rec.get("cvss_score", 0)
            severidad = rec.get("severidad", "").upper()
            
            # Datos de priorización
            pri_data = rec.get("prioridad_parcheo") or {}
            pri_label = pri_data.get("prioridad", "P4")
            pri_score = pri_data.get("score_total", 0)
            pri_desc = pri_data.get("descripcion", "")
            
            # EPSS data
            epss_data = rec.get("epss") or {}
            epss_score = epss_data.get("epss_score", 0) * 100  # Convert to percentage
            epss_percentile = epss_data.get("epss_percentile", 0)
            
            # ExploitDB
            edb_data = rec.get("exploitdb") or {}
            edb_id = edb_data.get("edb_id")
            
            # GitHub PoC
            github_data = rec.get("github_poc") or {}
            github_repo = github_data.get("repositorio")
            github_stars = github_data.get("estrellas", 0)
            
            # ATT&CK tactics
            att_ck_tactics = rec.get("att_ck_tactics") or []
            
            # Color según prioridad
            if pri_label == "P0":
                color = "#ff3333"
            elif pri_label == "P1":
                color = "#ff6464"
            elif pri_label == "P2":
                color = "#ffcc44"
            else:
                color = "#4dcc7a"
            
            # Card expandible
            with st.expander(f"🎯 {pri_label} | {cve_id} | {servicio}:{puerto} | CVSS {cvss}", expanded=(pri_label in ["P0", "P1"])):
                # Header con prioridad
                st.markdown(
                    f'<div style="padding:10px 14px;margin-bottom:10px;border:1px solid {color}22;'
                    f'border-left:4px solid {color};background:#030a04;">'
                    f'<div style="display:flex;justify-content:space-between;align-items:center;">'
                    f'<div>'
                    f'<span style="font-family:Orbitron,monospace;color:{color};font-size:.9rem;font-weight:700;">{pri_label}</span>'
                    f'<span style="font-family:JetBrains Mono,monospace;color:{color};font-size:.72rem;margin-left:12px;">Score: {pri_score:.1f}/100</span>'
                    f'</div>'
                    f'<div style="font-family:Orbitron,monospace;color:{color};font-size:.64rem;">{pri_desc}</div>'
                    f'</div>'
                    f'</div>',
                    unsafe_allow_html=True
                )
                
                # Métricas de explotabilidad
                col1, col2, col3, col4 = st.columns(4)
                with col1:
                    st.metric("EPSS Score", f"{epss_score:.2f}%", 
                             delta=f"Percentile {epss_percentile:.1f}")
                with col2:
                    st.metric("CVSS", f"{cvss}/10", delta=severidad)
                with col3:
                    edb_status = "✓ Found" if edb_id else "✕ None"
                    st.metric("ExploitDB", edb_status)
                with col4:
                    github_status = f"⭐ {github_stars}" if github_repo else "✕ None"
                    st.metric("GitHub PoC", github_status)
                
                # MITRE ATT&CK Tactics
                if att_ck_tactics:
                    st.markdown(
                        '<div style="font-family:Orbitron,monospace;font-size:.65rem;color:#00ff6a;margin-top:.8rem;margin-bottom:.4rem;">[ MITRE ATT&CK TACTICS ]</div>',
                        unsafe_allow_html=True
                    )
                    tactics_html = ""
                    for tactic in att_ck_tactics[:3]:  # Mostrar max 3
                        tactic_id = tactic.get("tactic_id", "")
                        tactic_name = tactic.get("tactic_name", "")
                        techniques = tactic.get("techniques", [])
                        techniques_str = ", ".join(techniques[:2])  # Max 2 techniques
                        tactics_html += (
                            f'<div style="padding:6px 10px;margin-bottom:4px;border:1px solid rgba(0,255,106,.15);'
                            f'background:#030a04;font-family:JetBrains Mono,monospace;font-size:.62rem;">'
                            f'<span style="color:#4dcc7a;font-weight:600;">{tactic_id}</span> - '
                            f'<span style="color:#7dffb0;">{tactic_name}</span><br>'
                            f'<span style="color:#5a8a6a;font-size:.58rem;">{techniques_str}</span>'
                            f'</div>'
                        )
                    st.markdown(tactics_html, unsafe_allow_html=True)
                
                # Mitigaciones
                mitigaciones = rec.get("mitigaciones", [])
                if mitigaciones:
                    st.markdown(
                        '<div style="font-family:Orbitron,monospace;font-size:.65rem;color:#00ff6a;margin-top:.8rem;margin-bottom:.4rem;">[ 🛡️ MITIGATIONS ]</div>',
                        unsafe_allow_html=True
                    )
                    for i, mit in enumerate(mitigaciones[:5], 1):  # Max 5
                        st.markdown(
                            f'<div style="padding:5px 10px;margin-bottom:3px;border-left:2px solid #4dcc7a;'
                            f'background:#030a04;font-family:JetBrains Mono,monospace;font-size:.62rem;color:#7dffb0;">'
                            f'<span style="color:#4dcc7a;margin-right:6px;">{i}.</span>{mit}'
                            f'</div>',
                            unsafe_allow_html=True
                        )
                
                # Nota adicional
                nota = rec.get("nota", "")
                if nota:
                    st.markdown(
                        f'<div style="padding:8px 12px;margin-top:8px;border:1px solid {color}22;'
                        f'background:#0a0404;font-family:JetBrains Mono,monospace;font-size:.64rem;color:{color};">'
                        f'<span style="opacity:.7;">📌 NOTE:</span> {nota}'
                        f'</div>',
                        unsafe_allow_html=True
                    )
    
    # Disclaimer
    disclaimer = ag[11].get("disclaimer", "")
    if disclaimer:
        st.markdown(
            f'<div style="border:1px solid rgba(255,100,100,.15);background:#0a0404;'
            f'padding:10px 12px;font-family:JetBrains Mono,monospace;font-size:.64rem;'
            f'color:#ff9999;margin-top:1.2rem;">'
            f'<span style="opacity:.6;font-size:.54rem;">⚠️ DISCLAIMER</span><br>'
            f'<span style="margin-top:4px;display:block;opacity:.9;">{disclaimer}</span>'
            f'</div>',
            unsafe_allow_html=True
        )
else:
    st.info("PENDING — awaiting agent 11 (Exploit Intelligence)")

st.divider()

#  RISK CORRELATION (AGENT 9)

st.markdown('<div class="sec-hdr">// CONSOLIDATED RISK ASSESSMENT</div>', unsafe_allow_html=True)

if ag[9]:
    risk_data = ag[9]
    
    # Métricas principales en una fila
    r1, r2, r3, r4, r5, r6 = st.columns(6)
    r1.metric("RISK SCORE", f"{risk_data.get('score_total', '—')}/100")
    r2.metric("RISK LEVEL", risk_data.get('nivel', 'N/A'))
    
    desglose = risk_data.get('desglose', {})
    r3.metric("NETWORK", f"{desglose.get('red', 0)}/25")
    r4.metric("WEB/OWASP", f"{desglose.get('web_owasp', 0)}/30")
    r5.metric("CVEs", f"{desglose.get('cves', 0)}/35")
    r6.metric("THREAT", f"{desglose.get('threat_intel', 0)}/25")
    
    # Gráfico de desglose
    if desglose:
        st.markdown('<div style="font-family:Orbitron,monospace;font-size:.7rem;color:#00ff6a;margin-top:1.2rem;margin-bottom:.5rem;">[ RISK BREAKDOWN ]</div>', unsafe_allow_html=True)
        st.bar_chart(desglose)
    
    # Factores críticos
    factores = risk_data.get('factores_criticos', [])
    if factores:
        st.markdown('<div style="font-family:Orbitron,monospace;font-size:.7rem;color:#00ff6a;margin-top:1.2rem;margin-bottom:.5rem;">[ CRITICAL RISK FACTORS ]</div>', unsafe_allow_html=True)
        for i, factor in enumerate(factores[:8], 1):  # Mostrar máximo 8
            st.markdown(
                f'<div style="padding:8px 12px;margin-bottom:5px;'
                f'border:1px solid rgba(255,100,100,.2);border-left:3px solid #ff6464;'
                f'background:#0a0404;font-family:JetBrains Mono,monospace;font-size:.68rem;color:#ff9999;">'
                f'<span style="color:#ff6464;margin-right:8px;">#{i}</span>{factor}</div>',
                unsafe_allow_html=True
            )
    
    # Fuentes usadas y faltantes
    fuentes_usadas = risk_data.get('fuentes_usadas', [])
    fuentes_faltantes = risk_data.get('fuentes_faltantes', [])
    
    if fuentes_usadas or fuentes_faltantes:
        st.markdown('<div style="font-family:Orbitron,monospace;font-size:.7rem;color:#00ff6a;margin-top:1.2rem;margin-bottom:.5rem;">[ DATA SOURCES ]</div>', unsafe_allow_html=True)
        
        col_usadas, col_faltantes = st.columns(2)
        with col_usadas:
            if fuentes_usadas:
                st.markdown(
                    '<div style="font-family:JetBrains Mono,monospace;font-size:.62rem;color:#4dcc7a;">'
                    f'✓ USED ({len(fuentes_usadas)}): {", ".join(fuentes_usadas)}'
                    '</div>',
                    unsafe_allow_html=True
                )
        with col_faltantes:
            if fuentes_faltantes:
                st.markdown(
                    '<div style="font-family:JetBrains Mono,monospace;font-size:.62rem;color:#ffcc44;">'
                    f'⚠ MISSING ({len(fuentes_faltantes)}): {", ".join(fuentes_faltantes)}'
                    '</div>',
                    unsafe_allow_html=True
                )
    
    # Recomendación inmediata
    recomendacion = risk_data.get('recomendacion_inmediata', '')
    if recomendacion:
        st.markdown(
            f'<div style="border:1px solid rgba(255,204,0,.22);border-left:3px solid #ffcc00;'
            f'background:#0a0800;padding:11px 15px;font-family:JetBrains Mono,monospace;'
            f'font-size:.72rem;color:#ffcc00;margin-top:1.2rem;">'
            f'<span style="opacity:.6;font-size:.58rem;letter-spacing:.1em;">⚡ PRIORITY ACTION</span><br>'
            f'<span style="margin-top:4px;display:block;">{recomendacion}</span>'
            f'</div>',
            unsafe_allow_html=True
        )
    
    # Análisis IA (si existe)
    analisis_ia = risk_data.get('analisis_ia', '')
    modelo_info = risk_data.get('modelo_usado', {})
    if analisis_ia and 'no disponible' not in analisis_ia.lower():
        st.markdown('<div style="font-family:Orbitron,monospace;font-size:.7rem;color:#00ff6a;margin-top:1.2rem;margin-bottom:.5rem;">[ AI RISK ANALYSIS ]</div>', unsafe_allow_html=True)
        st.markdown(
            f'<div style="border:1px solid rgba(0,255,106,.15);background:#030e05;'
            f'padding:12px 14px;font-family:JetBrains Mono,monospace;font-size:.68rem;'
            f'color:#7dffb0;line-height:1.6;">{analisis_ia}</div>',
            unsafe_allow_html=True
        )
        if modelo_info:
            st.caption(f"🤖 Model: {modelo_info.get('modelo', 'N/A')} | Type: {modelo_info.get('tipo', 'N/A')}")
            
else:
    st.info("PENDING — awaiting agent 9 (Risk Correlation)")

st.divider()
st.markdown('<div class="sec-hdr">// CHAT INTERACTIVO — CONSULTAS EN TIEMPO REAL</div>', unsafe_allow_html=True)

CHAT_HISTORY_FILE = os.path.join("shared_data", "chat_history.json")
AI_CHAT_MODEL = os.getenv("SECDASH_AI_MODEL", "minimax-m3:cloud")

try:
    from openai import OpenAI
    chat_ai = OpenAI(
        base_url=os.getenv("OLLAMA_BASE_URL", "http://localhost:11434/v1"),
        api_key=os.getenv("OLLAMA_API_KEY", "ollama"),
    )
    chat_available = True
    st.markdown(
        '<div style="font-family:JetBrains Mono,monospace;font-size:.64rem;color:#00ff6a;margin-bottom:.8rem;">'
        f'[ CHAT ] ✓ IA lista — {AI_CHAT_MODEL} | Bilingüe: English/Español'
        '</div>', unsafe_allow_html=True)
except Exception as e:
    chat_available = False
    st.markdown(
        f'<div style="font-family:JetBrains Mono,monospace;font-size:.64rem;color:#ffcc00;margin-bottom:.8rem;">'
        f'[ CHAT ] ⚠ IA offline — {str(e)[:50]}'
        '</div>', unsafe_allow_html=True)

def load_chat_history():
    try:
        with open(CHAT_HISTORY_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except:
        return [
            {"role": "assistant", "content": "🤖 **SecDash Security Assistant** en línea.\n\nPuedo ayudarte en **español** o **English**:\n- Analizar vulnerabilidades y CVEs\n- Explicar hallazgos de seguridad\n- Recomendar acciones de remediación\n- Interpretar datos de threat intelligence\n\n💡 Pregunta sobre cualquier dato del dashboard."}
        ]

def save_chat_history(messages):
    try:
        with open(CHAT_HISTORY_FILE, "w", encoding="utf-8") as f:
            json.dump(messages, f, indent=2, ensure_ascii=False)
    except Exception as e:
        st.error(f"Error guardando historial: {e}")

if "messages" not in st.session_state:
    st.session_state.messages = load_chat_history()

col_clear, col_download = st.columns([1, 1])
with col_clear:
    if st.button("🗑️ Limpiar Historial"):
        st.session_state.messages = [st.session_state.messages[0]]
        save_chat_history(st.session_state.messages)
        st.rerun()

with col_download:
    chat_json = json.dumps(st.session_state.messages, indent=2, ensure_ascii=False)
    st.download_button(
        label="📥 Descargar Chat",
        data=chat_json,
        file_name=f"secdash_chat_{target}.json",
        key="download_chat",
        mime="application/json"
    )

for msg in st.session_state.messages:
    with st.chat_message(msg["role"]):
        st.markdown(msg["content"])

if prompt := st.chat_input("Escribe tu pregunta en español o inglés..."):
    st.session_state.messages.append({"role": "user", "content": prompt})
    with st.chat_message("user"):
        st.markdown(prompt)

    # Crear contexto con datos del dashboard
    dashboard_context = f"""
DATOS ACTUALES DEL DASHBOARD:
- Target: {target}
- Agentes activos: {agentes_ok}/12
- Risk Score: {score}/100 ({nivel})

RESUMEN DE DATOS:
- Servicios detectados: {len((ag[2] or {}).get('services', []))}
- Vulnerabilidades web: {len((ag[4] or {}).get('hallazgos', [])) + len((ag[5] or {}).get('hallazgos', []))}
- CVEs encontrados: {len((ag[7] or {}).get('cves_encontrados', []))}
- IOCs analizados: {len((ag[8] or {}).get('iocs', []))}
- Controles compliance: {len((ag[10] or {}).get('compliance_checks', []))}

Tienes acceso contextual a todos estos datos para dar respuestas precisas.
"""

    with st.chat_message("assistant"):
        if not chat_available:
            response_text = f"⚠️ **Chat IA desconectado**\n\nAsegúrate de que Ollama esté corriendo:\n```bash\nollama serve\nollama pull {AI_CHAT_MODEL}\n```"
            st.markdown(response_text)
        else:
            with st.spinner("Analizando..." if any(c in prompt.lower() for c in "áéíóúñ¿¡") else "Analyzing..."):
                try:
                    response = chat_ai.chat.completions.create(
                        model=AI_CHAT_MODEL,
                        messages=[
                            {"role": "system", "content": f"""Eres un asistente de ciberseguridad especializado en análisis SOC.

ROLE: Analista senior con experiencia en:
- Análisis de vulnerabilidades (Nikto, Nuclei, CVEs)
- Threat intelligence y reputación de IOCs
- Compliance y controles de seguridad
- MITRE ATT&CK, OWASP Top 10, frameworks ISO 27001

INSTRUCCIONES:
1. DETECTA EL IDIOMA de la pregunta y responde en el MISMO IDIOMA
2. Sé técnico, preciso y accionable
3. Cita la fuente del agente cuando referencien datos específicos
   - Español: "Según el Agente 4...", "El Agente 7 detectó..."
   - English: "According to Agent 4...", "Agent 7 detected..."
4. Prioriza hallazgos críticos y recomendaciones prácticas
5. Usa emojis para claridad: 🔴 (crítico), 🟡 (medio), 🟢 (bajo)

CONTEXTO DEL DASHBOARD:
{dashboard_context}

Responde basándote en estos datos reales cuando sea relevante."""},
                            *st.session_state.messages[-10:],  # Últimas 10 interacciones
                            {"role": "user", "content": prompt}
                        ],
                        max_tokens=800,
                        temperature=0.3,
                        top_p=0.9
                    )
                    response_text = response.choices[0].message.content
                    st.markdown(response_text)
                except Exception as e:
                    response_text = f"❌ **Error de comunicación con IA**: {str(e)}\n\nVerifica que Ollama esté corriendo y el modelo {AI_CHAT_MODEL} instalado."
                    st.markdown(response_text)

    st.session_state.messages.append({"role": "assistant", "content": response_text})
    save_chat_history(st.session_state.messages)

st.divider()
st.markdown(
    f'<div style="display:flex;justify-content:space-between;flex-wrap:wrap;gap:.4rem;'
    f'font-family:JetBrains Mono,monospace;font-size:.58rem;color:#1a3320;">'
    f'<span>SECDASH AI SOC — CURSO DE SEGURIDAD EN COMPUTACIÓN</span>'
    f'<span>AGENTS: {agentes_ok}/12 · TARGET: {target}</span>'
    f'</div>', unsafe_allow_html=True)