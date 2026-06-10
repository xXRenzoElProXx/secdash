"""
dashboard.py — SecDash AI SOC
Dashboard principal. Lee los JSONs de shared_data/ y muestra el reporte.

Uso:
    streamlit run dashboard.py
"""

import streamlit as st
import json, os, subprocess

st.set_page_config(
    page_title="SecDash AI SOC",
    page_icon="🛡",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ══════════════════════════════════════════════════════════════════════════════
#  ESTILOS
# ══════════════════════════════════════════════════════════════════════════════

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@700;900&family=JetBrains+Mono:wght@400;500&display=swap');

/* ── Base ── */
*, *::before, *::after { box-sizing: border-box; }
html, body, [class*="css"] {
    font-family: 'JetBrains Mono', monospace !important;
    background: #040d06 !important;
    color: #7dffb0 !important;
}
.stApp { background: #040d06 !important; }

/* CRT lines — CSS-only, cero JS, muy ligero */
.stApp::after {
    content: "";
    position: fixed; inset: 0;
    background: repeating-linear-gradient(
        180deg,
        transparent 0px, transparent 3px,
        rgba(0,0,0,0.055) 3px, rgba(0,0,0,0.055) 4px
    );
    pointer-events: none;
    z-index: 9000;
}

/* ── Layout ── */
.block-container {
    padding-top: 0.8rem !important;
    padding-left: 1.4rem !important;
    padding-right: 1.4rem !important;
    max-width: 1440px !important;
}
[data-testid="column"] { padding: 0 0.35rem !important; }
#MainMenu, footer, header { visibility: hidden !important; }

/* ── Sidebar ── */
section[data-testid="stSidebar"] {
    background: #020b04 !important;
    border-right: 1px solid rgba(0,255,106,.13) !important;
    width: 230px !important; min-width: 230px !important;
}
section[data-testid="stSidebar"] > div { background: transparent !important; padding: 0 !important; }
[data-testid="collapsedControl"] {
    color: #00ff6a !important; background: #020b04 !important;
    border-right: 1px solid rgba(0,255,106,.12) !important;
}

/* ── Typography ── */
h1,h2,h3 {
    font-family: 'Orbitron', monospace !important;
    color: #00ff6a !important;
    text-shadow: 0 0 16px rgba(0,255,106,.4), 0 0 32px rgba(0,255,106,.12) !important;
    letter-spacing: .08em !important;
}
h1 { font-size: 1.55rem !important; font-weight: 900 !important; }
h2 { font-size: .95rem  !important; font-weight: 700 !important; }
h3 { font-size: .82rem  !important; font-weight: 700 !important; }

/* ── Metric cards ── */
[data-testid="metric-container"] {
    background: #050f07 !important;
    border: 1px solid rgba(0,255,106,.18) !important;
    border-top: 2px solid #00ff6a !important;
    border-radius: 2px !important;
    padding: .9rem !important;
    position: relative; overflow: hidden;
    box-shadow: 0 0 18px rgba(0,255,106,.05) !important;
    transition: box-shadow .3s, transform .25s !important;
}
[data-testid="metric-container"]:hover {
    box-shadow: 0 0 28px rgba(0,255,106,.15) !important;
    transform: translateY(-2px) !important;
}
/* sweep line — CSS only */
[data-testid="metric-container"]::before {
    content: '';
    position: absolute; top: 0; left: -100%; width: 60%; height: 1px;
    background: linear-gradient(90deg, transparent, rgba(0,255,106,.7), transparent);
    animation: sweep 5s ease-in-out infinite;
}
@keyframes sweep { 0%{left:-60%} 60%{left:160%} 100%{left:160%} }

[data-testid="stMetricValue"] {
    font-family: 'Orbitron', monospace !important;
    font-size: 1.45rem !important; font-weight: 700 !important;
    color: #00ff6a !important;
    text-shadow: 0 0 10px rgba(0,255,106,.5) !important;
}
[data-testid="stMetricLabel"] {
    font-family: 'JetBrains Mono', monospace !important;
    font-size: .6rem !important; color: #4dcc7a !important;
    letter-spacing: .14em !important; text-transform: uppercase !important;
}
[data-testid="stMetricDelta"] { font-family: 'JetBrains Mono', monospace !important; font-size: .66rem !important; }

/* ── Buttons ── */
.stButton > button {
    background: transparent !important; color: #00ff6a !important;
    border: 1px solid #00ff6a !important; border-radius: 2px !important;
    font-family: 'Orbitron', monospace !important; font-size: .68rem !important;
    font-weight: 700 !important; letter-spacing: .1em !important;
    text-transform: uppercase !important; padding: .45rem 1.1rem !important;
    transition: background .2s, box-shadow .2s, transform .15s !important;
    box-shadow: 0 0 8px rgba(0,255,106,.15) !important;
}
.stButton > button:hover {
    background: rgba(0,255,106,.08) !important;
    box-shadow: 0 0 20px rgba(0,255,106,.35) !important;
    transform: translateY(-1px) !important;
}
.stButton > button:active { transform: translateY(0) scale(.98) !important; }

/* ── Text input ── */
.stTextInput > div > div > input {
    background: #050f07 !important; color: #00ff6a !important;
    border: 1px solid rgba(0,255,106,.25) !important; border-radius: 2px !important;
    font-family: 'JetBrains Mono', monospace !important; font-size: .8rem !important;
    padding: .45rem .7rem !important;
    transition: border-color .2s, box-shadow .2s !important;
}
.stTextInput > div > div > input:focus {
    border-color: #00ff6a !important; box-shadow: 0 0 12px rgba(0,255,106,.2) !important; outline: none !important;
}
.stTextInput > div > div > input::placeholder { color: #265c36 !important; }
.stTextInput label {
    color: #4dcc7a !important; font-size: .6rem !important;
    letter-spacing: .12em !important; text-transform: uppercase !important;
}

/* ── Divider ── */
hr { border: none !important; border-top: 1px solid rgba(0,255,106,.1) !important; margin: 1.2rem 0 !important; }

/* ── Expanders ── */
.streamlit-expanderHeader {
    background: #050f07 !important; border: 1px solid rgba(0,255,106,.12) !important;
    border-radius: 2px !important; color: #7dffb0 !important;
    font-family: 'JetBrains Mono', monospace !important; font-size: .72rem !important;
    transition: background .2s !important;
}
.streamlit-expanderHeader:hover { background: #071509 !important; }
.streamlit-expanderContent {
    background: #030a04 !important; border: 1px solid rgba(0,255,106,.07) !important; border-top: none !important;
}

/* ── Dataframes ── */
.stDataFrame { border: 1px solid rgba(0,255,106,.12) !important; border-radius: 2px !important; }
.stDataFrame table { background: #030a04 !important; color: #7dffb0 !important; font-family: 'JetBrains Mono', monospace !important; font-size: .72rem !important; }
.stDataFrame thead th {
    background: #050f07 !important; color: #00ff6a !important;
    font-family: 'Orbitron', monospace !important; font-size: .6rem !important;
    letter-spacing: .07em !important; border-bottom: 1px solid rgba(0,255,106,.25) !important;
}
.stDataFrame tbody tr:hover { background: rgba(0,255,106,.03) !important; }

/* ── Alerts ── */
.stInfo,[data-testid="stInfo"] {
    background:#030a04 !important; border:1px solid rgba(0,255,106,.12) !important;
    border-left:3px solid rgba(0,255,106,.3) !important; border-radius:2px !important;
    color:#4dcc7a !important; font-family:'JetBrains Mono',monospace !important; font-size:.7rem !important;
}
.stSuccess,[data-testid="stSuccess"] {
    background:#030a04 !important; border:1px solid rgba(0,255,106,.25) !important;
    border-left:3px solid #00ff6a !important; border-radius:2px !important;
    color:#00ff6a !important; font-family:'JetBrains Mono',monospace !important; font-size:.7rem !important;
}
.stWarning,[data-testid="stWarning"] {
    background:#0a0800 !important; border:1px solid rgba(255,204,0,.18) !important;
    border-left:3px solid #ffcc00 !important; border-radius:2px !important;
    color:#ffcc00 !important; font-family:'JetBrains Mono',monospace !important; font-size:.7rem !important;
}
.stError,[data-testid="stError"] {
    background:#0a0000 !important; border:1px solid rgba(255,51,51,.18) !important;
    border-left:3px solid #ff3333 !important; border-radius:2px !important;
    color:#ff6666 !important; font-family:'JetBrains Mono',monospace !important; font-size:.7rem !important;
}

/* ── Progress ── */
.stProgress > div > div > div {
    background: linear-gradient(90deg, #00ff6a, #4dffaa) !important;
    box-shadow: 0 0 6px rgba(0,255,106,.45) !important;
}
.stProgress > div > div { background: #050f07 !important; border: 1px solid rgba(0,255,106,.18) !important; border-radius: 2px !important; }

/* ── Spinner ── */
.stSpinner > div { border-color: #00ff6a transparent transparent transparent !important; }

/* ── Chat ── */
[data-testid="stChatMessageContent"] {
    background: #050f07 !important; border: 1px solid rgba(0,255,106,.12) !important;
    border-radius: 2px !important; font-family: 'JetBrains Mono', monospace !important;
    font-size: .76rem !important; color: #7dffb0 !important;
}
[data-testid="stChatInput"] textarea {
    background: #050f07 !important; color: #00ff6a !important;
    border: 1px solid rgba(0,255,106,.25) !important; border-radius: 2px !important;
    font-family: 'JetBrains Mono', monospace !important; font-size: .78rem !important;
    transition: border-color .2s, box-shadow .2s !important;
}
[data-testid="stChatInput"] textarea:focus {
    border-color: #00ff6a !important; box-shadow: 0 0 12px rgba(0,255,106,.16) !important;
}

/* ── Scrollbar ── */
::-webkit-scrollbar { width: 4px; height: 4px; }
::-webkit-scrollbar-track { background: #030a04; }
::-webkit-scrollbar-thumb { background: rgba(0,255,106,.25); border-radius: 2px; }
::-webkit-scrollbar-thumb:hover { background: rgba(0,255,106,.5); }

/* ── Animations ── */
@keyframes fadeUp   { from{opacity:0;transform:translateY(10px)} to{opacity:1;transform:translateY(0)} }
@keyframes fadeIn   { from{opacity:0} to{opacity:1} }
@keyframes livePing {
    0%   { box-shadow: 0 0 0 0 rgba(0,255,106,.55); }
    70%  { box-shadow: 0 0 0 6px rgba(0,255,106,0); }
    100% { box-shadow: 0 0 0 0 rgba(0,255,106,0);   }
}
@keyframes headerBar {
    0%,100%{ width:32px; opacity:.9; }
    50%     { width:72px; opacity:.5; }
}

/* ── Reusable classes ── */
.anim-up  { animation: fadeUp  .5s ease both; }
.anim-in  { animation: fadeIn  .6s ease both; }
.d1{animation-delay:.05s}.d2{animation-delay:.1s}.d3{animation-delay:.18s}.d4{animation-delay:.26s}

.live-dot {
    display:inline-block; width:7px; height:7px;
    background:#00ff6a; border-radius:50%;
    margin-right:5px; vertical-align:middle;
    animation: livePing 1.8s ease-in-out infinite;
}

.sec-hdr {
    font-family:'Orbitron',monospace; font-size:.6rem; font-weight:700;
    color:#2a5c3a; letter-spacing:.2em; text-transform:uppercase;
    border-bottom:1px solid rgba(0,255,106,.1); padding-bottom:5px; margin-bottom:12px;
    position:relative;
}
.sec-hdr::after {
    content:''; position:absolute; bottom:-1px; left:0;
    height:1px; background:#00ff6a;
    animation: headerBar 3s ease-in-out infinite;
}

/* ── Responsive ── */
@media(max-width:768px){
    .block-container{padding-left:.6rem !important;padding-right:.6rem !important;}
    [data-testid="stMetricValue"]{font-size:1.05rem !important;}
    section[data-testid="stSidebar"]{width:180px !important;min-width:180px !important;}
}
</style>
""", unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════════════════════
#  CANVAS — ligero: grid + partículas reducidas + sweep, sin blobs
#  throttled a 30 fps para no saturar la CPU
# ══════════════════════════════════════════════════════════════════════════════

st.markdown("""
<canvas id="soc-bg" style="
    position:fixed;top:0;left:0;
    width:100vw;height:100vh;
    z-index:0;pointer-events:none;opacity:.45;
"></canvas>
<script>
(function(){
'use strict';
const cv  = document.getElementById('soc-bg');
if(!cv) return;
const cx  = cv.getContext('2d');
let W, H;

function resize(){
    W = cv.width  = window.innerWidth;
    H = cv.height = window.innerHeight;
}
resize();
window.addEventListener('resize', resize);

/* ── grid ── */
const CELL = 64;
function drawGrid(){
    cx.strokeStyle = 'rgba(0,255,106,.035)';
    cx.lineWidth   = .5;
    for(let x=0;x<W;x+=CELL){cx.beginPath();cx.moveTo(x,0);cx.lineTo(x,H);cx.stroke();}
    for(let y=0;y<H;y+=CELL){cx.beginPath();cx.moveTo(0,y);cx.lineTo(W,y);cx.stroke();}
}

/* ── sweep line ── */
let sweepY = 0;
function drawSweep(){
    sweepY = (sweepY + .8) % H;
    const g = cx.createLinearGradient(0, sweepY-36, 0, sweepY+4);
    g.addColorStop(0,'rgba(0,255,106,0)');
    g.addColorStop(1,'rgba(0,255,106,.055)');
    cx.fillStyle = g;
    cx.fillRect(0, sweepY-36, W, 40);
    cx.strokeStyle = 'rgba(0,255,106,.14)';
    cx.lineWidth   = .8;
    cx.beginPath(); cx.moveTo(0,sweepY); cx.lineTo(W,sweepY); cx.stroke();
}

/* ── particles (reduced count) ── */
const N  = 28;
const pts = Array.from({length:N}, ()=>({
    x:  Math.random()*1920,
    y:  Math.random()*1080,
    vx: (Math.random()-.5)*.28,
    vy: (Math.random()-.5)*.28,
    r:  Math.random()*1.4+.4,
    a:  Math.random()*.5+.15,
    ph: Math.random()*Math.PI*2,
    fs: Math.random()*.04+.01,
}));
const LINK = 110;

function drawParticles(){
    /* links — only check N*(N-1)/2 = 378 pairs, cheap enough */
    for(let i=0;i<N;i++){
        for(let j=i+1;j<N;j++){
            const dx=pts[i].x-pts[j].x, dy=pts[i].y-pts[j].y;
            const d2=dx*dx+dy*dy;
            if(d2<LINK*LINK){
                const a=.1*(1-Math.sqrt(d2)/LINK);
                cx.strokeStyle=`rgba(0,255,106,${a})`;
                cx.lineWidth=.55;
                cx.beginPath(); cx.moveTo(pts[i].x,pts[i].y); cx.lineTo(pts[j].x,pts[j].y); cx.stroke();
            }
        }
    }
    pts.forEach(p=>{
        p.ph+=p.fs;
        cx.beginPath(); cx.arc(p.x,p.y,p.r,0,Math.PI*2);
        cx.fillStyle=`rgba(0,255,106,${p.a*(.6+.4*Math.sin(p.ph))})`;
        cx.fill();
        p.x+=p.vx; p.y+=p.vy;
        if(p.x<0)p.x=W; if(p.x>W)p.x=0;
        if(p.y<0)p.y=H; if(p.y>H)p.y=0;
    });
}

/* ── corner HUD brackets ── */
function drawBrackets(){
    const s=20,p=18;
    cx.strokeStyle='rgba(0,255,106,.22)'; cx.lineWidth=1.2;
    [[p,p,1,1],[W-p,p,-1,1],[p,H-p,1,-1],[W-p,H-p,-1,-1]].forEach(([x,y,sx,sy])=>{
        cx.beginPath();
        cx.moveTo(x+sx*s,y); cx.lineTo(x,y); cx.lineTo(x,y+sy*s);
        cx.stroke();
    });
}

/* ── throttled loop at ~30 fps ── */
let last = 0;
function frame(ts){
    if(ts - last >= 33){   /* ~30 fps */
        last = ts;
        cx.clearRect(0,0,W,H);
        drawGrid();
        drawSweep();
        drawParticles();
        drawBrackets();
    }
    requestAnimationFrame(frame);
}
requestAnimationFrame(frame);
})();
</script>
""", unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════════════════════
#  HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def load_json(n):
    p = os.path.join("shared_data", f"ag{n}.json")
    try:
        with open(p) as f: return json.load(f)
    except: return None

def risk_icon(lvl):
    return {"alto":"⬤","medio":"◆","bajo":"▲","critico":"✕"}.get((lvl or "").lower(),"·")

def asset_row(a):
    lvl = (a.get("riesgo") or "").lower()
    c   = {"alto":"#ff6464","medio":"#ffcc44","bajo":"#00ff6a"}.get(lvl,"#4dcc7a")
    return (
        f'<div style="display:flex;gap:9px;padding:8px 10px;margin-bottom:5px;'
        f'border:1px solid {c}18;border-left:3px solid {c};background:#030a04;'
        f'transition:background .18s;" '
        f'onmouseover="this.style.background=\'#071509\'" '
        f'onmouseout="this.style.background=\'#030a04\'">'
        f'<span style="color:{c};font-size:.66rem;margin-top:2px;flex-shrink:0;">{risk_icon(lvl)}</span>'
        f'<div>'
        f'<div style="font-family:JetBrains Mono,monospace;color:{c};font-size:.72rem;font-weight:500;">'
        f'{a.get("nombre","")}</div>'
        f'<div style="font-family:JetBrains Mono,monospace;color:#4dcc7a;font-size:.64rem;'
        f'margin-top:1px;opacity:.85;">{a.get("razon","")}</div>'
        f'</div></div>'
    )

def ioc_row(ioc):
    rep  = ioc.get("reputacion","")
    c    = "#ff6464" if rep=="malicioso" else "#ffcc44" if rep=="sospechoso" else "#00ff6a"
    lbl  = rep.upper() if rep else "UNKNOWN"
    return (
        f'<div style="display:flex;align-items:center;justify-content:space-between;'
        f'padding:7px 10px;margin-bottom:5px;'
        f'border:1px solid {c}18;border-left:3px solid {c};background:#030a04;'
        f'transition:background .18s;" '
        f'onmouseover="this.style.background=\'#071509\'" '
        f'onmouseout="this.style.background=\'#030a04\'">'
        f'<span style="font-family:JetBrains Mono,monospace;color:#7dffb0;font-size:.7rem;">'
        f'{ioc.get("ip","")}</span>'
        f'<div style="text-align:right;">'
        f'<span style="font-family:Orbitron,monospace;color:{c};font-size:.58rem;">{lbl}</span><br>'
        f'<span style="font-family:JetBrains Mono,monospace;color:#4dcc7a;font-size:.6rem;">'
        f'SCORE: {ioc.get("abuse_score","?")}/100</span>'
        f'</div></div>'
    )

# ══════════════════════════════════════════════════════════════════════════════
#  DATOS
# ══════════════════════════════════════════════════════════════════════════════

ag = {i: load_json(i) for i in range(1, 12)}

# métricas
activos_list = (ag[3] or {}).get("activos_criticos", [])
altos = sum(1 for a in activos_list if a.get("riesgo") == "alto")
riesgo = "ALTO" if altos >= 2 else ("MEDIO" if altos == 1 else "BAJO")

if ag[2] and ag[3]:
    svc = len(ag[2].get("services", []))
    score = min(100,
        svc * 5 + altos * 15 +
        (20 if svc > 5 else 0) +
        (10 if any("ssh" in str(s).lower() for s in ag[2].get("services",[])) else 0)
    )
    nivel = riesgo
else:
    score, nivel = "—", "—"

agentes_ok = sum(1 for i in range(1,12) if ag[i])
target      = (ag[1] or ag[2] or {}).get("target", "sin_objetivo")

# ══════════════════════════════════════════════════════════════════════════════
#  SIDEBAR
# ══════════════════════════════════════════════════════════════════════════════

AGENT_LABELS = {
    1:"DISCOVERY", 2:"NETWORK",  3:"SURFACE",  4:"WEB-BASIC",
    5:"WEB-ADV",   6:"OWASP",    7:"CVE",       8:"THREAT",
    9:"LATERAL",   10:"COMPLY",  11:"REPORT"
}
NAV = [
    ("OVERVIEW",     "Métricas / Agentes 1-3"),
    ("NETWORK",      "Agente 2 — Integrante 1"),
    ("WEB / OWASP",  "Agentes 4-6 — Int. 2/3"),
    ("CVE INTEL",    "Agente 7 — Integrante 2"),
    ("THREAT INTEL", "Agente 8 — Integrante 3"),
    ("COMPLIANCE",   "Agente 10 — Integrante 3"),
    ("SOC CHAT",     "Agente 12 — Integrante 4"),
]

with st.sidebar:
    # ── logo
    st.markdown(f"""
    <div style="padding:1.1rem 1rem .8rem;border-bottom:1px solid rgba(0,255,106,.1);">
        <div style="font-family:Orbitron,monospace;font-size:.95rem;font-weight:900;
                    color:#00ff6a;letter-spacing:.1em;
                    text-shadow:0 0 12px rgba(0,255,106,.45);">▶ SECDASH</div>
        <div style="font-family:JetBrains Mono,monospace;font-size:.55rem;
                    color:#265c36;letter-spacing:.18em;margin-top:3px;">AI SOC PLATFORM</div>
    </div>""", unsafe_allow_html=True)

    # ── status
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

    # ── target
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

    # ── nav
    st.markdown('<div style="padding:.6rem 1rem .2rem;">'
                '<div style="font-family:JetBrains Mono,monospace;font-size:.55rem;'
                'color:#265c36;letter-spacing:.16em;">NAVIGATION</div></div>',
                unsafe_allow_html=True)
    for label, hint in NAV:
        st.markdown(f"""
        <div style="padding:5px 1rem;border-left:2px solid transparent;cursor:default;
                    transition:border-color .2s,background .2s;"
             onmouseover="this.style.borderLeftColor='rgba(0,255,106,.35)';this.style.background='#071509';"
             onmouseout="this.style.borderLeftColor='transparent';this.style.background='transparent';">
            <div style="font-family:Orbitron,monospace;font-size:.58rem;
                        font-weight:700;color:#4dcc7a;letter-spacing:.07em;">{label}</div>
            <div style="font-family:JetBrains Mono,monospace;font-size:.53rem;
                        color:#265c36;margin-top:1px;">{hint}</div>
        </div>""", unsafe_allow_html=True)

    # ── agent checklist
    st.markdown('<div style="padding:.7rem 1rem .2rem;border-top:1px solid rgba(0,255,106,.08);">'
                '<div style="font-family:JetBrains Mono,monospace;font-size:.55rem;'
                'color:#265c36;letter-spacing:.16em;margin-bottom:5px;">AGENT STATUS</div>',
                unsafe_allow_html=True)
    for i in range(1, 12):
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

# ══════════════════════════════════════════════════════════════════════════════
#  HEADER PRINCIPAL
# ══════════════════════════════════════════════════════════════════════════════

st.markdown(f"""
<div class="anim-up" style="
    border:1px solid rgba(0,255,106,.2);
    border-top:2px solid #00ff6a;
    background:linear-gradient(135deg,#030e05,#040d06 70%,#050f07);
    padding:1rem 1.3rem;margin-bottom:1.1rem;
    position:relative;overflow:hidden;
">
    <!-- grid lines decorativo -->
    <div style="position:absolute;inset:0;
        background:repeating-linear-gradient(90deg,
            transparent,transparent 63px,
            rgba(0,255,106,.01) 63px,rgba(0,255,106,.01) 64px);
        pointer-events:none;"></div>

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

<script>
(function tick(){{
    const el=document.getElementById('soc-clock');
    if(el){{const n=new Date();
        el.textContent=[n.getUTCHours(),n.getUTCMinutes(),n.getUTCSeconds()]
            .map(v=>String(v).padStart(2,'0')).join(':') + ' UTC';
    }}
    setTimeout(tick,1000);
}})();
</script>
""", unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════════════════════
#  TARGET ACQUISITION
# ══════════════════════════════════════════════════════════════════════════════

st.markdown('<div class="sec-hdr anim-up d1">// TARGET ACQUISITION</div>', unsafe_allow_html=True)

col_inp, col_btn = st.columns([4, 1])
with col_inp:
    target_input = st.text_input("DOMAIN / IP", value="scanme.nmap.org",
                                  placeholder="example.com or 192.168.1.1")
with col_btn:
    st.markdown("<br>", unsafe_allow_html=True)
    run_btn = st.button("▶ EXECUTE AGENTS 1–3")

if run_btn:
    try:
        bar = st.progress(0)
        steps = [
            ("[ AG1 ] Asset discovery...",    ["python","integrante1/agent1_discovery.py", target_input], 33),
            ("[ AG2 ] Network scan...",        ["python","integrante1/agent2_network.py"],                 66),
            ("[ AG3 ] Attack surface...",      ["python","integrante1/agent3_surface.py"],                100),
        ]
        for msg, cmd, pct in steps:
            with st.spinner(msg):
                subprocess.run(cmd, check=True)
            bar.progress(pct)
        st.success("✓ ALL AGENTS COMPLETED — DATA SYNCHRONIZED")
        st.rerun()
    except Exception as e:
        st.error(f"EXECUTION FAILURE: {e}")

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

# ── Raw JSON dumps
st.markdown('<div class="sec-hdr">// RAW AGENT OUTPUT</div>', unsafe_allow_html=True)
c1, c2, c3 = st.columns(3)
for col, n, lbl in [(c1,1,"AG1 :: DISCOVERY"),(c2,2,"AG2 :: NETWORK"),(c3,3,"AG3 :: SURFACE")]:
    with col:
        with st.expander(f"[ {lbl} ]"):
            st.json(ag[n]) if ag[n] else st.info(f"ag{n}.json not found")

st.divider()

# ══════════════════════════════════════════════════════════════════════════════
#  MÉTRICAS
# ══════════════════════════════════════════════════════════════════════════════

st.markdown('<div class="sec-hdr">// THREAT METRICS</div>', unsafe_allow_html=True)
m1, m2, m3, m4 = st.columns(4)
m1.metric("RISK SCORE",   f"{score}/100" if score != "—" else score, nivel if nivel != "—" else None)
m2.metric("CVEs DETECTED", len((ag[7] or {}).get("cves_encontrados", [])))
m3.metric("WEB FINDINGS",  len((ag[4] or {}).get("hallazgos", [])) + len((ag[5] or {}).get("hallazgos", [])))
m4.metric("OPEN PORTS",    len((ag[2] or {}).get("services", [])))

st.divider()

# ══════════════════════════════════════════════════════════════════════════════
#  NETWORK & OWASP
# ══════════════════════════════════════════════════════════════════════════════

cn, co = st.columns(2)
with cn:
    st.markdown('<div class="sec-hdr">// EXPOSED SERVICES</div>', unsafe_allow_html=True)
    svcs = (ag[2] or {}).get("services", [])
    st.dataframe(svcs, use_container_width=True, hide_index=True) if svcs \
        else st.info("PENDING — run agent 2")

with co:
    st.markdown('<div class="sec-hdr">// OWASP TOP 10 HEATMAP</div>', unsafe_allow_html=True)
    hmap = (ag[6] or {}).get("heatmap_owasp", {})
    st.bar_chart(hmap) if hmap \
        else st.info("PENDING — awaiting agent 6 (Integrante 2/3)")

st.divider()

# ══════════════════════════════════════════════════════════════════════════════
#  CVEs & ACTIVOS CRÍTICOS
# ══════════════════════════════════════════════════════════════════════════════

cc, ca = st.columns(2)
with cc:
    st.markdown('<div class="sec-hdr">// CVE INTELLIGENCE</div>', unsafe_allow_html=True)
    cves = (ag[7] or {}).get("cves_encontrados", [])
    st.dataframe(cves, use_container_width=True, hide_index=True) if cves \
        else st.info("PENDING — awaiting agent 7 (Integrante 2)")

with ca:
    st.markdown('<div class="sec-hdr">// CRITICAL ASSETS</div>', unsafe_allow_html=True)
    if activos_list:
        st.markdown("".join(asset_row(a) for a in activos_list), unsafe_allow_html=True)
    else:
        st.info("PENDING — run agent 3")

# recomendación prioritaria
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

# ══════════════════════════════════════════════════════════════════════════════
#  COMPLIANCE & THREAT INTEL
# ══════════════════════════════════════════════════════════════════════════════

cmp, thr = st.columns(2)
with cmp:
    st.markdown('<div class="sec-hdr">// COMPLIANCE STATUS</div>', unsafe_allow_html=True)
    checks  = (ag[10] or {}).get("compliance_checks", [])
    res10   = (ag[10] or {}).get("resumen", {})
    if checks:
        if res10:
            r1,r2,r3 = st.columns(3)
            r1.metric("TOTAL",  res10.get("total","—"))
            r2.metric("✓ PASS", res10.get("cumple","—"))
            r3.metric("✕ FAIL", res10.get("falla","—"))
        st.dataframe(checks, use_container_width=True, hide_index=True)
    else:
        st.info("PENDING — awaiting agent 10 (Integrante 3)")

with thr:
    st.markdown('<div class="sec-hdr">// THREAT INTELLIGENCE IOCs</div>', unsafe_allow_html=True)
    iocs = (ag[8] or {}).get("iocs", [])
    if iocs:
        st.markdown("".join(ioc_row(i) for i in iocs), unsafe_allow_html=True)
    else:
        st.info("PENDING — awaiting agent 8 (Integrante 3)")

st.divider()

# ══════════════════════════════════════════════════════════════════════════════
#  SOC ASSISTANT
# ══════════════════════════════════════════════════════════════════════════════

st.markdown('<div class="sec-hdr">// SOC ASSISTANT — AI CHAT INTERFACE</div>', unsafe_allow_html=True)
st.markdown(
    '<div style="font-family:JetBrains Mono,monospace;font-size:.64rem;color:#265c36;'
    'margin-bottom:.8rem;">'
    '[ AG12 ] Query the assistant for threat analysis and recommendations<br>'
    '<span style="color:#1a3320;">→ TODO (Integrante 4): reemplazar respuesta con Ollama / Claude API</span>'
    '</div>', unsafe_allow_html=True)

if "messages" not in st.session_state:
    st.session_state.messages = []

for msg in st.session_state.messages:
    with st.chat_message(msg["role"]):
        st.write(msg["content"])

if prompt := st.chat_input("QUERY >"):
    st.session_state.messages.append({"role":"user","content":prompt})
    with st.chat_message("user"): st.write(prompt)

    ctx = {f"ag{i}": ag[i] for i in range(1,12) if ag[i]}
    # ── TODO (Integrante 4): reemplazar este bloque con tu llamada a Ollama/Claude ──
    resp = (f"[ AGENT 12 — PENDING: Integrante 4 ]\n\n"
            f"Context available: {list(ctx.keys())}\n"
            f"→ Replace with: ollama.chat() or anthropic.messages.create()")
    st.session_state.messages.append({"role":"assistant","content":resp})
    with st.chat_message("assistant"): st.write(resp)

# ══════════════════════════════════════════════════════════════════════════════
#  FOOTER
# ══════════════════════════════════════════════════════════════════════════════

st.divider()
st.markdown(
    f'<div style="display:flex;justify-content:space-between;flex-wrap:wrap;gap:.4rem;'
    f'font-family:JetBrains Mono,monospace;font-size:.58rem;color:#1a3320;">'
    f'<span>SECDASH AI SOC — CURSO DE SEGURIDAD EN COMPUTACIÓN</span>'
    f'<span>AGENTS: {agentes_ok}/11 · TARGET: {target}</span>'
    f'</div>', unsafe_allow_html=True)