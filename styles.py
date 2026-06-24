import streamlit as st
import streamlit.components.v1 as components


CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@700;900&family=JetBrains+Mono:wght@400;500&display=swap');

*, *::before, *::after { box-sizing: border-box; }
html, body, [class*="css"] {
    font-family: 'JetBrains Mono', monospace !important;
    background: #040d06 !important;
    color: #7dffb0 !important;
}
.stApp { background: #040d06 !important; }

.stApp::after {
    content: "";
    position: fixed; inset: 0;
    background: repeating-linear-gradient(
        180deg, transparent 0px, transparent 3px,
        rgba(0,0,0,0.055) 3px, rgba(0,0,0,0.055) 4px
    );
    pointer-events: none;
    z-index: 9000;
}

.block-container {
    padding-top: 0.8rem !important;
    padding-left: 1.4rem !important;
    padding-right: 1.4rem !important;
    max-width: 1440px !important;
}
[data-testid="column"] { padding: 0 0.35rem !important; }
#MainMenu, footer, header { visibility: hidden !important; }

/* ── Sidebar ── */
section[data-testid="stSidebar"],
[data-testid="stSidebar"] {
    transform: none !important;
    margin-left: 0 !important;
    visibility: visible !important;
    display: flex !important;
    min-width: 230px !important;
    width: 230px !important;
    background: #020b04 !important;
    border-right: 1px solid rgba(0,255,106,.13) !important;
}
section[data-testid="stSidebar"] > div { background: transparent !important; padding: 0 !important; }
[data-testid="collapsedControl"],
button[kind="header"],
[aria-label="Close sidebar"],
[aria-label="Collapse sidebar"] { display: none !important; }
[data-testid="stSidebar"][aria-expanded="false"],
[data-testid="stSidebar"][style*="translateX"] {
    transform: translateX(0) !important;
    margin-left: 0 !important;
}

/* ── Fix chat input background ── */
[data-testid="stBottom"],
[data-testid="stBottom"] > div,
[data-testid="stBottomBlockContainer"],
[data-testid="stBottomBlockContainer"] > div {
    background: #040d06 !important;
}
div:has(> [data-testid="stChatInput"]) {
    background: #040d06 !important;
}
.st-emotion-cache-1gulkj5,
.st-emotion-cache-1c7y2kl,
[class*="stChatInputContainer"] {
    background: #040d06 !important;
    border-top: 1px solid rgba(0,255,106,.15) !important;
}

h1,h2,h3 {
    font-family: 'Orbitron', monospace !important;
    color: #00ff6a !important;
    text-shadow: 0 0 16px rgba(0,255,106,.4), 0 0 32px rgba(0,255,106,.12) !important;
    letter-spacing: .08em !important;
}
h1 { font-size: 1.55rem !important; font-weight: 900 !important; }
h2 { font-size: .95rem  !important; font-weight: 700 !important; }
h3 { font-size: .82rem  !important; font-weight: 700 !important; }

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

hr { border: none !important; border-top: 1px solid rgba(0,255,106,.1) !important; margin: 1.2rem 0 !important; }

.streamlit-expanderHeader {
    background: #050f07 !important; border: 1px solid rgba(0,255,106,.12) !important;
    border-radius: 2px !important; color: #7dffb0 !important;
    font-family: 'JetBrains Mono', monospace !important; font-size: .72rem !important;
}
.streamlit-expanderContent {
    background: #030a04 !important; border: 1px solid rgba(0,255,106,.07) !important; border-top: none !important;
}

.stDataFrame { border: 1px solid rgba(0,255,106,.12) !important; border-radius: 2px !important; }
.stDataFrame table { background: #030a04 !important; color: #7dffb0 !important; font-family: 'JetBrains Mono', monospace !important; font-size: .72rem !important; }
.stDataFrame thead th {
    background: #050f07 !important; color: #00ff6a !important;
    font-family: 'Orbitron', monospace !important; font-size: .6rem !important;
    letter-spacing: .07em !important; border-bottom: 1px solid rgba(0,255,106,.25) !important;
}

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

.stProgress > div > div > div {
    background: linear-gradient(90deg, #00ff6a, #4dffaa) !important;
    box-shadow: 0 0 6px rgba(0,255,106,.45) !important;
}
.stProgress > div > div { background: #050f07 !important; border: 1px solid rgba(0,255,106,.18) !important; border-radius: 2px !important; }

.stSpinner > div { border-color: #00ff6a transparent transparent transparent !important; }

[data-testid="stChatMessageContent"] {
    background: #050f07 !important; border: 1px solid rgba(0,255,106,.12) !important;
    border-radius: 2px !important; font-family: 'JetBrains Mono', monospace !important;
    font-size: .76rem !important; color: #7dffb0 !important;
}
[data-testid="stChatInput"] textarea {
    background: #050f07 !important; color: #00ff6a !important;
    border: 1px solid rgba(0,255,106,.25) !important; border-radius: 2px !important;
    font-family: 'JetBrains Mono', monospace !important; font-size: .78rem !important;
}
[data-testid="stChatInput"] textarea:focus {
    border-color: #00ff6a !important; box-shadow: 0 0 12px rgba(0,255,106,.16) !important;
}

::-webkit-scrollbar { width: 4px; height: 4px; }
::-webkit-scrollbar-track { background: #030a04; }
::-webkit-scrollbar-thumb { background: rgba(0,255,106,.25); border-radius: 2px; }
::-webkit-scrollbar-thumb:hover { background: rgba(0,255,106,.5); }

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

/* ── Chat Panel Lateral ── */
#chat-panel-overlay {
    position: fixed;
    top: 0; right: 0; bottom: 0; left: 0;
    background: rgba(4,13,6,0.92);
    backdrop-filter: blur(3px);
    z-index: 10000;
    opacity: 0;
    visibility: hidden;
    transition: opacity 0.35s ease, visibility 0.35s ease;
}
#chat-panel-overlay.active {
    opacity: 1;
    visibility: visible;
}
#chat-panel {
    position: fixed;
    top: 0; right: -480px; bottom: 0;
    width: 480px; max-width: 85vw;
    background: #020b04;
    border-left: 2px solid #00ff6a;
    box-shadow: -8px 0 32px rgba(0,255,106,0.25);
    z-index: 10001;
    display: flex; flex-direction: column;
    transition: right 0.4s cubic-bezier(0.4, 0, 0.2, 1);
    overflow: hidden;
}
#chat-panel.active {
    right: 0;
}
.chat-panel-header {
    background: linear-gradient(135deg, #030e05, #040d06);
    border-bottom: 1px solid rgba(0,255,106,0.2);
    padding: 1.2rem 1.5rem;
    flex-shrink: 0;
}
.chat-panel-title {
    font-family: 'Orbitron', monospace;
    font-size: 1.1rem; font-weight: 900;
    color: #00ff6a; letter-spacing: 0.12em;
    text-shadow: 0 0 16px rgba(0,255,106,0.5);
    display: flex; align-items: center; gap: 0.6rem;
}
.chat-panel-subtitle {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.62rem; color: #4dcc7a;
    letter-spacing: 0.1em; margin-top: 0.4rem;
}
.chat-panel-close {
    position: absolute; top: 1.2rem; right: 1.5rem;
    background: transparent; border: 1px solid rgba(0,255,106,0.3);
    color: #00ff6a; font-family: 'Orbitron', monospace;
    font-size: 0.7rem; font-weight: 700; padding: 0.35rem 0.8rem;
    cursor: pointer; letter-spacing: 0.08em;
    transition: all 0.2s ease;
    border-radius: 2px;
}
.chat-panel-close:hover {
    background: rgba(0,255,106,0.1);
    box-shadow: 0 0 16px rgba(0,255,106,0.3);
}
.chat-panel-body {
    flex: 1; overflow-y: auto; overflow-x: hidden;
    padding: 1rem 1.5rem;
    background: #040d06;
}
.chat-panel-body::-webkit-scrollbar { width: 6px; }
.chat-panel-body::-webkit-scrollbar-track { background: #030a04; }
.chat-panel-body::-webkit-scrollbar-thumb { 
    background: rgba(0,255,106,0.3); border-radius: 3px; 
}
.chat-panel-body::-webkit-scrollbar-thumb:hover { 
    background: rgba(0,255,106,0.5); 
}
.chat-panel-footer {
    border-top: 1px solid rgba(0,255,106,0.15);
    background: #030a04;
    padding: 1rem 1.5rem;
    flex-shrink: 0;
}
.chat-toggle-btn {
    position: fixed; bottom: 2rem; right: 2rem;
    width: 64px; height: 64px;
    background: linear-gradient(135deg, #00ff6a, #00cc55);
    border: 2px solid #00ff6a; border-radius: 50%;
    box-shadow: 0 4px 24px rgba(0,255,106,0.45), 0 0 12px rgba(0,255,106,0.3);
    cursor: pointer; z-index: 9999;
    display: flex; align-items: center; justify-content: center;
    font-size: 1.8rem; color: #020b04;
    transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
    animation: chatPulse 2.5s ease-in-out infinite;
}
.chat-toggle-btn:hover {
    transform: scale(1.1); box-shadow: 0 6px 32px rgba(0,255,106,0.6);
}
.chat-toggle-btn:active {
    transform: scale(0.95);
}
.chat-toggle-btn.active {
    background: linear-gradient(135deg, #ff6464, #ff3333);
    border-color: #ff6464;
    box-shadow: 0 4px 24px rgba(255,100,100,0.45);
}
.chat-badge {
    position: absolute; top: -4px; right: -4px;
    background: #ff3333; color: white;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.65rem; font-weight: 700;
    padding: 0.15rem 0.4rem; border-radius: 10px;
    border: 2px solid #020b04;
    box-shadow: 0 2px 8px rgba(255,51,51,0.5);
}
@keyframes chatPulse {
    0%, 100% { box-shadow: 0 4px 24px rgba(0,255,106,0.45), 0 0 12px rgba(0,255,106,0.3); }
    50% { box-shadow: 0 4px 32px rgba(0,255,106,0.65), 0 0 20px rgba(0,255,106,0.5); }
}

@media(max-width:768px){
    .block-container{padding-left:.6rem !important;padding-right:.6rem !important;}
    [data-testid="stMetricValue"]{font-size:1.05rem !important;}
    section[data-testid="stSidebar"]{width:180px !important;min-width:180px !important;}
    #chat-panel { width: 100%; max-width: 100vw; right: -100%; }
    .chat-toggle-btn { bottom: 1.5rem; right: 1.5rem; width: 56px; height: 56px; font-size: 1.5rem; }
}
</style>
"""

CANVAS_HTML = """
<!DOCTYPE html>
<html>
<head>
<style>
  * { margin:0; padding:0; }
  body { background: transparent; overflow: hidden; }
  canvas {
    position: fixed; top: 0; left: 0;
    width: 100vw; height: 100vh;
    pointer-events: none; opacity: .45;
  }
</style>
</head>
<body>
<canvas id="bg"></canvas>
<script>
(function(){
  const cv = document.getElementById('bg');
  const cx = cv.getContext('2d');
  let W = 0, H = 0;

  function resize(){
    W = cv.width  = window.innerWidth  || 1280;
    H = cv.height = window.innerHeight || 800;
  }
  resize();
  window.addEventListener('resize', resize);

  const CELL = 64;
  function drawGrid(){
    cx.strokeStyle = 'rgba(0,255,106,.035)';
    cx.lineWidth = .5;
    for(let x=0;x<W;x+=CELL){cx.beginPath();cx.moveTo(x,0);cx.lineTo(x,H);cx.stroke();}
    for(let y=0;y<H;y+=CELL){cx.beginPath();cx.moveTo(0,y);cx.lineTo(W,y);cx.stroke();}
  }

  let sweepY = 0;
  function drawSweep(){
    if(!W||!H||!isFinite(sweepY)) return;
    sweepY = (sweepY + .8) % H;
    const y1 = sweepY - 36, y2 = sweepY + 4;
    if(!isFinite(y1)||!isFinite(y2)) return;
    const g = cx.createLinearGradient(0, y1, 0, y2);
    g.addColorStop(0,'rgba(0,255,106,0)');
    g.addColorStop(1,'rgba(0,255,106,.055)');
    cx.fillStyle = g;
    cx.fillRect(0, y1, W, 40);
    cx.strokeStyle = 'rgba(0,255,106,.14)';
    cx.lineWidth = .8;
    cx.beginPath(); cx.moveTo(0,sweepY); cx.lineTo(W,sweepY); cx.stroke();
  }

  const N = 22;
  const pts = Array.from({length:N}, ()=>({
    x: Math.random()*1280, y: Math.random()*800,
    vx:(Math.random()-.5)*.28, vy:(Math.random()-.5)*.28,
    r: Math.random()*1.4+.4, a: Math.random()*.5+.15,
    ph:Math.random()*Math.PI*2, fs:Math.random()*.04+.01,
  }));
  const LINK = 110;

  function drawParticles(){
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

  function drawBrackets(){
    const s=20,p=18;
    cx.strokeStyle='rgba(0,255,106,.22)'; cx.lineWidth=1.2;
    [[p,p,1,1],[W-p,p,-1,1],[p,H-p,1,-1],[W-p,H-p,-1,-1]].forEach(([x,y,sx,sy])=>{
      cx.beginPath();
      cx.moveTo(x+sx*s,y); cx.lineTo(x,y); cx.lineTo(x,y+sy*s);
      cx.stroke();
    });
  }

  let last = 0;
  function frame(ts){
    if(ts - last >= 33){
      last = ts;
      if(W && H){
        cx.clearRect(0,0,W,H);
        drawGrid(); drawSweep(); drawParticles(); drawBrackets();
      }
    }
    requestAnimationFrame(frame);
  }
  requestAnimationFrame(frame);
})();
</script>
</body>
</html>
"""

CLOCK_JS = """
<script>
(function tick(){
    try {
        const el = window.parent.document.getElementById('soc-clock');
        if(el){
            const n = new Date();
            el.textContent = [n.getUTCHours(),n.getUTCMinutes(),n.getUTCSeconds()]
                .map(v=>String(v).padStart(2,'0')).join(':') + ' UTC';
        }
    } catch(e){}
    setTimeout(tick, 1000);
})();
</script>
"""


def inject_styles():
    """Inyecta el CSS global de SecDash en la app Streamlit."""
    st.markdown(CSS, unsafe_allow_html=True)


def inject_canvas():
    """Renderiza el canvas animado de fondo (grid + sweep + partículas)."""
    st.components.v1.html(CANVAS_HTML, height=1, scrolling=False)


def inject_clock():
    """Inyecta el script JS que actualiza el reloj UTC en el header."""
    st.components.v1.html(CLOCK_JS, height=0, scrolling=False)


def inject_chat_panel():
    """Inyecta el botón flotante y panel lateral para el chatbot."""
    CHAT_PANEL_HTML = """
    <div id="chat-toggle-btn" class="chat-toggle-btn" onclick="toggleChat()">
        💬
        <span id="chat-badge" class="chat-badge" style="display:none;">0</span>
    </div>
    
    <div id="chat-panel-overlay" onclick="closeChat()"></div>
    
    <div id="chat-panel">
        <div class="chat-panel-header">
            <div class="chat-panel-title">
                🤖 SECURITY ASSISTANT
            </div>
            <div class="chat-panel-subtitle">
                [ AG12 ] minimax-m3:cloud | Bilingüe: EN/ES
            </div>
            <button class="chat-panel-close" onclick="closeChat()">✕ CLOSE</button>
        </div>
        <div id="chat-panel-body" class="chat-panel-body">
            <div style="text-align:center; padding:2rem 1rem; color:#4dcc7a; font-family:'JetBrains Mono',monospace; font-size:0.7rem;">
                <div style="font-size:2.5rem; margin-bottom:0.5rem;">🤖</div>
                <div style="color:#00ff6a; font-family:'Orbitron',monospace; font-size:0.85rem; font-weight:700; margin-bottom:0.5rem;">
                    AGENT 12 READY
                </div>
                <div style="line-height:1.6;">
                    El chatbot se cargará aquí.<br>
                    Scroll hacia abajo en el dashboard<br>
                    para ver la sección completa del chat.
                </div>
            </div>
        </div>
    </div>
    
    <script>
    function toggleChat() {
        const panel = window.parent.document.getElementById('chat-panel');
        const overlay = window.parent.document.getElementById('chat-panel-overlay');
        const btn = window.parent.document.getElementById('chat-toggle-btn');
        
        if (panel && overlay && btn) {
            const isActive = panel.classList.contains('active');
            
            if (isActive) {
                closeChat();
            } else {
                panel.classList.add('active');
                overlay.classList.add('active');
                btn.classList.add('active');
                
                // Scroll al chat en el dashboard
                setTimeout(() => {
                    const chatSection = window.parent.document.querySelector('[data-testid="stChatInput"]');
                    if (chatSection) {
                        chatSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
                    }
                }, 400);
            }
        }
    }
    
    function closeChat() {
        const panel = window.parent.document.getElementById('chat-panel');
        const overlay = window.parent.document.getElementById('chat-panel-overlay');
        const btn = window.parent.document.getElementById('chat-toggle-btn');
        
        if (panel && overlay && btn) {
            panel.classList.remove('active');
            overlay.classList.remove('active');
            btn.classList.remove('active');
        }
    }
    
    // Detectar mensajes nuevos y actualizar badge
    function updateChatBadge() {
        try {
            const chatMessages = window.parent.document.querySelectorAll('[data-testid="stChatMessage"]');
            const badge = window.parent.document.getElementById('chat-badge');
            if (badge && chatMessages.length > 0) {
                // Mostrar número de mensajes
                badge.textContent = chatMessages.length;
                badge.style.display = 'block';
            }
        } catch(e) {}
    }
    
    // Actualizar badge cada 2 segundos
    setInterval(updateChatBadge, 2000);
    updateChatBadge();
    
    // Cerrar con tecla ESC
    window.parent.document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape') {
            closeChat();
        }
    });
    </script>
    """
    st.components.v1.html(CHAT_PANEL_HTML, height=0, scrolling=False)