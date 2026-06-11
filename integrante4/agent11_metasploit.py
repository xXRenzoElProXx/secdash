import streamlit as st
import json
import re
from openai import OpenAI

# ─── Configuración IA ──────────────────────────────────────────────
ai = OpenAI(base_url="http://localhost:11434/v1", api_key="ollama")
AI_MODEL = "qwen-lite" 

# Inicializar memoria persistente
if 'resultado_exploits' not in st.session_state:
    st.session_state.resultado_exploits = None

# ─── Lógica del Agente (Buscador de Metasploit) ────────────────────
def buscar_exploits(cve):
    prompt = f"""Eres un investigador de ciberseguridad experto en Metasploit Framework.
    Tu objetivo es buscar módulos de explotación para el CVE proporcionado.
    Devuelve un JSON estrictamente con esta estructura:
    {{
      "cve": "{cve}",
      "modulo_metasploit": "ruta/al/modulo (o 'No encontrado')",
      "descripcion": "Breve explicación de la vulnerabilidad",
      "rango_explotacion": "remoto/local",
      "comandos": ["use ruta/al/modulo", "set RHOSTS <target>", "exploit"]
    }}
    Si no encuentras un módulo específico de Metasploit, intenta dar alternativas o contexto.
    Responde SOLO con el JSON."""

    try:
        response = ai.chat.completions.create(
            model=AI_MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1,
        )
        raw = response.choices[0].message.content.strip()
        raw = re.sub(r"```json|```", "", raw).strip()
        return json.loads(raw)
    except Exception as e:
        return {
            "cve": cve,
            "modulo_metasploit": "Error",
            "descripcion": f"Error buscando información: {str(e)}",
            "comandos": []
        }

# ─── Interfaz Streamlit ────────────────────────────────────────────
st.set_page_config(page_title="Buscador de Exploits", page_icon="💥")

st.title("💥 Agente 2 — Buscador de Exploits")
cve_input = st.text_input("Ingresa el ID del CVE (ej. CVE-2021-44228):")

if st.button("Buscar en Metasploit"):
    if cve_input.strip():
        with st.spinner("Buscando en la base de datos..."):
            st.session_state.resultado_exploits = buscar_exploits(cve_input)
    else:
        st.warning("Por favor, ingresa un CVE válido.")

# ─── Visualización de resultados ──────────────────────────────────
if st.session_state.resultado_exploits is not None:
    res = st.session_state.resultado_exploits
    
    st.success(f"Resultados para: **{res.get('cve')}**")
    
    col1, col2 = st.columns(2)
    with col1:
        st.subheader("Módulo sugerido")
        st.code(res.get("modulo_metasploit", "N/A"), language="bash")
    with col2:
        st.subheader("Tipo")
        st.write(res.get("rango_explotacion", "N/A"))
        
    st.markdown("### Descripción")
    st.info(res.get("descripcion", ""))
    
    st.subheader("Comandos para Metasploit")
    for cmd in res.get("comandos", []):
        st.code(cmd, language="bash")

    # Botón de descarga
    st.download_button(
        label="📥 Descargar Reporte de Exploit",
        data=json.dumps(res, indent=2, ensure_ascii=False),
        file_name=f"exploit_{res.get('cve')}.json",
        mime="application/json"
    )