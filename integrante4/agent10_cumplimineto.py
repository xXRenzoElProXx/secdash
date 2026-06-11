import streamlit as st
import json
import re
from openai import OpenAI
ai = OpenAI(base_url="http://localhost:11434/v1", api_key="ollama")
AI_MODEL = "qwen-lite" 

if 'resultado_analisis' not in st.session_state:
    st.session_state.resultado_analisis = None

def analizar_cumplimiento(datos):
    prompt = f"""Eres un consultor de ciberseguridad senior.
    Analiza la siguiente configuración o logs.
    Devuelve un JSON estrictamente con esta estructura:
    {{
      "estado_cumplimiento": "aprobado|advertencia|critico",
      "normativa_evaluada": "OWASP Top 10",
      "hallazgos": ["Hallazgo detallado 1", "Hallazgo detallado 2"],
      "recomendaciones": ["Recomendación técnica 1", "Recomendación técnica 2"],
      "explicacion_resumida": "Una breve explicación sencilla para cualquier persona sobre por qué esto es peligroso."
    }}
    Datos: {datos}
    Responde SOLO con el JSON, sin texto adicional."""

    try:
        response = ai.chat.completions.create(
            model=AI_MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2,
        )
        raw = response.choices[0].message.content.strip()
        raw = re.sub(r"```json|```", "", raw).strip()
        return json.loads(raw)
    except Exception as e:
        return {
            "estado_cumplimiento": "error",
            "hallazgos": [f"Error técnico: {str(e)}"],
            "recomendaciones": [],
            "explicacion_resumida": "No se pudo procesar la solicitud. Verifica el formato de entrada."
        }

st.set_page_config(page_title="Auditor de Seguridad", page_icon="🛡️")

st.title("🛡️ Auditoría de Cumplimiento")
user_input = st.text_area("Pega aquí los logs o configuración a auditar:", height=150)

if st.button("Analizar en Profundidad"):
    if user_input.strip():
        with st.spinner("El consultor senior está analizando..."):
            # Guardamos el resultado en la memoria de la sesión
            st.session_state.resultado_analisis = analizar_cumplimiento(user_input)
    else:
        st.warning("Ingresa algo para analizar.")

if st.session_state.resultado_analisis is not None:
    res = st.session_state.resultado_analisis
    
    # Colores según el estado
    status = res.get("estado_cumplimiento", "error")
    
    col1, col2 = st.columns([1, 3])
    with col1:
        st.metric("Estado", status.upper())
    with col2:
        st.info(res.get("explicacion_resumida", ""))

    with st.expander("🔍 Ver Hallazgos Técnicos", expanded=True):
        for h in res.get("hallazgos", []):
            st.markdown(f"- ⚠️ {h}")

    with st.expander("✅ Recomendaciones para solucionar"):
        for r in res.get("recomendaciones", []):
            st.markdown(f"- 💡 {r}")

    # Botón de descarga
    st.download_button(
        label="📥 Descargar Reporte Técnico (JSON)",
        data=json.dumps(res, indent=2, ensure_ascii=False),
        file_name="reporte_seguridad.json",
        mime="application/json"
    )