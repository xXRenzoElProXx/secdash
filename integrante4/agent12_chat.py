import streamlit as st
import json
from openai import OpenAI


ai = OpenAI(base_url="http://localhost:11434/v1", api_key="ollama")
AI_MODEL = "qwen-lite"

st.set_page_config(page_title="Agente Mentor", page_icon="💬")
st.title("💬Mentor de Seguridad")
st.markdown("Tu asistente para consultas técnicas y soporte de la Hacker Suite.")

# Inicializar historial de chat
if "messages" not in st.session_state:
    st.session_state.messages = [
        {"role": "assistant", "content": "Hola, soy tu mentor de seguridad. ¿En qué puedo ayudarte hoy?"}
    ]

# Mostrar historial de mensajes
for message in st.session_state.messages:
    with st.chat_message(message["role"]):
        st.markdown(message["content"])

# Input del usuario
if prompt := st.chat_input("Pregúntame sobre vulnerabilidades, herramientas o normativa..."):
    # Añadir mensaje de usuario al historial
    st.session_state.messages.append({"role": "user", "content": prompt})
    with st.chat_message("user"):
        st.markdown(prompt)

    # Respuesta del asistente
    with st.chat_message("assistant"):
        with st.spinner("Pensando..."):
            # Enviar el historial completo a la IA para que tenga contexto
            response = ai.chat.completions.create(
                model=AI_MODEL,
                messages=[
                    {"role": "system", "content": "Eres un mentor de ciberseguridad experto. Ayudas al usuario a entender riesgos, herramientas y normativas (OWASP, etc). Sé conciso y técnico."},
                    *st.session_state.messages
                ]
            )
            full_response = response.choices[0].message.content
            st.markdown(full_response)
    
    # Añadir respuesta al historial
    st.session_state.messages.append({"role": "assistant", "content": full_response})

st.divider()
st.download_button(
    label="📥 Descargar Conversación (JSON)",
    data=json.dumps(st.session_state.messages, indent=2, ensure_ascii=False),
    file_name="historial_chat.json",
    mime="application/json"
)