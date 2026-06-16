import json
import os
import re
from datetime import datetime, UTC
from dotenv import load_dotenv

load_dotenv()

USE_OLLAMA = True

if USE_OLLAMA:
    from openai import OpenAI
    ai = OpenAI(base_url="http://localhost:11434/v1", api_key="ollama")
    AI_MODEL = "minimax-m3:cloud"
else:
    from openai import OpenAI
    ai = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
    AI_MODEL = "gpt-4o-mini"

def leer_json(path, nombre):
    if not os.path.exists(path):
        print(f"   ⚠ No se encontró {nombre}. Usando datos vacíos.")
        return {}
    with open(path) as f:
        return json.load(f)

def analizar_superficie(ag1, ag2):
    contexto = f"""
=== DATOS DE RECONOCIMIENTO (Agente 1) ===
Dominio: {ag1.get('target', 'desconocido')}
IP: {ag1.get('ip', 'desconocida')}
Subdominios: {ag1.get('subdominios', [])}
DNS: {json.dumps(ag1.get('dns', {}), indent=2)}
Análisis previo: {json.dumps(ag1.get('analisis_ia', {}), indent=2)}

=== DATOS DE RED (Agente 2) ===
Puertos y servicios abiertos: {json.dumps(ag2.get('services', []), indent=2)}
OS detectado: {ag2.get('os_detected', 'desconocido')}
Firewall/IDS: {json.dumps(ag2.get('firewall_ids_detection', {}), indent=2)}
SSL/TLS: {json.dumps(ag2.get('ssl_tls_services', []), indent=2)}
Security Issues: {json.dumps(ag2.get('security_issues', []), indent=2)}
"""

    prompt = f"""Eres un analista de seguridad experto en superficie de ataque y bastionado de sistemas.
Analiza estos datos de reconocimiento y red aplicando conceptos de:
- Control de acceso (DAC, MAC, RBAC)
- Principio de mínimo privilegio
- Bastionado (hardening) de sistemas
- Defensa en profundidad
- Post-explotación y movimiento lateral

Devuelve SOLO un JSON válido con esta estructura:

{{
  "activos_criticos": [
    {{
      "nombre": "ssh en puerto 22",
      "tipo": "servicio|subdominio|endpoint",
      "riesgo": "alto|medio|bajo",
      "razon": "versión desactualizada / expuesto a internet / etc"
    }}
  ],
  "control_acceso": {{
    "modelo_detectado": "DAC|RBAC|desconocido",
    "servicios_sin_autenticacion": ["telnet", "ftp"],
    "puertos_administrativos_expuestos": [22, 3389],
    "recomendaciones_acl": ["Restringir SSH solo a IPs internas", "Deshabilitar Telnet"]
  }},
  "hardening_analysis": {{
    "servicios_innecesarios": ["telnet en puerto 23", "ftp en puerto 21"],
    "protocolos_inseguros": ["SSLv3", "TLSv1.0"],
    "falta_segmentacion": true,
    "medidas_sugeridas": [
      "Aplicar DEP/ASLR si es Windows",
      "Configurar iptables/firewall restrictivo",
      "Deshabilitar servicios no críticos"
    ]
  }},
  "post_exploitation_vectors": [
    "SSH con credenciales débiles puede permitir acceso inicial",
    "FTP anónimo puede exponer archivos de configuración",
    "Movimiento lateral posible vía RDP sin segmentación"
  ],
  "prioridad": ["activo más crítico", "segundo más crítico"],
  "vectores_de_ataque": [
    "descripción de posible vector 1",
    "descripción de posible vector 2"
  ],
  "superficie_total": "descripción general de qué tan expuesto está el sistema",
  "recomendacion_inmediata": "la acción más urgente a tomar"
}}

Datos a analizar:
{contexto}

Responde SOLO con el JSON, sin texto adicional ni markdown."""

    response = ai.chat.completions.create(
        model=AI_MODEL,
        messages=[{"role": "user", "content": prompt}],
        temperature=0.3,
    )
    raw = response.choices[0].message.content.strip()
    raw = re.sub(r"```json|```", "", raw).strip()

    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {
            "activos_criticos": [],
            "control_acceso": {
                "modelo_detectado": "desconocido",
                "servicios_sin_autenticacion": [],
                "puertos_administrativos_expuestos": [],
                "recomendaciones_acl": []
            },
            "hardening_analysis": {
                "servicios_innecesarios": [],
                "protocolos_inseguros": [],
                "falta_segmentacion": False,
                "medidas_sugeridas": []
            },
            "post_exploitation_vectors": [],
            "prioridad": [],
            "vectores_de_ataque": [],
            "superficie_total": "No se pudo analizar",
            "recomendacion_inmediata": raw[:300]
        }

def run_agent():
    print(f"\n🎯 Agente 3 — Attack Surface")

    base = os.path.join(os.path.dirname(__file__), "..", "shared_data")

    print("   Leyendo ag1.json y ag2.json...")
    ag1 = leer_json(os.path.join(base, "ag1.json"), "ag1.json")
    ag2 = leer_json(os.path.join(base, "ag2.json"), "ag2.json")

    if not ag1 and not ag2:
        print("   ❌ No hay datos de entrada. Ejecuta primero agent1 y agent2.")
        return {}

    print("   🤖 Analizando superficie de ataque con IA...")
    analisis = analizar_superficie(ag1, ag2)

    resultado = {
        "target": ag1.get("target", ag2.get("target", "desconocido")),
        "ip": ag1.get("ip", ag2.get("ip", "desconocida")),
        "activos_criticos": analisis.get("activos_criticos", []),
        "control_acceso": analisis.get("control_acceso", {}),
        "hardening_analysis": analisis.get("hardening_analysis", {}),
        "post_exploitation_vectors": analisis.get("post_exploitation_vectors", []),
        "prioridad": analisis.get("prioridad", []),
        "vectores_de_ataque": analisis.get("vectores_de_ataque", []),
        "superficie_total": analisis.get("superficie_total", ""),
        "recomendacion_inmediata": analisis.get("recomendacion_inmediata", ""),
        "fuentes": ["ag1.json", "ag2.json"],
        "timestamp": datetime.now(UTC).isoformat()
    }

    output_path = os.path.join(base, "ag3.json")
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(resultado, f, indent=2, ensure_ascii=False)

    print(f"\n   ✅ Listo. Guardado en shared_data/ag3.json")
    print(f"   📊 Resumen:")
    print(f"      Activos críticos: {len(resultado['activos_criticos'])}")
    for a in resultado["activos_criticos"][:3]:
        print(f"        → [{a.get('riesgo','?').upper()}] {a.get('nombre','?')}: {a.get('razon','')}")
    
    ctrl = resultado.get('control_acceso', {})
    if ctrl.get('servicios_sin_autenticacion'):
        print(f"      🔓 Servicios sin auth: {len(ctrl.get('servicios_sin_autenticacion', []))}")
    
    hard = resultado.get('hardening_analysis', {})
    if hard.get('servicios_innecesarios'):
        print(f"      ⚙️ Servicios innecesarios: {len(hard.get('servicios_innecesarios', []))}")
    
    post_exp = resultado.get('post_exploitation_vectors', [])
    if post_exp:
        print(f"      🎯 Vectores post-explotación: {len(post_exp)}")
    
    print(f"      Superficie: {resultado['superficie_total'][:100]}...")
    print(f"      Acción urgente: {resultado['recomendacion_inmediata'][:100]}")

    return resultado

if __name__ == "__main__":
    run_agent()