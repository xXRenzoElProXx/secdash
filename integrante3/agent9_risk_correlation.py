import json
import os
from datetime import datetime, UTC

from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()

USE_OLLAMA = True
AI_MODEL = "gpt-oss:20b-cloud"  # Integrante 3

if USE_OLLAMA:
    ai = OpenAI(base_url="http://localhost:11434/v1", api_key="ollama")
else:
    ai = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

def root_path():
    return os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

def shared_path(filename):
    return os.path.join(root_path(), "shared_data", filename)

def leer_json(path, default=None):
    if default is None:
        default = {}

    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return default
    except json.JSONDecodeError:
        print(f"⚠ El archivo {path} no tiene JSON válido")
        return default

def guardar_json(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)

    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def normalizar_severidad(valor):
    return str(valor or "").strip().lower()

def puntos_por_severidad(sev):
    sev = normalizar_severidad(sev)

    if sev in ["critical", "critico", "crítico"]:
        return 20
    if sev in ["high", "alto", "alta"]:
        return 12
    if sev in ["medium", "medio", "media"]:
        return 7
    if sev in ["low", "bajo", "baja"]:
        return 3

    return 5

def calcular_riesgo_red(ag2):
    services = ag2.get("services", [])
    puntos = 0
    factores = []

    # Cada puerto abierto suma riesgo moderado.
    puntos += min(len(services) * 5, 20)

    servicios_sensibles = ["ssh", "ftp", "telnet", "smb", "rdp", "mysql", "postgres", "mongodb"]

    for s in services:
        nombre = str(s.get("service", "")).lower()
        version = str(s.get("version", "")).lower()
        port = s.get("port", "")

        texto = f"{nombre} {version}"

        for sensible in servicios_sensibles:
            if sensible in texto:
                puntos += 5
                factores.append(f"Servicio sensible expuesto: {nombre} en puerto {port}")
                break

    return min(puntos, 25), factores

def obtener_hallazgos_web(ag4, ag5):
    hallazgos = []

    if isinstance(ag4.get("hallazgos"), list):
        hallazgos.extend(ag4.get("hallazgos", []))

    if isinstance(ag5.get("hallazgos"), list):
        hallazgos.extend(ag5.get("hallazgos", []))

    return hallazgos

def calcular_riesgo_web(ag4, ag5, ag6):
    hallazgos = obtener_hallazgos_web(ag4, ag5)
    puntos = 0
    factores = []

    for h in hallazgos:
        sev = h.get("severidad") or h.get("severity") or h.get("riesgo") or "medium"
        puntos += puntos_por_severidad(sev)

        if puntos_por_severidad(sev) >= 12:
            nombre = h.get("titulo") or h.get("nombre") or h.get("template") or "hallazgo web"
            factores.append(f"Hallazgo web relevante: {nombre}")

    heatmap = ag6.get("heatmap_owasp", {})
    puntos_owasp = 0

    if isinstance(heatmap, dict):
        try:
            puntos_owasp = min(sum(int(v) for v in heatmap.values()) * 2, 10)
        except Exception:
            puntos_owasp = 0

    puntos += puntos_owasp

    return min(puntos, 30), factores

def calcular_riesgo_cves(ag7):
    cves = ag7.get("cves_encontrados", [])
    puntos = 0
    factores = []

    for cve in cves:
        sev = cve.get("severidad", "")
        score = cve.get("cvss_score", 0)

        try:
            score_float = float(score)
        except Exception:
            score_float = 0

        if score_float >= 9:
            puntos += 20
        elif score_float >= 7:
            puntos += 12
        elif score_float >= 4:
            puntos += 7
        elif score_float > 0:
            puntos += 3
        else:
            puntos += puntos_por_severidad(sev)

        if score_float >= 7 or normalizar_severidad(sev) in ["high", "alto", "critical", "critico", "crítico"]:
            cve_id = cve.get("cve_id", "CVE sin ID")
            software = cve.get("software", "software no especificado")
            factores.append(f"CVE relevante detectada: {cve_id} en {software}")

    return min(puntos, 35), factores

def calcular_riesgo_threat_intel(ag8):
    iocs = ag8.get("iocs", [])
    puntos = 0
    factores = []

    for ioc in iocs:
        reputacion = str(ioc.get("reputacion", "")).lower()

        try:
            abuse_score = int(ioc.get("abuse_score", 0))
        except Exception:
            abuse_score = 0

        puntos += int(abuse_score * 0.25)

        if reputacion == "malicioso":
            puntos += 15
            factores.append(f"IOC malicioso detectado: {ioc.get('ip', 'IP desconocida')}")
        elif reputacion == "sospechoso":
            puntos += 8
            factores.append(f"IOC sospechoso detectado: {ioc.get('ip', 'IP desconocida')}")

    return min(puntos, 25), factores

def nivel_por_score(score):
    if score >= 81:
        return "CRITICO"
    if score >= 61:
        return "ALTO"
    if score >= 31:
        return "MEDIO"
    return "BAJO"

def recomendacion_por_nivel(nivel, fuentes_faltantes):
    if nivel == "CRITICO":
        return "Atender de inmediato los servicios expuestos, CVEs críticas e indicadores maliciosos detectados."
    if nivel == "ALTO":
        return "Priorizar corrección de vulnerabilidades relevantes, endurecer servicios expuestos y validar hallazgos web."
    if nivel == "MEDIO":
        return "Revisar versiones de servicios, aplicar parches pendientes y completar validación web/OWASP."
    if fuentes_faltantes:
        return "Riesgo bajo con datos incompletos. Completar agentes faltantes para una correlación más precisa."
    return "Riesgo bajo. Mantener monitoreo, parches actualizados y buenas prácticas de configuración."

def generar_analisis_ia(target, ip, score_total, nivel, desglose, factores_criticos, fuentes_faltantes):
    """
    Usa el mismo estilo del Agente 2:
    Ollama con endpoint compatible OpenAI y modelo gpt-oss:20b-cloud (Integrante 3).
    Si falla, devuelve un análisis de respaldo para no romper el agente.
    """

    prompt = f"""
Eres un analista SOC. Resume el riesgo de seguridad de este objetivo en español claro.

Objetivo: {target}
IP: {ip}
Score total: {score_total}/100
Nivel: {nivel}
Desglose: {json.dumps(desglose, ensure_ascii=False)}
Factores críticos: {json.dumps(factores_criticos, ensure_ascii=False)}
Fuentes faltantes: {json.dumps(fuentes_faltantes, ensure_ascii=False)}

Redacta:
1. Diagnóstico breve.
2. Riesgos principales.
3. Recomendación inmediata.

No inventes CVEs ni amenazas que no estén en los datos.
Máximo 130 palabras.
"""

    try:
        response = ai.chat.completions.create(
            model=AI_MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2,
        )

        return response.choices[0].message.content.strip()

    except Exception as e:
        return (
            "Análisis IA no disponible. "
            f"El score fue calculado por reglas ponderadas. Error: {e}"
        )

def run_agent():
    print("\n📊 Agente 9 — Risk Correlation")

    archivos = {
        "ag2": shared_path("ag2.json"),
        "ag4": shared_path("ag4.json"),
        "ag5": shared_path("ag5.json"),
        "ag6": shared_path("ag6.json"),
        "ag7": shared_path("ag7.json"),
        "ag8": shared_path("ag8.json"),
    }

    datos = {}
    fuentes_usadas = []
    fuentes_faltantes = []

    for nombre, ruta in archivos.items():
        if os.path.exists(ruta):
            datos[nombre] = leer_json(ruta, default={})
            fuentes_usadas.append(f"{nombre}.json")
        else:
            datos[nombre] = {}
            fuentes_faltantes.append(f"{nombre}.json")

    ag2 = datos["ag2"]
    ag4 = datos["ag4"]
    ag5 = datos["ag5"]
    ag6 = datos["ag6"]
    ag7 = datos["ag7"]
    ag8 = datos["ag8"]

    target = ag2.get("target") or ag8.get("target") or ag7.get("target") or "sin_objetivo"
    ip = ag2.get("ip") or ag7.get("ip") or "sin_ip"

    riesgo_red, factores_red = calcular_riesgo_red(ag2)
    riesgo_web, factores_web = calcular_riesgo_web(ag4, ag5, ag6)
    riesgo_cves, factores_cves = calcular_riesgo_cves(ag7)
    riesgo_threat, factores_threat = calcular_riesgo_threat_intel(ag8)

    score_total = min(
        riesgo_red + riesgo_web + riesgo_cves + riesgo_threat,
        100
    )

    nivel = nivel_por_score(score_total)

    factores_criticos = []
    factores_criticos.extend(factores_red)
    factores_criticos.extend(factores_web)
    factores_criticos.extend(factores_cves)
    factores_criticos.extend(factores_threat)

    recomendacion = recomendacion_por_nivel(nivel, fuentes_faltantes)

    resultado = {
        "agent": "AG9_RISK_CORRELATION",
        "integrante": 3,
        "target": target,
        "ip": ip,
        "score_total": score_total,
        "nivel": nivel,
        "desglose": {
            "red": riesgo_red,
            "web_owasp": riesgo_web,
            "cves": riesgo_cves,
            "threat_intel": riesgo_threat
        },
        "factores_criticos": factores_criticos,
        "recomendacion_inmediata": recomendacion,
        "fuentes_usadas": fuentes_usadas,
        "fuentes_faltantes": fuentes_faltantes,
        "analisis_ia": generar_analisis_ia(
            target,
   	    ip,
   	    score_total,
   	    nivel,
    	   {
        	"red": riesgo_red,
        	"web_owasp": riesgo_web,
        	"cves": riesgo_cves,
        	"threat_intel": riesgo_threat
    	   },
    	   factores_criticos,
    	   fuentes_faltantes
	),
	"modelo_usado": {
    	   "tipo": "ollama_openai_compatible",
      	   "modelo": AI_MODEL,
    	   "descripcion": "Score calculado con reglas ponderadas y análisis técnico generado con modelo local/remoto vía Ollama."
        },
        "timestamp": datetime.now(UTC).isoformat()
    }

    guardar_json(shared_path("ag9.json"), resultado)

    print("\n✅ Listo. Guardado en shared_data/ag9.json")
    print(f" Target: {target}")
    print(f" Score total: {score_total}/100")
    print(f" Nivel: {nivel}")

    if fuentes_faltantes:
        print(f" ⚠ Fuentes faltantes: {', '.join(fuentes_faltantes)}")

    return resultado

if __name__ == "__main__":
    run_agent()