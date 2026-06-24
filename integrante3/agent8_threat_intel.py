import json
import os
import re
import ipaddress
from datetime import datetime, UTC

import requests
from dotenv import load_dotenv

load_dotenv()

USE_REAL_APIS = os.getenv("USE_REAL_APIS", "true").lower() == "true"
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
REQUEST_TIMEOUT = 20

USE_AI_ANALYSIS = False  # Temporalmente deshabilitado por errores de parsing

if USE_AI_ANALYSIS:
    try:
        from openai import OpenAI
        ai_client = OpenAI(
            base_url=os.getenv("OLLAMA_BASE_URL", "http://localhost:11434/v1"),
            api_key=os.getenv("OLLAMA_API_KEY", "ollama"),
        )
        AI_MODEL = os.getenv("SECDASH_AI_MODEL", "minimax-m3:cloud")
        AI_AVAILABLE = True
    except ImportError:
        print("⚠️ OpenAI no disponible.")
        AI_AVAILABLE = False
else:
    AI_AVAILABLE = False

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
        print(f"⚠ No se encontró {path}")
        return default
    except json.JSONDecodeError:
        print(f"⚠ El archivo {path} no tiene JSON válido")
        return default

def guardar_json(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)

    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def es_ip_valida(valor):
    try:
        ipaddress.ip_address(str(valor))
        return True
    except ValueError:
        return False

def es_ip_publica(ip):
    try:
        obj = ipaddress.ip_address(str(ip))
        return not (
            obj.is_private
            or obj.is_loopback
            or obj.is_link_local
            or obj.is_multicast
            or obj.is_reserved
            or obj.is_unspecified
        )
    except ValueError:
        return False

def buscar_ips_en_texto(texto):
    texto = str(texto or "")
    patron_ipv4 = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"

def ai_analyze_threat_intel(ioc_data: dict) -> dict:
    if not AI_AVAILABLE:
        return {}
    
    try:
        ip = ioc_data.get("ip", "")
        country = ioc_data.get("country", "")
        abuse_confidence = ioc_data.get("abuse_confidence", 0)
        usage_type = ioc_data.get("usage_type", "")
        categories = ioc_data.get("categories", [])
        
        prompt = f"""Analiza este IOC:

IP: {ip}
PAÍS: {country}
CONFIANZA ABUSO: {abuse_confidence}%
USO: {usage_type}
CATEGORÍAS: {categories}

Responde en JSON con:
1. "perfil_amenaza": Tipo de actor/campaña probable
2. "contexto_geopolitico": Relevancia del país
3. "tacticas_ttp": Técnicas MITRE ATT&CK comunes
4. "campanas_relacionadas": Campañas conocidas
5. "nivel_sofisticacion": BÁSICO/INTERMEDIO/AVANZADO/APT
6. "recomendaciones_blocking": Acciones de bloqueo
7. "indicadores_adicionales": Qué más monitorear
8. "contexto_temporal": Tendencias recientes

Responde SOLO en JSON válido.
"""
        
        response = ai_client.chat.completions.create(
            model=AI_MODEL,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=800,
            temperature=0.2
        )
        
        analysis_text = response.choices[0].message.content.strip()
        
        if not analysis_text:
            raise ValueError("Respuesta vacía de la IA")
        
        # Limpiar markdown
        if analysis_text.startswith('```'):
            analysis_text = analysis_text.replace('```json', '').replace('```', '').strip()
        
        # Intentar parsear JSON
        parsed = json.loads(analysis_text)
        
        # Validar que sea diccionario
        if not isinstance(parsed, dict):
            raise ValueError("Respuesta no es un diccionario")
        
        return parsed
        
    except Exception as e:
        print(f"⚠️ Error en análisis IA: {e}")
        return {
            "perfil_amenaza": "Requiere análisis manual",
            "contexto_geopolitico": "No determinado",
            "tacticas_ttp": ["Consultar MITRE ATT&CK"],
            "campanas_relacionadas": ["Investigación adicional requerida"],
            "nivel_sofisticacion": "NO_DETERMINADO",
            "recomendaciones_blocking": ["Bloqueo preventivo recomendado"],
            "indicadores_adicionales": ["Monitorear tráfico relacionado"],
            "contexto_temporal": "Análisis pendiente",
            "ia_error": str(e)
        }

def buscar_ips_en_texto(texto):
    texto = str(texto or "")
    patron_ipv4 = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    posibles = re.findall(patron_ipv4, texto)
    return [ip for ip in posibles if es_ip_valida(ip)]

def extraer_ips_recursivo(obj):
    """
    Busca IPs en dicts/listas/textos para ser compatible aunque ag1/ag2
    cambien un poco su estructura.
    """
    ips = []
    
    if obj is None:
        return ips

    if isinstance(obj, dict):
        for _, valor in obj.items():
            ips.extend(extraer_ips_recursivo(valor))

    elif isinstance(obj, list):
        for item in obj:
            ips.extend(extraer_ips_recursivo(item))

    elif isinstance(obj, str):
        ips.extend(buscar_ips_en_texto(obj))

    elif isinstance(obj, (int, float)):
        pass

    return ips

def reputacion_por_score(score):
    try:
        score = int(score)
    except Exception:
        score = 0

    if score >= 75:
        return "malicioso"
    if score >= 25:
        return "sospechoso"
    return "limpio"

def consultar_abuseipdb(ip):
    """
    Consulta reputación de IP en AbuseIPDB cuando hay API key.
    Si USE_REAL_APIS=true pero no hay key, usa análisis local.
    """
    if not USE_REAL_APIS:
        return None

    if not es_ip_publica(ip):
        return {
            "ip": ip,
            "abuse_score": 0,
            "reputacion": "interno",
            "campanas_malware": [],
            "fuente": "LOCAL_CHECK",
            "detalle": "IP privada o no pública. No se consulta reputación externa."
        }

    if not ABUSEIPDB_API_KEY:
        print(f"⚠ USE_REAL_APIS=true, pero falta ABUSEIPDB_API_KEY en .env")
        print(f"  → Usando análisis local para {ip}")
        # Usar análisis básico local en lugar de None
        return {
            "ip": ip,
            "abuse_score": 0,
            "reputacion": "no_verificado",
            "campanas_malware": [],
            "fuente": "LOCAL_ANALYSIS",
            "detalle": "Sin API key - análisis básico. IP pública no verificada en bases de amenazas."
        }

    url = "https://api.abuseipdb.com/api/v2/check"

    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }

    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }

    try:
        response = requests.get(
            url,
            headers=headers,
            params=params,
            timeout=REQUEST_TIMEOUT
        )
        response.raise_for_status()
        data = response.json().get("data", {})
    except Exception as e:
        print(f"⚠ Error consultando AbuseIPDB para {ip}: {e}")
        return None

    abuse_score = data.get("abuseConfidenceScore", 0)
    reputacion = reputacion_por_score(abuse_score)

    return {
        "ip": ip,
        "abuse_score": abuse_score,
        "reputacion": reputacion,
        "campanas_malware": [],
        "fuente": "AbuseIPDB",
        "pais": data.get("countryCode", ""),
        "isp": data.get("isp", ""),
        "dominio": data.get("domain", ""),
        "tipo_uso": data.get("usageType", ""),
        "total_reportes": data.get("totalReports", 0),
        "detalle": "Consulta de reputación realizada mediante API externa."
    }

def generar_ioc_demo(ip):
    """
    Modo demo con conceptos del curso: IoCs, malware, threat actors, MITRE ATT&CK
    """
    if not es_ip_publica(ip):
        return {
            "ip": ip,
            "abuse_score": 0,
            "reputacion": "interno",
            "campanas_malware": [],
            "threat_actors": [],
            "mitre_attack_tactics": [],
            "indicadores_compromiso": {
                "tipo": "IP privada",
                "confidence": "N/A"
            },
            "fuente": "MOCK",
            "detalle": "IP privada/no pública detectada en modo demostrativo."
        }

    # Generar datos de demostración con conceptos del curso
    return {
        "ip": ip,
        "abuse_score": 15,
        "reputacion": "limpio",
        "campanas_malware": [
            {
                "nombre": "DEMO-Botnet-2024",
                "tipo": "C2 Server",
                "familia": "Mirai",
                "primera_deteccion": "2024-01-15",
                "activa": False
            }
        ],
        "threat_actors": [
            {
                "nombre": "APT-DEMO",
                "origen": "Unknown",
                "motivacion": "Financial",
                "nivel_sofisticacion": "Medium"
            }
        ],
        "mitre_attack_tactics": [
            {
                "tactic_id": "TA0001",
                "tactic_name": "Initial Access",
                "techniques": ["T1190 - Exploit Public-Facing Application"]
            },
            {
                "tactic_id": "TA0011",
                "tactic_name": "Command and Control",
                "techniques": ["T1071 - Application Layer Protocol"]
            }
        ],
        "indicadores_compromiso": {
            "tipo": "Network IOC",
            "confidence": "Low",
            "observables": {
                "conexiones_sospechosas": 0,
                "payloads_maliciosos": 0,
                "firmas_malware": []
            }
        },
        "analisis_forense": {
            "volatilidad": "Media",
            "persistencia_detectada": False,
            "artefactos": []
        },
        "fuente": "MOCK",
        "detalle": "Resultado demostrativo con conceptos del curso: IoCs, malware, threat actors, MITRE ATT&CK. Para datos reales activar USE_REAL_APIS=true."
    }

def run_agent():
    print("\n🕵️ Agente 8 — Threat Intelligence")

    ag1 = leer_json(shared_path("ag1.json"), default={})
    ag2 = leer_json(shared_path("ag2.json"), default={})

    target = ag1.get("target") or ag2.get("target") or "sin_objetivo"

    ips = []

    if ag1.get("ip"):
        ips.append(ag1.get("ip"))

    if ag2.get("ip"):
        ips.append(ag2.get("ip"))

    ips.extend(extraer_ips_recursivo(ag1))
    ips.extend(extraer_ips_recursivo(ag2))

    # Limpiar duplicados conservando orden
    ips_limpias = []
    for ip in ips:
        ip = str(ip).strip()
        if es_ip_valida(ip) and ip not in ips_limpias:
            ips_limpias.append(ip)

    print(f" Target: {target}")
    print(f" IPs encontradas: {len(ips_limpias)}")

    iocs = []

    for ip in ips_limpias:
        print(f" → Analizando reputación de {ip}")

        resultado_real = consultar_abuseipdb(ip)

        if resultado_real:
            iocs.append(resultado_real)
        else:
            # Si USE_REAL_APIS=false, usar demo
            iocs.append(generar_ioc_demo(ip))

    if AI_AVAILABLE and USE_AI_ANALYSIS and iocs:
        print("🤖 Aplicando análisis IA...")
        for ioc in iocs:
            ai_analysis = ai_analyze_threat_intel(ioc)
            if ai_analysis:
                ioc["inteligencia_ia"] = ai_analysis
        print(f"✅ {len(iocs)} IOCs procesados")

    resultado = {
        "agent": "AG8_THREAT_INTELLIGENCE",
        "integrante": 3,
        "target": target,
        "modo": "real_abuseipdb" if USE_REAL_APIS else "demo",
        "api_key_configurada": bool(ABUSEIPDB_API_KEY) if USE_REAL_APIS else False,
        "iocs": iocs,
        "total_iocs": len(iocs),
        "ia_habilitada": AI_AVAILABLE and USE_AI_ANALYSIS,
        "modelo_ia": AI_MODEL if AI_AVAILABLE else None,
        "resumen_amenazas": {
            "maliciosos": sum(1 for ioc in iocs if ioc.get("reputacion") == "malicioso"),
            "sospechosos": sum(1 for ioc in iocs if ioc.get("reputacion") == "sospechoso"),
            "limpios": sum(1 for ioc in iocs if ioc.get("reputacion") == "limpio"),
            "internos": sum(1 for ioc in iocs if ioc.get("reputacion") == "interno"),
            "campanas_activas": sum(len(ioc.get("campanas_malware", [])) for ioc in iocs),
            "threat_actors_unicos": len(set(
                actor["nombre"] 
                for ioc in iocs 
                for actor in ioc.get("threat_actors", [])
            )),
            "mitre_tactics_detected": len(set(
                tactic["tactic_id"]
                for ioc in iocs
                for tactic in ioc.get("mitre_attack_tactics", [])
            ))
        },
        "timestamp": datetime.now(UTC).isoformat(),
        "nota": "Modo REAL activado. Sin API key se usa análisis local. Para modo demo, establecer USE_REAL_APIS=false en .env"
    }

    output_path = shared_path("ag8.json")
    guardar_json(output_path, resultado)

    print("\n✅ Listo. Guardado en shared_data/ag8.json")
    print(f" IOCs registrados: {len(iocs)}")

    for ioc in iocs:
        print(f" → {ioc['ip']} | {ioc['reputacion']} | score {ioc['abuse_score']}/100")

    return resultado

if __name__ == "__main__":
    run_agent()