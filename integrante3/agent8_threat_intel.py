"""
AGENTE 8 — Threat Intelligence
Integrante 3

Lee shared_data/ag1.json y shared_data/ag2.json para extraer IPs.
Luego genera shared_data/ag8.json con reputación básica de IOCs.

Modo:
- Si USE_REAL_APIS=true y existe ABUSEIPDB_API_KEY en .env, consulta AbuseIPDB.
- Si no, trabaja en modo demo para que el dashboard funcione.
"""

import json
import os
import re
import ipaddress
from datetime import datetime, UTC

import requests
from dotenv import load_dotenv

load_dotenv()

USE_REAL_APIS = os.getenv("USE_REAL_APIS", "false").lower() == "true"
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
REQUEST_TIMEOUT = 20


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
    posibles = re.findall(patron_ipv4, texto)

    return [ip for ip in posibles if es_ip_valida(ip)]


def extraer_ips_recursivo(obj):
    """
    Busca IPs en dicts/listas/textos para ser compatible aunque ag1/ag2
    cambien un poco su estructura.
    """
    ips = []

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
    Si falla, devuelve None para no romper el agente.
    """
    if not USE_REAL_APIS:
        return None

    if not ABUSEIPDB_API_KEY:
        print("⚠ USE_REAL_APIS=true, pero falta ABUSEIPDB_API_KEY en .env")
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
            iocs.append(generar_ioc_demo(ip))

    resultado = {
        "agent": "AG8_THREAT_INTELLIGENCE",
        "integrante": 3,
        "target": target,
        "modo": "real_abuseipdb" if USE_REAL_APIS else "mock_demo",
        "iocs": iocs,
        "total_iocs": len(iocs),
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
        "nota": "MOCK indica dato demostrativo con conceptos del curso: IoCs, malware, threat actors, MITRE ATT&CK, análisis forense. Para datos reales activar USE_REAL_APIS=true."
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