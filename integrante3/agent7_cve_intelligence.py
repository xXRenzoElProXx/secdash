import json
import os
import re
from datetime import datetime, UTC

import requests
from dotenv import load_dotenv

load_dotenv()

USE_REAL_APIS = os.getenv("USE_REAL_APIS", "true").lower() == "true"
NVD_API_KEY = os.getenv("NVD_API_KEY", "")
REQUEST_TIMEOUT = 20

USE_AI_ANALYSIS = False  # Temporalmente deshabilitado por errores de parsing

if USE_AI_ANALYSIS:
    try:
        from openai import OpenAI
        ai_client = OpenAI(base_url="http://localhost:11434/v1", api_key="ollama")
        AI_MODEL = "gpt-oss:20b-cloud"
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

def limpiar_texto(texto):
    texto = str(texto or "").strip()
    texto = re.sub(r"\s+", " ", texto)
    return texto

def ai_analyze_cve(cve_data: dict) -> dict:
    if not AI_AVAILABLE:
        return {}
    
    try:
        cve_id = cve_data.get("id", "")
        description = cve_data.get("descripcion", "")
        cvss_score = cve_data.get("cvss_score", 0)
        servicio = cve_data.get("servicio_afectado", "")
        
        prompt = f"""Analiza este CVE:

CVE ID: {cve_id}
DESCRIPCIÓN: {description}
CVSS SCORE: {cvss_score}
SERVICIO: {servicio}

Responde en JSON con:
1. "contexto_amenaza": Tipo de vulnerabilidad (2-3 líneas)
2. "explotabilidad": BAJA/MEDIA/ALTA
3. "impacto_organizacional": Riesgo específico
4. "indicadores_compromiso": Qué buscar si fue explotado
5. "prioridad_parcheo": INMEDIATA/ALTA/MEDIA/BAJA con justificación
6. "recursos_defensa": Herramientas para detectar/prevenir
7. "contexto_apt": Relación con grupos APT

Responde SOLO en JSON válido.
"""
        
        response = ai_client.chat.completions.create(
            model=AI_MODEL,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=700,
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
        
        # Validar que tenga las claves esperadas
        if not isinstance(parsed, dict):
            raise ValueError("Respuesta no es un diccionario")
        
        return parsed
        
    except Exception as e:
        print(f"⚠️ Error en análisis IA: {e}")
        return {
            "contexto_amenaza": "Análisis IA no disponible",
            "explotabilidad": "REVISAR_MANUAL",
            "impacto_organizacional": "Requiere evaluación manual",
            "indicadores_compromiso": ["Logs de aplicación", "Tráfico anómalo"],
            "prioridad_parcheo": "EVALUAR",
            "recursos_defensa": ["Consultar MITRE ATT&CK"],
            "contexto_apt": "No determinado",
            "ia_error": str(e)
        }

def construir_query_servicio(servicio):
    """
    El Agente 2 guarda datos así:
    {
      "service": "http",
      "version": "nginx 1.18.0"
    }

    Por eso construimos una búsqueda flexible usando service + version.
    """
    service = limpiar_texto(servicio.get("service", ""))
    version = limpiar_texto(servicio.get("version", ""))

    if version:
        return version

    if service:
        return service

    return ""

def extraer_cvss_y_severidad(cve_item):
    """
    Extrae CVSS score completo: Base, Temporal, Environmental (si disponible)
    Prioriza CVSSv3.1 > CVSSv3.0 > CVSSv2
    """
    metrics = cve_item.get("metrics", {})
    
    cvss_detail = {
        "base_score": 0,
        "base_severity": "UNKNOWN",
        "temporal_score": None,
        "environmental_score": None,
        "vector_string": "",
        "exploitability": None,
        "impact": None
    }

    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        if key in metrics and metrics[key]:
            metric = metrics[key][0]
            cvss_data = metric.get("cvssData", {})
            
            cvss_detail["base_score"] = cvss_data.get("baseScore", 0)
            cvss_detail["base_severity"] = metric.get("baseSeverity") or cvss_data.get("baseSeverity") or "UNKNOWN"
            cvss_detail["vector_string"] = cvss_data.get("vectorString", "")
            
            # Scores adicionales (CVSSv3)
            if "exploitabilityScore" in metric:
                cvss_detail["exploitability"] = metric.get("exploitabilityScore")
            if "impactScore" in metric:
                cvss_detail["impact"] = metric.get("impactScore")
            
            return cvss_detail["base_score"], cvss_detail["base_severity"], cvss_detail

    return 0, "UNKNOWN", cvss_detail

def buscar_cves_nvd(query, service_info):
    """
    Consulta NVD si USE_REAL_APIS=true.
    Si no hay API key, funciona en modo sin autenticación (rate limitado).
    Incluye análisis de vulnerabilidades día cero y supply chain.
    """
    if not USE_REAL_APIS:
        return []

    if not query:
        return []

    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "keywordSearch": query,
        "resultsPerPage": 5
    }

    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
        print(f"      ✓ Usando API key de NVD")
    else:
        print(f"      ⚠️  Sin API key NVD - modo rate limitado (puede ser lento)")

    try:
        response = requests.get(
            url,
            params=params,
            headers=headers,
            timeout=REQUEST_TIMEOUT
        )
        response.raise_for_status()
        data = response.json()
    except Exception as e:
        print(f"⚠ Error consultando NVD para '{query}': {e}")
        return []

    resultados = []

    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "N/A")

        descripcion = ""
        for desc in cve.get("descriptions", []):
            if desc.get("lang") == "en":
                descripcion = desc.get("value", "")
                break

        score, severity, cvss_detail = extraer_cvss_y_severidad(cve)

        refs = cve.get("references", [])
        advisory = refs[0].get("url", "") if refs else ""
        
        # Análisis de día cero y supply chain
        published = cve.get("published", "")
        is_zero_day = "DISPUTED" in descripcion.upper() or "0-DAY" in descripcion.upper()
        is_supply_chain = any(word in descripcion.lower() for word in ["supply chain", "dependency", "third-party", "package"])

        resultados.append({
            "software": service_info.get("service", ""),
            "version": service_info.get("version", ""),
            "port": service_info.get("port", ""),
            "protocol": service_info.get("protocol", ""),
            "cve_id": cve_id,
            "cvss_score": score,
            "severidad": severity,
            "cvss_detail": cvss_detail,
            "descripcion": descripcion[:280],
            "advisory_url": advisory,
            "published_date": published,
            "is_zero_day": is_zero_day,
            "is_supply_chain": is_supply_chain,
            "fuente": "NVD"
        })

    return resultados

def cves_mock_para_demo(services):
    """
    Modo demostrativo con conceptos del curso: CVSS detallado, día cero, supply chain
    """
    cves = []

    for s in services:
        query = construir_query_servicio(s).lower()
        service = str(s.get("service", "")).lower()

        if "nginx" in query or "http" in service:
            cves.append({
                "software": s.get("service", "http"),
                "version": s.get("version", "nginx"),
                "port": s.get("port", 80),
                "protocol": s.get("protocol", "tcp"),
                "cve_id": "CVE-2021-23017",
                "cvss_score": 8.1,
                "severidad": "HIGH",
                "cvss_detail": {
                    "base_score": 8.1,
                    "base_severity": "HIGH",
                    "exploitability": 3.9,
                    "impact": 5.9,
                    "vector_string": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"
                },
                "descripcion": "Buffer overflow in DNS resolver - permite ejecución remota de código",
                "advisory_url": "https://nvd.nist.gov/vuln/detail/CVE-2021-23017",
                "published_date": "2021-06-01T00:00:00",
                "is_zero_day": False,
                "is_supply_chain": False,
                "fuente": "MOCK"
            })

        if "ssh" in service or "openssh" in query:
            cves.append({
                "software": s.get("service", "ssh"),
                "version": s.get("version", "OpenSSH"),
                "port": s.get("port", 22),
                "protocol": s.get("protocol", "tcp"),
                "cve_id": "CVE-2023-38408",
                "cvss_score": 9.8,
                "severidad": "CRITICAL",
                "cvss_detail": {
                    "base_score": 9.8,
                    "base_severity": "CRITICAL",
                    "exploitability": 3.9,
                    "impact": 5.9,
                    "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                },
                "descripcion": "Remote code execution in ssh-agent forwarding",
                "advisory_url": "https://nvd.nist.gov/vuln/detail/CVE-2023-38408",
                "published_date": "2023-07-19T00:00:00",
                "is_zero_day": False,
                "is_supply_chain": False,
                "fuente": "MOCK"
            })
    
    # Añadir ejemplo de vulnerabilidad día cero
    if len(services) > 0:
        cves.append({
            "software": "unknown",
            "version": "unknown",
            "port": 0,
            "protocol": "tcp",
            "cve_id": "CVE-2024-XXXXX",
            "cvss_score": 9.0,
            "severidad": "CRITICAL",
            "cvss_detail": {
                "base_score": 9.0,
                "base_severity": "CRITICAL",
                "exploitability": 3.9,
                "impact": 5.9,
                "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
            },
            "descripcion": "EJEMPLO: Vulnerabilidad día cero potencial detectada - requiere análisis manual",
            "advisory_url": "",
            "published_date": datetime.now(UTC).isoformat(),
            "is_zero_day": True,
            "is_supply_chain": False,
            "fuente": "MOCK"
        })
        
        # Añadir ejemplo de supply chain
        cves.append({
            "software": "dependency",
            "version": "lib-xyz-1.2.3",
            "port": 0,
            "protocol": "n/a",
            "cve_id": "CVE-2024-SUPPLY",
            "cvss_score": 7.5,
            "severidad": "HIGH",
            "cvss_detail": {
                "base_score": 7.5,
                "base_severity": "HIGH",
                "exploitability": 3.9,
                "impact": 3.6,
                "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
            },
            "descripcion": "EJEMPLO: Vulnerabilidad en cadena de suministro (supply chain) - dependencia comprometida",
            "advisory_url": "",
            "published_date": "2024-01-15T00:00:00",
            "is_zero_day": False,
            "is_supply_chain": True,
            "fuente": "MOCK"
        })

    return cves

def run_agent():
    print("\n🧬 Agente 7 — CVE Intelligence")

    ag2_path = shared_path("ag2.json")
    ag2 = leer_json(ag2_path, default={})

    target = ag2.get("target", "sin_objetivo")
    ip = ag2.get("ip", "sin_ip")
    services = ag2.get("services", [])

    print(f" Target: {target}")
    print(f" IP: {ip}")
    print(f" Servicios recibidos: {len(services)}")

    cves_encontrados = []

    if USE_REAL_APIS:
        print(" Modo real activo: consultando NVD...")
        if not NVD_API_KEY:
            print(" ⚠️  Sin NVD_API_KEY - consultando sin autenticación (rate limitado)")
        for s in services:
            query = construir_query_servicio(s)
            if not query:
                continue
            print(f" → Buscando CVEs para: {query}")
            cves_encontrados.extend(buscar_cves_nvd(query, s))
    else:
        print(" Modo demo activo: generando CVEs simulados para pruebas.")
        cves_encontrados = cves_mock_para_demo(services)

    if AI_AVAILABLE and USE_AI_ANALYSIS and cves_encontrados:
        print("🤖 Aplicando análisis IA...")
        for cve in cves_encontrados:
            ai_analysis = ai_analyze_cve(cve)
            if ai_analysis:
                cve["inteligencia_ia"] = ai_analysis
        print(f"✅ {len(cves_encontrados)} CVEs procesados")

    resultado = {
        "agent": "AG7_CVE_INTELLIGENCE",
        "integrante": 3,
        "target": target,
        "ip": ip,
        "modo": "real_nvd" if USE_REAL_APIS else "demo",
        "api_key_configurada": bool(NVD_API_KEY) if USE_REAL_APIS else False,
        "cves_encontrados": cves_encontrados,
        "total_cves": len(cves_encontrados),
        "ia_habilitada": AI_AVAILABLE and USE_AI_ANALYSIS,
        "modelo_ia": AI_MODEL if AI_AVAILABLE else None,
        "analisis_cvss": {
            "critical": sum(1 for c in cves_encontrados if c.get("severidad") == "CRITICAL"),
            "high": sum(1 for c in cves_encontrados if c.get("severidad") == "HIGH"),
            "medium": sum(1 for c in cves_encontrados if c.get("severidad") == "MEDIUM"),
            "low": sum(1 for c in cves_encontrados if c.get("severidad") == "LOW"),
            "avg_score": round(sum(c.get("cvss_score", 0) for c in cves_encontrados) / len(cves_encontrados), 2) if cves_encontrados else 0
        },
        "vulnerabilidades_especiales": {
            "zero_day_count": sum(1 for c in cves_encontrados if c.get("is_zero_day", False)),
            "supply_chain_count": sum(1 for c in cves_encontrados if c.get("is_supply_chain", False)),
            "zero_day_ids": [c["cve_id"] for c in cves_encontrados if c.get("is_zero_day", False)],
            "supply_chain_ids": [c["cve_id"] for c in cves_encontrados if c.get("is_supply_chain", False)]
        },
        "timestamp": datetime.now(UTC).isoformat(),
        "nota": "Modo REAL activado. Sin API key NVD se usan consultas rate-limitadas. Sin API key AbuseIPDB se usa análisis local. Para modo demo, establecer USE_REAL_APIS=false en .env"
    }

    output_path = shared_path("ag7.json")
    guardar_json(output_path, resultado)

    print("\n✅ Listo. Guardado en shared_data/ag7.json")
    print(f" CVEs registrados: {len(cves_encontrados)}")

    return resultado

if __name__ == "__main__":
    run_agent()