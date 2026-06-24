import json
import os
import re
import subprocess
import hashlib
from datetime import datetime, UTC
from openai import OpenAI
import requests

USE_REAL_APIS = os.getenv("USE_REAL_APIS", "true").lower() == "true"
REQUEST_TIMEOUT = 15

try:
    ai = OpenAI(
        base_url=os.getenv("OLLAMA_BASE_URL", "http://localhost:11434/v1"),
        api_key=os.getenv("OLLAMA_API_KEY", "ollama"),
    )
    AI_MODEL = os.getenv("SECDASH_AI_MODEL", "minimax-m3:cloud")
    # Test de conexión más rápido
    ai.models.list()
    print("   ✓ Ollama conectado")
    ai_available = True
except Exception as e:
    print(f"   ⚠️  IA no disponible: {e}")
    print("   ℹ️  Continuando en modo sin IA...")
    ai_available = False

def load_json(filename):
    """Carga un JSON desde shared_data/"""
    path = os.path.join(os.path.dirname(__file__), "..", "shared_data", filename)
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"   ⚠️  {filename} no encontrado")
        return None
    except Exception as e:
        print(f"   ❌ Error leyendo {filename}: {e}")
        return None

def buscar_en_msfconsole(cve_id):
    
    try:
        # Ejecutar msfconsole en modo script para buscar el CVE
        cmd = f'msfconsole -q -x "search {cve_id}; exit"'
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=30
        )
        
        output = result.stdout.strip()
        
        # Parsear output para encontrar módulos
        if "No results" in output or not output:
            return None
        
        # Buscar líneas que contienen módulos (formato: exploit/...)
        modules = []
        for line in output.split('\n'):
            if 'exploit/' in line or 'auxiliary/' in line:
                # Extraer nombre del módulo
                parts = line.split()
                for part in parts:
                    if 'exploit/' in part or 'auxiliary/' in part:
                        modules.append(part.strip())
                        break
        
        return modules[0] if modules else None
        
    except subprocess.TimeoutExpired:
        print(f"      ⏱️  Timeout buscando {cve_id}")
        return None
    except FileNotFoundError:
        print(f"      ⚠️  msfconsole no instalado")
        return None
    except Exception as e:
        print(f"      ❌ Error: {e}")
        return None

def buscar_con_ia(cve_id, descripcion):
    """Fallback: usa IA para sugerir módulos si msfconsole no está disponible"""
    if not ai_available:
        return analisis_basico(cve_id, descripcion)
    
    prompt = f"""Eres un experto en Metasploit Framework.
Para el siguiente CVE, indica si existe un módulo de explotación conocido.

CVE: {cve_id}
Descripción: {descripcion}

Devuelve SOLO un JSON con esta estructura:
{{
  "modulo_msf": "exploit/path/to/module o 'No encontrado'",
  "probabilidad_exito": "alta | media | baja",
  "impacto": "critico | alto | medio | bajo",
  "nota": "Breve nota técnica sobre el exploit"
}}

Si no conoces un módulo específico, pon "No encontrado" en modulo_msf.
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
        print(f"      ⚠️  Error en análisis IA: {e}")
        return analisis_basico(cve_id, descripcion)

def consultar_epss(cve_id):
    """
    Consulta EPSS (Exploit Prediction Scoring System) de FIRST.org
    Devuelve probabilidad de explotación en próximos 30 días
    """
    if not USE_REAL_APIS:
        # Datos simulados para demo
        return {
            "cve_id": cve_id,
            "epss_score": round(0.15 + hash(cve_id) % 50 / 100, 4),  # 0.15-0.65
            "epss_percentile": round(45 + hash(cve_id) % 50, 1),  # 45-95%
            "fecha_calculo": "2026-06-12",
            "fuente": "MOCK"
        }
    
    try:
        # API real de FIRST EPSS
        url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
        response = requests.get(url, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        data = response.json()
        
        if data.get("data") and len(data["data"]) > 0:
            epss_data = data["data"][0]
            return {
                "cve_id": cve_id,
                "epss_score": float(epss_data.get("epss", 0)),
                "epss_percentile": float(epss_data.get("percentile", 0)) * 100,
                "fecha_calculo": epss_data.get("date", ""),
                "fuente": "FIRST.org"
            }
    except Exception as e:
        print(f"      ⚠️  Error consultando EPSS: {e}")
    
    return None

def buscar_exploitdb(cve_id):
    """
    Busca el CVE en ExploitDB
    En modo real usaría searchsploit o API de ExploitDB
    """
    if not USE_REAL_APIS:
        # Simulado: algunos CVEs tienen exploit, otros no
        if hash(cve_id) % 3 == 0:
            return {
                "edb_id": f"EDB-{40000 + hash(cve_id) % 10000}",
                "titulo": f"Exploit para {cve_id}",
                "tipo": "remote",
                "plataforma": "linux",
                "fecha": "2024-05-15",
                "url": f"https://www.exploit-db.com/exploits/{40000 + hash(cve_id) % 10000}",
                "fuente": "MOCK"
            }
        return None
    
    try:
        # En producción: usar searchsploit o requests a exploit-db.com
        # searchsploit --cve CVE-YYYY-XXXX --json
        cmd = ["searchsploit", "--cve", cve_id, "--json"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0:
            exploits = json.loads(result.stdout)
            if exploits and "RESULTS_EXPLOIT" in exploits and len(exploits["RESULTS_EXPLOIT"]) > 0:
                exploit = exploits["RESULTS_EXPLOIT"][0]
                return {
                    "edb_id": exploit.get("EDB-ID", ""),
                    "titulo": exploit.get("Title", ""),
                    "tipo": exploit.get("Type", ""),
                    "plataforma": exploit.get("Platform", ""),
                    "fecha": exploit.get("Date", ""),
                    "url": f"https://www.exploit-db.com/exploits/{exploit.get('EDB-ID', '')}",
                    "fuente": "ExploitDB"
                }
    except Exception as e:
        print(f"      ⚠️  searchsploit no disponible: {e}")
    
    return None

def buscar_github_poc(cve_id):
    """
    Busca Proof of Concept en GitHub
    Simulado para no consumir rate limit de GitHub API
    """
    if not USE_REAL_APIS:
        # Simulado
        if hash(cve_id) % 2 == 0:
            return {
                "repositorio": f"security-researcher/{cve_id}-poc",
                "estrellas": 15 + hash(cve_id) % 100,
                "forks": 5 + hash(cve_id) % 30,
                "ultima_actualizacion": "2024-08-20",
                "lenguaje": "Python",
                "url": f"https://github.com/poc-repo/{cve_id}",
                "fuente": "MOCK"
            }
        return None
    
    # En producción usar GitHub API con token
    return None

def mapear_att_ck(descripcion, severidad):
    """
    Mapea la vulnerabilidad a tácticas y técnicas MITRE ATT&CK
    Basado en el tipo de vulnerabilidad
    """
    desc_lower = descripcion.lower()
    tactics = []
    
    # Initial Access
    if any(word in desc_lower for word in ["remote", "rce", "exploit", "public-facing"]):
        tactics.append({
            "tactic_id": "TA0001",
            "tactic_name": "Initial Access",
            "techniques": ["T1190 - Exploit Public-Facing Application"]
        })
    
    # Execution
    if any(word in desc_lower for word in ["code execution", "rce", "command"]):
        tactics.append({
            "tactic_id": "TA0002",
            "tactic_name": "Execution",
            "techniques": ["T1059 - Command and Scripting Interpreter"]
        })
    
    # Privilege Escalation
    if any(word in desc_lower for word in ["privilege", "escalation", "elevation"]):
        tactics.append({
            "tactic_id": "TA0004",
            "tactic_name": "Privilege Escalation",
            "techniques": ["T1068 - Exploitation for Privilege Escalation"]
        })
    
    # Credential Access
    if any(word in desc_lower for word in ["credential", "password", "authentication"]):
        tactics.append({
            "tactic_id": "TA0006",
            "tactic_name": "Credential Access",
            "techniques": ["T1110 - Brute Force", "T1555 - Credentials from Password Stores"]
        })
    
    # Impact
    if "denial of service" in desc_lower or "dos" in desc_lower:
        tactics.append({
            "tactic_id": "TA0040",
            "tactic_name": "Impact",
            "techniques": ["T1499 - Endpoint Denial of Service"]
        })
    
    return tactics if tactics else [{
        "tactic_id": "TA0001",
        "tactic_name": "Initial Access",
        "techniques": ["T1190 - Exploit Public-Facing Application"]
    }]

def calcular_prioridad_parcheo(cve_data, epss_data, msf_modulo, exploitdb, github_poc):
    """
    Calcula prioridad de parcheo multi-dimensional
    Score: 0-100 (P0: 90-100, P1: 70-89, P2: 50-69, P3: 30-49, P4: 0-29)
    """
    score = 0
    factores = []
    
    # Factor 1: CVSS Score (30%)
    cvss = cve_data.get("cvss_score", 0)
    score_cvss = (cvss / 10) * 30
    score += score_cvss
    factores.append(f"CVSS: {cvss}/10 → {score_cvss:.1f} pts")
    
    # Factor 2: EPSS Probability (25%)
    if epss_data:
        epss_prob = epss_data.get("epss_score", 0)
        score_epss = epss_prob * 100 * 0.25
        score += score_epss
        factores.append(f"EPSS: {epss_prob:.2%} → {score_epss:.1f} pts")
    else:
        factores.append("EPSS: No disponible → 0 pts")
    
    # Factor 3: Exploit público disponible (20%)
    exploit_publico = 0
    if msf_modulo and msf_modulo != "No encontrado":
        exploit_publico += 20
        factores.append("MSF Module: Sí → 20 pts")
    elif exploitdb:
        exploit_publico += 15
        factores.append("ExploitDB: Sí → 15 pts")
    elif github_poc:
        exploit_publico += 10
        factores.append("GitHub PoC: Sí → 10 pts")
    else:
        factores.append("Exploit público: No → 0 pts")
    score += exploit_publico
    
    # Factor 4: Criticidad del servicio (15%)
    # Simplificado: si es un servicio web o SSH, más crítico
    servicio = cve_data.get("software", "").lower()
    if any(s in servicio for s in ["http", "web", "apache", "nginx"]):
        score_servicio = 15
        factores.append("Criticidad servicio: Web (Alta) → 15 pts")
    elif any(s in servicio for s in ["ssh", "rdp", "database", "sql"]):
        score_servicio = 12
        factores.append("Criticidad servicio: Infraestructura (Alta) → 12 pts")
    else:
        score_servicio = 8
        factores.append("Criticidad servicio: Otro (Media) → 8 pts")
    score += score_servicio
    
    # Factor 5: Facilidad de parcheo (10%)
    # Simplificado: asumimos que parches existen
    score += 8
    factores.append("Facilidad parcheo: Parche disponible → 8 pts")
    
    # Normalizar a 100
    score = min(score, 100)
    
    # Determinar prioridad
    if score >= 90:
        prioridad = "P0"
        descripcion = "CRÍTICO - Parchear inmediatamente"
    elif score >= 70:
        prioridad = "P1"
        descripcion = "ALTO - Parchear en 24-48h"
    elif score >= 50:
        prioridad = "P2"
        descripcion = "MEDIO - Parchear en 7 días"
    elif score >= 30:
        prioridad = "P3"
        descripcion = "BAJO - Parchear en 30 días"
    else:
        prioridad = "P4"
        descripcion = "MÍNIMO - Parchear en próximo ciclo"
    
    return {
        "score_total": round(score, 1),
        "prioridad": prioridad,
        "descripcion": descripcion,
        "factores": factores
    }

def run_agent():
    print(f"\n💥 Agente 11 — Metasploit & Exploit Intelligence (EXPANDIDO)")
    print("   Buscando exploits y calculando prioridades...\n")

    print("   [1/2] Cargando ag7.json (CVEs)...")
    ag7 = load_json("ag7.json")
    
    if not ag7:
        print("   ❌ ag7.json no disponible")
        print("   ℹ️  Generando reporte vacío...")
        resultado = {
            "agent": "AG11_EXPLOIT_INTEL",
            "integrante": 4,
            "recomendaciones": [],
            "disclaimer": "ag7.json no encontrado. No se pudieron buscar exploits.",
            "timestamp": datetime.now(UTC).isoformat()
        }
    else:
        cves = ag7.get("cves_encontrados", [])
        print(f"         CVEs encontrados: {len(cves)}")

        print("\n   [2/2] Analizando exploitabilidad...")
        print(f"         Modo: {'APIs reales' if USE_REAL_APIS else 'Demo/Mock'}")
        
        # Verificar si msfconsole está disponible
        try:
            subprocess.run(["msfconsole", "-v"], capture_output=True, timeout=5)
            msf_available = True
            print("         ✓ msfconsole detectado")
        except:
            msf_available = False
            print("         ⚠️  msfconsole no instalado")

        recomendaciones = []
        
        for i, cve_data in enumerate(cves, 1):
            cve_id = cve_data.get("cve_id", "")
            descripcion = cve_data.get("descripcion", "")
            
            print(f"         [{i}/{len(cves)}] Analizando {cve_id}...")
            
            # Buscar en Metasploit
            modulo_msf = None
            if msf_available:
                modulo_msf = buscar_en_msfconsole(cve_id)
            
            if not modulo_msf:
                modulo_msf = "No encontrado"
            
            # Consultar EPSS
            epss_data = consultar_epss(cve_id)
            
            # Buscar en ExploitDB
            exploitdb_data = buscar_exploitdb(cve_id)
            
            # Buscar PoC en GitHub
            github_poc = buscar_github_poc(cve_id)
            
            # Mapear a MITRE ATT&CK
            att_ck_tactics = mapear_att_ck(descripcion, cve_data.get("severidad", ""))
            
            # Calcular prioridad de parcheo
            prioridad = calcular_prioridad_parcheo(
                cve_data, epss_data, modulo_msf, exploitdb_data, github_poc
            )
            
            # Determinar probabilidad de éxito
            if modulo_msf != "No encontrado":
                prob_exito = "alta"
            elif exploitdb_data or github_poc:
                prob_exito = "media"
            elif epss_data and epss_data.get("epss_score", 0) > 0.5:
                prob_exito = "media"
            else:
                prob_exito = "baja"
            
            # Mitigaciones específicas
            mitigaciones = []
            if "sql" in descripcion.lower():
                mitigaciones.extend([
                    "Aplicar parche del fabricante inmediatamente",
                    "Implementar WAF con reglas anti-SQLi",
                    "Usar consultas parametrizadas",
                    "Principio de mínimo privilegio en DB"
                ])
            elif "buffer overflow" in descripcion.lower():
                mitigaciones.extend([
                    "Actualizar software a versión parchada",
                    "Habilitar DEP (Data Execution Prevention)",
                    "Habilitar ASLR (Address Space Layout Randomization)",
                    "Validar longitud de entrada"
                ])
            elif "xss" in descripcion.lower():
                mitigaciones.extend([
                    "Aplicar parche",
                    "Implementar CSP (Content Security Policy)",
                    "Sanitizar salida HTML",
                    "Usar X-XSS-Protection header"
                ])
            else:
                mitigaciones.extend([
                    f"Actualizar {cve_data.get('software', 'software')} a versión segura",
                    "Aplicar principio de defensa en profundidad",
                    "Monitorear logs para detectar intentos de explotación"
                ])
            
            # Construir recomendación completa
            recomendacion = {
                "cve_id": cve_id,
                "servicio": cve_data.get("software", "desconocido"),
                "version": cve_data.get("version", ""),
                "puerto": cve_data.get("port", ""),
                "cvss_score": cve_data.get("cvss_score", 0),
                "severidad": cve_data.get("severidad", "medium"),
                "modulo_msf": modulo_msf,
                "probabilidad_exito": prob_exito,
                "impacto": cve_data.get("severidad", "medium").lower(),
                "epss": epss_data,
                "exploitdb": exploitdb_data,
                "github_poc": github_poc,
                "att_ck_tactics": att_ck_tactics,
                "prioridad_parcheo": prioridad,
                "mitigaciones": mitigaciones,
                "nota": f"Análisis multi-fuente completado. Prioridad: {prioridad['prioridad']}"
            }
            
            recomendaciones.append(recomendacion)

        # Calcular resumen
        total = len(recomendaciones)
        con_msf = sum(1 for r in recomendaciones if r["modulo_msf"] != "No encontrado")
        con_exploitdb = sum(1 for r in recomendaciones if r["exploitdb"] is not None)
        con_github = sum(1 for r in recomendaciones if r["github_poc"] is not None)
        
        alta_prob = sum(1 for r in recomendaciones if r["probabilidad_exito"] == "alta")
        media_prob = sum(1 for r in recomendaciones if r["probabilidad_exito"] == "media")
        baja_prob = sum(1 for r in recomendaciones if r["probabilidad_exito"] == "baja")
        
        p0 = sum(1 for r in recomendaciones if r["prioridad_parcheo"]["prioridad"] == "P0")
        p1 = sum(1 for r in recomendaciones if r["prioridad_parcheo"]["prioridad"] == "P1")
        p2 = sum(1 for r in recomendaciones if r["prioridad_parcheo"]["prioridad"] == "P2")
        p3 = sum(1 for r in recomendaciones if r["prioridad_parcheo"]["prioridad"] == "P3")
        
        resultado = {
            "agent": "AG11_EXPLOIT_INTEL",
            "integrante": 4,
            "target": ag7.get("target", "desconocido"),
            "modo": "real_apis" if USE_REAL_APIS else "demo",
            "recomendaciones": recomendaciones,
            "resumen": {
                "total_cves": total,
                "con_modulo_msf": con_msf,
                "con_exploitdb": con_exploitdb,
                "con_github_poc": con_github,
                "sin_exploit_publico": total - max(con_msf, con_exploitdb, con_github),
                "alta_probabilidad": alta_prob,
                "media_probabilidad": media_prob,
                "baja_probabilidad": baja_prob,
                "prioridad_p0": p0,
                "prioridad_p1": p1,
                "prioridad_p2": p2,
                "prioridad_p3": p3
            },
            "fuentes_consultadas": [
                "Metasploit Framework" if msf_available else "Metasploit (no disponible)",
                "EPSS - FIRST.org",
                "ExploitDB",
                "GitHub PoC Search",
                "MITRE ATT&CK"
            ],
            "disclaimer": "⚠️ SOLO ANÁLISIS TEÓRICO. NUNCA ejecutar exploits sin autorización explícita por escrito. Este reporte es únicamente para evaluación de riesgo y priorización de parches.",
            "timestamp": datetime.now(UTC).isoformat()
        }

    output_path = os.path.join(
        os.path.dirname(__file__), "..", "shared_data", "ag11.json"
    )
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(resultado, f, indent=2, ensure_ascii=False)

    print(f"\n   ✅ Listo. Guardado en shared_data/ag11.json")
    if resultado.get("recomendaciones"):
        print(f"   📊 Resumen:")
        resumen = resultado["resumen"]
        print(f"      CVEs analizados: {resumen['total_cves']}")
        print(f"      Con módulo MSF: {resumen['con_modulo_msf']}")
        print(f"      Con ExploitDB: {resumen['con_exploitdb']}")
        print(f"      Con GitHub PoC: {resumen['con_github_poc']}")
        print(f"      Prioridad P0 (crítico): {resumen['prioridad_p0']}")
        print(f"      Prioridad P1 (alto): {resumen['prioridad_p1']}")
        print(f"      ⚠️  {resultado['disclaimer'][:80]}...")

    return resultado

if __name__ == "__main__":
    try:
        run_agent()
    except Exception as e:
        print(f"\n❌ ERROR FATAL: {e}")
        import traceback
        traceback.print_exc()
        exit(1)
