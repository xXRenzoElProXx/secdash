import json
import subprocess
import os
import re
from datetime import datetime, UTC
from dotenv import load_dotenv

load_dotenv()

USE_OLLAMA = True
AI_MODEL = os.getenv("SECDASH_AI_MODEL", "minimax-m3:cloud")

if USE_OLLAMA:
    from openai import OpenAI
    ai = OpenAI(
        base_url=os.getenv("OLLAMA_BASE_URL", "http://localhost:11434/v1"),
        api_key=os.getenv("OLLAMA_API_KEY", "ollama"),
    )
else:
    from openai import OpenAI
    ai = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

def run_cmd(cmd):
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=30
        )
        # Validar que el comando realmente funcionó
        if result.returncode != 0:
            return f"ERROR: {result.stderr}"
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        return "TIMEOUT"
    except Exception as e:
        return f"ERROR: {e}"

def get_ip(domain):
    import socket
    # Intentar con dig
    output = run_cmd(f"dig +short A {domain}")
    if "ERROR" not in output and "TIMEOUT" not in output:
        for line in output.splitlines():
            line = line.strip()
            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", line):
                return line
    
    # Fallback: socket.gethostbyname()
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except Exception as e:
        return "desconocida"

def get_dns_records(domain):
    records = {}
    for rtype in ["A", "MX", "NS", "TXT"]:
        output = run_cmd(f"dig +short {rtype} {domain}")
        # Filtrar líneas de error/timeout y comentarios
        lines = [l.strip() for l in output.splitlines() 
                 if l.strip() and not l.startswith(';') 
                 and 'ERROR' not in l and 'TIMEOUT' not in l]
        records[rtype] = lines
    return records

def get_whois(domain):
    output = run_cmd(f"whois {domain}")
    if "ERROR" not in output and "TIMEOUT" not in output:
        for line in output.splitlines():
            if "Registrar:" in line or "registrar:" in line:
                return line.split(":", 1)[-1].strip()
    return "no_disponible"

def get_subdominios(domain):
    output = run_cmd(f"subfinder -d {domain} -silent -timeout 20")
    if "not found" not in output.lower() and "ERROR" not in output and "TIMEOUT" not in output:
        results = [l.strip() for l in output.splitlines() if l.strip()]
        if results:
            return results
    
    # Fallback: intentar con dig para subdominios comunes
    comunes = ["www", "mail", "api", "dev", "staging", "ftp", "admin", "ns1", "ns2"]
    encontrados = []
    for sub in comunes:
        ip = run_cmd(f"dig +short A {sub}.{domain}")
        if ip.strip() and "ERROR" not in ip and "TIMEOUT" not in ip and re.match(r"^\d", ip):
            encontrados.append(f"{sub}.{domain}")
    return encontrados

def check_ollama_available():
    """Verifica si Ollama está disponible"""
    try:
        ai.models.list()
        return True
    except Exception:
        return False

def analisis_basico(domain, ip, dns, subdominios, whois_reg):
    """Análisis básico sin IA"""
    riesgo = "bajo"
    observaciones = []
    
    # Contar subdominios
    num_subdominios = len(subdominios)
    if num_subdominios > 10:
        riesgo = "alto"
        observaciones.append(f"Se encontraron {num_subdominios} subdominios (indicador de superficie de ataque amplia)")
    elif num_subdominios > 5:
        riesgo = "medio"
        observaciones.append(f"Se encontraron {num_subdominios} subdominios")
    
    # Contar registros MX (correo)
    num_mx = len(dns.get("MX", []))
    if num_mx > 0:
        observaciones.append(f"Correo configurado ({num_mx} registros MX)")
    
    # Validar IP
    if ip == "desconocida":
        riesgo = "desconocido"
        observaciones.append("No se pudo resolver la IP del dominio")
    else:
        observaciones.append(f"Dominio resuelve a {ip}")
    
    # WHOIS
    if whois_reg != "no_disponible":
        observaciones.append(f"Registrador: {whois_reg}")
    
    return {
        "observaciones": observaciones or ["Análisis completado sin IA"],
        "riesgo_exposicion": riesgo,
        "razon_riesgo": "Análisis básico (IA no disponible)",
        "subdominios_criticos": subdominios[:3] if subdominios else []
    }

def analizar_con_ia(domain, ip, dns, subdominios, whois_reg):
    """Intenta análisis con IA, fallback a análisis básico"""
    if not check_ollama_available():
        return analisis_basico(domain, ip, dns, subdominios, whois_reg)
    
    try:
        contexto = f"""
Dominio: {domain}
IP: {ip}
Registrar WHOIS: {whois_reg}
DNS Records: {json.dumps(dns, indent=2)}
Subdominios encontrados: {subdominios}
"""
        prompt = f"""Eres un analista de reconocimiento pasivo.
Analiza estos datos de un dominio y devuelve SOLO un JSON válido con esta estructura:
{{
  "observaciones": ["observación 1", "observación 2"],
  "riesgo_exposicion": "bajo|medio|alto",
  "razon_riesgo": "explicación breve",
  "subdominios_criticos": ["sub1", "sub2"]
}}

Datos:
{contexto}

Responde SOLO con el JSON, sin texto adicional."""

        response = ai.chat.completions.create(
            model=AI_MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2,
        )
        raw = response.choices[0].message.content.strip()
        raw = re.sub(r"```json|```", "", raw).strip()
        return json.loads(raw)
    except Exception as e:
        # Fallback a análisis básico si IA falla
        return analisis_basico(domain, ip, dns, subdominios, whois_reg)

def run_agent(target):
    try:
        print(f"\n🔍 Agente 1 — Asset Discovery")
        print(f"   Objetivo: {target}")
        print("   Iniciando reconocimiento pasivo...\n")

        print("   [1/4] Resolviendo IP...")
        ip = get_ip(target)
        print(f"         IP: {ip}")

        print("   [2/4] Obteniendo registros DNS...")
        dns = get_dns_records(target)

        print("   [3/4] Buscando subdominios...")
        subdominios = get_subdominios(target)
        print(f"         Encontrados: {len(subdominios)}")

        print("   [4/4] Consultando WHOIS...")
        whois_reg = get_whois(target)

        print("\n   🤖 Analizando con IA...")
        analisis_ia = analizar_con_ia(target, ip, dns, subdominios, whois_reg)

        resultado = {
            "target": target,
            "ip": ip,
            "dns": dns,
            "subdominios": subdominios,
            "whois_registrar": whois_reg,
            "analisis_ia": analisis_ia,
            "timestamp": datetime.now(UTC).isoformat()
        }

        output_path = os.path.join(
            os.path.dirname(__file__), "..", "shared_data", "ag1.json"
        )
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(resultado, f, indent=2, ensure_ascii=False)

        print(f"\n   ✅ Listo. Guardado en shared_data/ag1.json")
        print(f"   📊 Resumen:")
        print(f"      IP: {ip}")
        print(f"      Subdominios: {len(subdominios)}")
        print(f"      Riesgo según IA: {analisis_ia.get('riesgo_exposicion','?')}")
        print(f"      Razón: {analisis_ia.get('razon_riesgo','?')}")

        return resultado
    
    except Exception as e:
        # Fallback: generar ag1.json con error para no bloquear el pipeline
        print(f"   ❌ Error en AG1: {str(e)}")
        
        resultado = {
            "target": target,
            "ip": "error",
            "dns": {},
            "subdominios": [],
            "whois_registrar": "error",
            "analisis_ia": {
                "observaciones": [f"Error durante ejecución: {str(e)}"],
                "riesgo_exposicion": "desconocido",
                "razon_riesgo": "Agente falló",
                "subdominios_criticos": []
            },
            "timestamp": datetime.now(UTC).isoformat(),
            "error": str(e)
        }
        
        output_path = os.path.join(
            os.path.dirname(__file__), "..", "shared_data", "ag1.json"
        )
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(resultado, f, indent=2, ensure_ascii=False)
        
        print(f"   📁 Error JSON guardado en shared_data/ag1.json")
        raise

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Uso: python agent1_discovery.py <dominio>")
        print("Ejemplo: python agent1_discovery.py scanme.nmap.org")
        sys.exit(1)

    target = sys.argv[1]
    run_agent(target)
