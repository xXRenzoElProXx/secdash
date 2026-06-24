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
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        return "TIMEOUT"
    except Exception as e:
        return f"ERROR: {e}"

def get_ip(domain):
    output = run_cmd(f"dig +short A {domain}")
    for line in output.splitlines():
        line = line.strip()
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", line):
            return line
    return "desconocida"

def get_dns_records(domain):
    records = {}
    for rtype in ["A", "MX", "NS", "TXT"]:
        output = run_cmd(f"dig +short {rtype} {domain}")
        records[rtype] = [l.strip() for l in output.splitlines() if l.strip()]
    return records

def get_whois(domain):
    output = run_cmd(f"whois {domain}")
    for line in output.splitlines():
        if "Registrar:" in line or "registrar:" in line:
            return line.split(":", 1)[-1].strip()
    return "desconocido"

def get_subdominios(domain):
    output = run_cmd(f"subfinder -d {domain} -silent -timeout 20")
    if "not found" in output.lower() or "ERROR" in output:
        # Fallback: intentar con dig para subdominios comunes
        comunes = ["www", "mail", "api", "dev", "staging", "ftp", "admin"]
        encontrados = []
        for sub in comunes:
            ip = run_cmd(f"dig +short A {sub}.{domain}")
            if ip.strip():
                encontrados.append(f"{sub}.{domain}")
        return encontrados
    return [l.strip() for l in output.splitlines() if l.strip()]

def analizar_con_ia(domain, ip, dns, subdominios, whois_reg):
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

    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {
            "observaciones": ["No se pudo parsear la respuesta de la IA"],
            "riesgo_exposicion": "desconocido",
            "razon_riesgo": raw[:200],
            "subdominios_criticos": []
        }

def run_agent(target):
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

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Uso: python agent1_discovery.py <dominio>")
        print("Ejemplo: python agent1_discovery.py scanme.nmap.org")
        sys.exit(1)

    target = sys.argv[1]
    run_agent(target)
