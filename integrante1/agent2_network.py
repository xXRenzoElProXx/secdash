"""
AGENTE 2 — Network Exposure
Integrante 1

Qué hace:
  Lee la IP del ag1.json, corre nmap para detectar puertos
  abiertos, servicios y versiones de software.

Salida: shared_data/ag2.json
"""

import json
import subprocess
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


# ─── Escaneo nmap ────────────────────────────────────────────────────────────

def run_nmap(ip):
    """
    Corre nmap con detección de versiones, OS y scripts NSE de seguridad.
    Incluye detección de firewall/IDS.
    """
    print(f"   Ejecutando nmap sobre {ip}...")
    print("   (puede tardar 1-2 minutos)")

    # Escaneo completo: versiones + OS + scripts de seguridad + detección firewall
    cmd = f"nmap -sV -O --script=banner,ssl-cert,ssh-auth-methods,firewall-bypass --open -T4 {ip}"
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=180
        )
        return result.stdout
    except subprocess.TimeoutExpired:
        return "TIMEOUT: nmap tardó demasiado"
    except Exception as e:
        return f"ERROR: {e}"


def run_nmap_os(ip):
    """Intenta detección de OS (requiere sudo)."""
    cmd = f"sudo nmap -O --osscan-guess {ip} 2>/dev/null | grep -i 'os\\|running'"
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=60
        )
        return result.stdout.strip() or "No detectado"
    except:
        return "No detectado (requiere sudo)"


# ─── IA: parsear output de nmap ──────────────────────────────────────────────

def parsear_nmap_con_ia(ip, nmap_output):
    """
    Le pasa el output de nmap a la IA para que lo convierta a JSON estructurado.
    Incluye análisis de firewall, IDS y configuración de seguridad.
    """
    prompt = f"""Analiza este output de nmap y devuelve SOLO un JSON válido con esta estructura exacta:
{{
  "ip": "{ip}",
  "puertos_abiertos": [
    {{
      "port": 80,
      "protocol": "tcp",
      "state": "open",
      "service": "http",
      "version": "nginx 1.18.0",
      "banner": "nginx/1.18.0"
    }}
  ],
  "os_detected": "Linux 4.x / Windows Server 2019 / etc",
  "firewall_ids_detection": {{
    "firewall_present": true,
    "ids_ips_detected": false,
    "filtered_ports": 5,
    "evidence": "varios puertos filtrados detectados"
  }},
  "ssl_tls_services": [
    {{
      "port": 443,
      "protocol": "TLSv1.2",
      "cipher": "AES256-GCM-SHA384",
      "certificate_valid": true
    }}
  ],
  "security_issues": [
    "SSH con autenticación por contraseña habilitada",
    "Servicio Telnet expuesto (puerto 23)"
  ],
  "resumen": "descripción breve de lo encontrado"
}}

Output de nmap:
{nmap_output[:3000]}

Responde SOLO con el JSON, sin texto adicional ni markdown."""

    response = ai.chat.completions.create(
        model=AI_MODEL,
        messages=[{"role": "user", "content": prompt}],
        temperature=0.1,
    )
    raw = response.choices[0].message.content.strip()
    raw = re.sub(r"```json|```", "", raw).strip()

    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        # Fallback: parseo manual básico
        return parsear_nmap_manual(ip, nmap_output)


def parsear_nmap_manual(ip, nmap_output):
    """Parseo de respaldo si la IA falla."""
    services = []
    for line in nmap_output.splitlines():
        # Línea típica: "80/tcp   open  http    nginx 1.18.0"
        match = re.match(r"(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)", line)
        if match:
            services.append({
                "port": int(match.group(1)),
                "protocol": match.group(2),
                "state": "open",
                "service": match.group(3),
                "version": match.group(4).strip()
            })
    return {
        "ip": ip,
        "puertos_abiertos": services,
        "os_detected": "No detectado",
        "resumen": f"{len(services)} puertos abiertos encontrados"
    }


# ─── Agente principal ────────────────────────────────────────────────────────

def run_agent():
    print(f"\n🖧 Agente 2 — Network Exposure")

    # 1. Leer IP del Agente 1
    ag1_path = os.path.join(
        os.path.dirname(__file__), "..", "shared_data", "ag1.json"
    )

    if not os.path.exists(ag1_path):
        print("   ⚠ No se encontró ag1.json. Usando IP de ejemplo.")
        ip = "scanme.nmap.org"
        target = ip
    else:
        with open(ag1_path) as f:
            ag1 = json.load(f)
        ip = ag1.get("ip", "scanme.nmap.org")
        target = ag1.get("target", ip)
        print(f"   Leyó ag1.json → IP: {ip}")

    # 2. Correr nmap
    nmap_output = run_nmap(ip)

    if "ERROR" in nmap_output or "TIMEOUT" in nmap_output:
        print(f"   ❌ Error en nmap: {nmap_output}")
        print("   Generando resultado vacío...")
        parsed = {"ip": ip, "puertos_abiertos": [], "os_detected": "Error", "resumen": nmap_output}
    else:
        # 3. Parsear con IA
        print("   🤖 Parseando output con IA...")
        parsed = parsear_nmap_con_ia(ip, nmap_output)

    # 4. Construir JSON de salida
    resultado = {
        "target": target,
        "ip": ip,
        "services": parsed.get("puertos_abiertos", []),
        "os_detected": parsed.get("os_detected", "desconocido"),
        "firewall_ids_detection": parsed.get("firewall_ids_detection", {
            "firewall_present": False,
            "ids_ips_detected": False,
            "filtered_ports": 0,
            "evidence": "No detectado"
        }),
        "ssl_tls_services": parsed.get("ssl_tls_services", []),
        "security_issues": parsed.get("security_issues", []),
        "resumen": parsed.get("resumen", ""),
        "timestamp": datetime.now(UTC).isoformat()    
     }

    # 5. Guardar
    output_path = os.path.join(
        os.path.dirname(__file__), "..", "shared_data", "ag2.json"
    )
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(resultado, f, indent=2, ensure_ascii=False)

    print(f"\n   ✅ Listo. Guardado en shared_data/ag2.json")
    print(f"   📊 Resumen:")
    print(f"      IP: {ip}")
    print(f"      OS: {resultado['os_detected']}")
    print(f"      Puertos abiertos: {len(resultado['services'])}")
    
    # Mostrar firewall/IDS detection
    fw_data = resultado.get('firewall_ids_detection', {})
    if fw_data.get('firewall_present'):
        print(f"      🔥 Firewall detectado: {fw_data.get('evidence', 'Sí')}")
    if fw_data.get('ids_ips_detected'):
        print(f"      🚨 IDS/IPS detectado")
    
    # Mostrar servicios SSL/TLS
    ssl_services = resultado.get('ssl_tls_services', [])
    if ssl_services:
        print(f"      🔐 Servicios SSL/TLS: {len(ssl_services)}")
    
    # Mostrar issues de seguridad
    issues = resultado.get('security_issues', [])
    if issues:
        print(f"      ⚠️ Issues de seguridad: {len(issues)}")
    
    for s in resultado["services"][:5]:
        print(f"        → {s['port']}/{s['protocol']} {s['service']} {s.get('version','')}")
    if len(resultado["services"]) > 5:
        print(f"        ... y {len(resultado['services'])-5} más")

    return resultado


if __name__ == "__main__":
    run_agent()
