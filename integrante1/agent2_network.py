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

def run_nmap(ip):
    print(f"   Ejecutando nmap sobre {ip}...")
    print("   (puede tardar 1-2 minutos)")

    # Primero intenta con modo rápido (-T5 es máximo speed)
    cmd = f"nmap -sV --open -T5 --max-retries 1 {ip}"
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=120
        )
        if result.returncode == 0:
            return result.stdout
        else:
            return f"ERROR: {result.stderr}"
    except subprocess.TimeoutExpired:
        print("   ⚠️ nmap tardo > 2min. Intentando modo más rápido...")
        return "TIMEOUT"
    except Exception as e:
        return f"ERROR: {e}"

def run_nmap_os(ip):
    cmd = f"sudo nmap -O --osscan-guess {ip} 2>/dev/null | grep -i 'os\\|running'"
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=60
        )
        return result.stdout.strip() or "No detectado"
    except:
        return "No detectado (requiere sudo)"

def parsear_nmap_con_ia(ip, nmap_output):
    # Si nmap no retorna nada, usar fallback
    if not nmap_output or len(nmap_output) < 50:
        return parsear_nmap_manual(ip, nmap_output)
    
    try:
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

        return json.loads(raw)
    except Exception as e:
        # Fallback a parseador manual si IA falla
        print(f"   ⚠️ IA falló: {str(e)[:50]}. Usando parser manual...")
        return parsear_nmap_manual(ip, nmap_output)

def parsear_nmap_manual(ip, nmap_output):
    services = []
    for line in nmap_output.splitlines():
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

def run_agent():
    try:
        print(f"\n🖧 Agente 2 — Network Exposure")

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

        nmap_output = run_nmap(ip)

        if "ERROR" in nmap_output or "TIMEOUT" in nmap_output:
            print(f"   ⚠️ nmap falló: {nmap_output[:100]}")
            print("   Generando resultado básico sin escaneo profundo...")
            parsed = {"ip": ip, "puertos_abiertos": [], "os_detected": "Timeout/Error", "resumen": "Escaneo de nmap no disponible"}
        else:
            print("   🤖 Parseando output con IA...")
            parsed = parsear_nmap_con_ia(ip, nmap_output)

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
        
        fw_data = resultado.get('firewall_ids_detection', {})
        if fw_data.get('firewall_present'):
            print(f"      🔥 Firewall detectado: {fw_data.get('evidence', 'Sí')}")
        if fw_data.get('ids_ips_detected'):
            print(f"      🚨 IDS/IPS detectado")
        
        ssl_services = resultado.get('ssl_tls_services', [])
        if ssl_services:
            print(f"      🔐 Servicios SSL/TLS: {len(ssl_services)}")
        
        issues = resultado.get('security_issues', [])
        if issues:
            print(f"      ⚠️ Issues de seguridad: {len(issues)}")
        
        for s in resultado["services"][:5]:
            print(f"        → {s['port']}/{s['protocol']} {s['service']} {s.get('version','')}")
        if len(resultado["services"]) > 5:
            print(f"        ... y {len(resultado['services'])-5} más")

        return resultado
    
    except Exception as e:
        # Fallback: generar ag2.json con error para no bloquear el pipeline
        print(f"   ❌ Error en AG2: {str(e)}")
        
        resultado = {
            "target": "desconocido",
            "ip": "error",
            "services": [],
            "os_detected": "error",
            "firewall_ids_detection": {},
            "ssl_tls_services": [],
            "security_issues": [f"Error durante ejecución: {str(e)}"],
            "resumen": "Agente falló",
            "timestamp": datetime.now(UTC).isoformat(),
            "error": str(e)
        }
        
        output_path = os.path.join(
            os.path.dirname(__file__), "..", "shared_data", "ag2.json"
        )
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(resultado, f, indent=2, ensure_ascii=False)
        
        print(f"   📁 Error JSON guardado en shared_data/ag2.json")
        raise

if __name__ == "__main__":
    run_agent()
