import json
import subprocess
import os
import re
import time
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

# Configuración desde variables de entorno
SCAN_TYPE = os.getenv("SCAN_TYPE", "fast")  # "fast" o "full"
TIMEOUT_FAST = int(os.getenv("TIMEOUT_FAST", "180"))
TIMEOUT_ULTRA = int(os.getenv("TIMEOUT_ULTRA", "60"))
TIMEOUT_FULL = int(os.getenv("TIMEOUT_FULL", "300"))

def run_nmap(ip):
    """Ejecuta nmap con estrategia de fases para garantizar resultados rápidos."""
    print(f"   Ejecutando nmap sobre {ip}...")

    if SCAN_TYPE == "full":
        cmd = f"nmap -sV --open -T4 --max-retries 1 -p- {ip}"
        print(f"   Comando (full): {cmd}")
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=TIMEOUT_FULL)
            if result.returncode == 0 and len(result.stdout) > 100:
                return result.stdout
            cmd_pn = f"nmap -sV --open -T4 --max-retries 1 -Pn -p- {ip}"
            result = subprocess.run(cmd_pn, shell=True, capture_output=True, text=True, timeout=TIMEOUT_FULL)
            if result.returncode == 0:
                return result.stdout
        except subprocess.TimeoutExpired:
            print(f"   ⚠️ Escaneo completo agotó {TIMEOUT_FULL}s.")
        except Exception as e:
            return f"ERROR: {e}"
        return "ERROR: No se pudo completar escaneo completo"

    # Escaneo rápido (top 1000 puertos)
    cmd = f"nmap -sV --open -T4 --max-retries 2 --top-ports 1000 {ip}"
    print(f"   Comando (fast): {cmd}")
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=TIMEOUT_FAST)
        if result.returncode == 0 and len(result.stdout) > 100:
            return result.stdout
    except subprocess.TimeoutExpired:
        print(f"   ⚠️ Escaneo rápido agotó {TIMEOUT_FAST}s.")
    except Exception as e:
        print(f"   ⚠️ Error en escaneo rápido: {e}")

    # Reintento con -Pn
    print("   Reintentando con -Pn (sin ping)...")
    cmd_pn = f"nmap -sV --open -T4 --max-retries 2 -Pn --top-ports 1000 {ip}"
    try:
        result = subprocess.run(cmd_pn, shell=True, capture_output=True, text=True, timeout=TIMEOUT_FAST)
        if result.returncode == 0 and len(result.stdout) > 100:
            return result.stdout
    except subprocess.TimeoutExpired:
        print(f"   ⚠️ Escaneo rápido con -Pn agotó {TIMEOUT_FAST}s.")
    except Exception as e:
        print(f"   ⚠️ Error en escaneo rápido con -Pn: {e}")

    # Último recurso: top 100 puertos
    print("   Intentando escaneo ultra rápido (top 100 puertos)...")
    cmd_ultra = f"nmap -sV --open -T5 --max-retries 1 -F {ip}"
    try:
        result = subprocess.run(cmd_ultra, shell=True, capture_output=True, text=True, timeout=TIMEOUT_ULTRA)
        if result.returncode == 0 and len(result.stdout) > 50:
            return result.stdout
    except subprocess.TimeoutExpired:
        print(f"   ⚠️ Escaneo ultra rápido agotó {TIMEOUT_ULTRA}s.")
    except Exception as e:
        print(f"   ⚠️ Error en escaneo ultra rápido: {e}")

    return "ERROR: No se pudo obtener respuesta de nmap con ninguna estrategia"

def run_nmap_os(ip):
    """Detecta SO (opcional, no se usa en el flujo principal)"""
    cmd = f"sudo nmap -O --osscan-guess {ip} 2>/dev/null | grep -i 'os\\|running'"
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
        return result.stdout.strip() or "No detectado"
    except:
        return "No detectado (requiere sudo)"

def parsear_nmap_manual(ip, nmap_output):
    """Parseo manual mejorado con extracción de banners y versiones."""
    services = []
    os_detected = "No detectado"
    for line in nmap_output.splitlines():
        match = re.match(r"^(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)$", line)
        if match:
            port = int(match.group(1))
            protocol = match.group(2)
            service = match.group(3)
            version = match.group(4).strip()
            banner = ""
            if "(" in version and ")" in version:
                banner = version[version.find("(")+1:version.find(")")]
            elif version:
                banner = version
            services.append({
                "port": port,
                "protocol": protocol,
                "state": "open",
                "service": service,
                "version": version,
                "banner": banner if banner else version
            })
    for line in nmap_output.splitlines():
        if "OS details" in line or "Running" in line:
            os_detected = line.strip()
            break
    return {
        "ip": ip,
        "puertos_abiertos": services,
        "os_detected": os_detected,
        "resumen": f"{len(services)} puertos abiertos encontrados (parseo manual)"
    }

def parsear_nmap_con_ia(ip, nmap_output):
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
        print(f"   ⚠️ IA falló: {str(e)[:50]}. Usando parser manual...")
        return parsear_nmap_manual(ip, nmap_output)

def run_agent():
    try:
        print(f"\n🖧 Agente 2 — Network Exposure")

        # Rutas absolutas
        base_dir = os.path.dirname(os.path.abspath(__file__))
        shared_dir = os.path.join(base_dir, "..", "shared_data")
        ag1_path = os.path.join(shared_dir, "ag1.json")

        # Esperar hasta que ag1.json exista (máximo 5 intentos)
        ag1 = None
        for intento in range(5):
            if os.path.exists(ag1_path):
                try:
                    with open(ag1_path, 'r', encoding='utf-8') as f:
                        ag1 = json.load(f)
                    print(f"   ✅ Leído ag1.json (intento {intento+1})")
                    break
                except Exception as e:
                    print(f"   ⚠️ Error al leer ag1.json: {e}")
                    ag1 = None
                    break
            else:
                print(f"   ⏳ Esperando ag1.json... (intento {intento+1}/5)")
                time.sleep(2)

        if ag1:
            ip = ag1.get("ip")
            target = ag1.get("target")
            if not ip:
                print("   ⚠️ ag1.json no contiene IP. Usando fallback.")
                ip = "scanme.nmap.org"
                target = ip
            else:
                print(f"   📡 IP obtenida: {ip}, Target: {target}")
        else:
            ip = "scanme.nmap.org"
            target = ip
            print(f"   ⚠️ Usando fallback: {ip}")

        # Ejecutar nmap
        nmap_output = run_nmap(ip)

        if "ERROR" in nmap_output:
            print(f"   ⚠️ nmap falló: {nmap_output[:100]}")
            parsed = {
                "ip": ip,
                "puertos_abiertos": [],
                "os_detected": "Error en escaneo",
                "resumen": f"Escaneo no disponible: {nmap_output}"
            }
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

        output_path = os.path.join(shared_dir, "ag2.json")
        os.makedirs(shared_dir, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(resultado, f, indent=2, ensure_ascii=False)

        print(f"\n   ✅ Listo. Guardado en {output_path}")
        print(f"   📊 Resumen:")
        print(f"      Target: {target}")
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
            banner = s.get('banner', s.get('version', ''))
            print(f"        → {s['port']}/{s['protocol']} {s['service']} {banner}")
        if len(resultado["services"]) > 5:
            print(f"        ... y {len(resultado['services'])-5} más")

        return resultado

    except Exception as e:
        print(f"   ❌ Error en AG2: {str(e)}")
        resultado = {
            "target": target if 'target' in locals() else "desconocido",
            "ip": ip if 'ip' in locals() else "error",
            "services": [],
            "os_detected": "error",
            "firewall_ids_detection": {},
            "ssl_tls_services": [],
            "security_issues": [f"Error durante ejecución: {str(e)}"],
            "resumen": "Agente falló",
            "timestamp": datetime.now(UTC).isoformat(),
            "error": str(e)
        }
        output_path = os.path.join(shared_dir, "ag2.json")
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(resultado, f, indent=2, ensure_ascii=False)
        print(f"   📁 Error JSON guardado en {output_path}")
        return resultado

if __name__ == "__main__":
    run_agent()