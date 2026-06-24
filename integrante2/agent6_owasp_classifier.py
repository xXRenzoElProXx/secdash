#!/usr/bin/env python3

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import requests
except ImportError:
    requests = None

DEFAULT_AG4 = Path("shared_data/ag4.json")
DEFAULT_AG5 = Path("shared_data/ag5.json")
DEFAULT_OUTPUT = Path("shared_data/ag6.json")

OWASP_2021 = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable and Outdated Components",
    "A07": "Identification and Authentication Failures",
    "A08": "Software and Data Integrity Failures",
    "A09": "Security Logging and Monitoring Failures",
    "A10": "Server Side Request Forgery (SSRF)",
}

MITIGACIONES = {
    "A01": "Aplicar controles de autorización por rol (RBAC), validar permisos en servidor, implementar principio de mínimo privilegio y evitar acceso directo a recursos no autorizados.",
    "A02": "Usar TLS 1.2+, cifrado fuerte (AES-256, RSA-2048+), evitar algoritmos obsoletos (DES, MD5, SHA-1), gestión adecuada de claves, certificados X.509 válidos y protección de datos sensibles.",
    "A03": "Validar y sanitizar todas las entradas, usar consultas parametrizadas, codificación de salida, evitar concatenación de datos del usuario, proteger contra buffer overflow con DEP/ASLR.",
    "A04": "Revisar el diseño de seguridad, modelar amenazas (STRIDE), implementar defensa en profundidad y validar reglas de negocio antes de implementar.",
    "A05": "Corregir configuraciones inseguras, deshabilitar funciones innecesarias (Telnet, FTP anónimo), aplicar hardening del servidor, configurar firewalls/ACLs restrictivos, eliminar servicios no críticos.",
    "A06": "Actualizar componentes vulnerables, retirar versiones obsoletas, mantener inventario de dependencias y monitorear CVEs.",
    "A07": "Fortalecer autenticación, sesiones seguras, políticas de contraseñas robustas, MFA, protección contra fuerza bruta y tokens CSRF.",
    "A08": "Verificar integridad de software/datos con hashes criptográficos, firmar artefactos con firmas digitales, controlar fuentes de actualización y validar deserialización.",
    "A09": "Activar logs de seguridad, implementar SIEM, monitoreo con IDS/IPS, alertas y trazabilidad de eventos relevantes.",
    "A10": "Validar destinos de peticiones del servidor, usar listas permitidas, segmentar red y bloquear acceso a redes internas/metadata.",
}

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

def load_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}

def extract_hallazgos(data: Dict[str, Any], fuente: str) -> List[Dict[str, Any]]:
    items = data.get("hallazgos", [])
    if not isinstance(items, list):
        return []

    normalized: List[Dict[str, Any]] = []
    for i, item in enumerate(items, start=1):
        if not isinstance(item, dict):
            continue
        hallazgo_id = item.get("id") or f"{fuente.upper()}-{i:03d}"
        normalized.append({
            "hallazgo_id": str(hallazgo_id),
            "fuente": fuente,
            "descripcion": str(item.get("descripcion") or ""),
            "severidad": str(item.get("severidad") or "N/A"),
            "url_afectada": str(item.get("url_afectada") or data.get("url_escaneada") or "N/A"),
            "template": item.get("template"),
            "cve_id": item.get("cve_id"),
            "raw": item,
        })
    return normalized

def text_for_classification(h: Dict[str, Any]) -> str:
    pieces = [
        h.get("hallazgo_id"),
        h.get("descripcion"),
        h.get("severidad"),
        h.get("url_afectada"),
        h.get("template"),
        h.get("cve_id"),
    ]
    return " ".join(str(p) for p in pieces if p).lower()

def classify_by_rules(h: Dict[str, Any]) -> Tuple[str, str]:
    t = text_for_classification(h)

    rules = [
        ("A10", ["ssrf", "server side request forgery", "metadata", "169.254.169.254"]),
        ("A03", [
            "sql injection", "sqli", "injection", "xss", "cross-site scripting", 
            "command injection", "ssti", "ldap injection", "xml injection",
            "nosql injection", "buffer overflow", "stack overflow", "heap overflow",
            "format string", "code injection", "eval", "unserialize"
        ]),
        ("A01", [
            "broken access", "access control", "idor", "unauthorized", "forbidden bypass", 
            "path traversal", "directory traversal", "../", "admin exposed", 
            "privilege escalation", "authorization", "rbac", "dac", "mac"
        ]),
        ("A02", [
            "ssl", "tls", "cipher", "certificate", "cleartext", "weak crypto", 
            "cryptographic", "https not enforced", "sslv2", "sslv3", "rc4", 
            "des", "md5", "sha1", "weak hash", "expired certificate", 
            "self-signed", "aes", "rsa", "diffie-hellman", "pki", "x509"
        ]),
        ("A06", [
            "cve-", "outdated", "old version", "vulnerable component", "eol", 
            "end of life", "apache/2.4.49", "php/5", "wordpress version",
            "dependency", "library", "framework version"
        ]),
        ("A07", [
            "default password", "default credential", "weak password", "login", 
            "authentication", "session fixation", "brute force", "password policy",
            "multi-factor", "mfa", "2fa", "session management", "csrf token"
        ]),
        ("A08", [
            "deserialization", "integrity", "unsigned", "supply chain", 
            "dependency confusion", "untrusted update", "insecure deserialization",
            "pickle", "yaml load", "hash verification", "digital signature"
        ]),
        ("A09", [
            "log", "logging", "monitoring", "audit", "alert", "siem", 
            "intrusion detection", "ids", "ips", "security event"
        ]),
        ("A04", [
            "business logic", "insecure design", "workflow", "rate limit", 
            "no limit", "threat model", "attack surface", "defense in depth"
        ]),
        ("A05", [
            "header", "x-frame-options", "content-security-policy", "x-content-type-options", 
            "directory indexing", "trace", "options method", "cors", "server-status", 
            "phpinfo", "robots.txt", "config", "misconfiguration", "default page", 
            "information disclosure", "hardening", "firewall", "acl", "unnecessary service",
            "telnet", "ftp anonymous", "debug mode"
        ]),
    ]

    for code, keywords in rules:
        if any(k in t for k in keywords):
            return code, f"Clasificado por coincidencia de palabras clave asociadas a {OWASP_2021[code]}."

    return "A05", "Clasificación por defecto: el hallazgo parece una configuración o exposición web general."

def extract_json_from_text(text: str) -> Optional[Dict[str, Any]]:
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if not match:
        return None
    try:
        return json.loads(match.group(0))
    except json.JSONDecodeError:
        return None

def classify_with_ollama(h: Dict[str, Any], model: str, base_url: str) -> Optional[Dict[str, Any]]:
    if requests is None:
        return None

    prompt = f"""
Eres un analista de seguridad defensiva. Clasifica este hallazgo en OWASP Top 10 2021.
Devuelve SOLO JSON válido con estas claves:
  categoria_owasp: uno de A01,A02,A03,A04,A05,A06,A07,A08,A09,A10
  nombre_categoria: nombre oficial de la categoría
  mitigacion: recomendación defensiva breve en español
  razon: por qué pertenece a esa categoría

Hallazgo:
{json.dumps(h, ensure_ascii=False, indent=2)}
""".strip()

    try:
        response = requests.post(
            f"{base_url.rstrip('/')}/api/chat",
            json={
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "stream": False,
                "options": {"temperature": 0.1},
            },
            timeout=45,
        )
        response.raise_for_status()
        content = response.json().get("message", {}).get("content", "")
        parsed = extract_json_from_text(content)
        if not parsed:
            return None
        code = str(parsed.get("categoria_owasp", "")).upper().strip()
        if code not in OWASP_2021:
            return None
        return {
            "categoria_owasp": code,
            "nombre_categoria": OWASP_2021[code],
            "mitigacion": str(parsed.get("mitigacion") or MITIGACIONES[code]),
            "razon": str(parsed.get("razon") or "Clasificación realizada con Ollama."),
            "clasificador": "ollama",
        }
    except Exception:
        return None

def classify_hallazgo(h: Dict[str, Any], use_ollama: bool, model: str, base_url: str) -> Dict[str, Any]:
    if use_ollama:
        ai_result = classify_with_ollama(h, model, base_url)
        if ai_result:
            code = ai_result["categoria_owasp"]
            return {
                "hallazgo_id": h["hallazgo_id"],
                "fuente": h["fuente"],
                "categoria_owasp": code,
                "nombre_categoria": ai_result["nombre_categoria"],
                "mitigacion": ai_result["mitigacion"],
                "razon": ai_result["razon"],
                "url_afectada": h["url_afectada"],
                "severidad": h["severidad"],
                "clasificador": ai_result["clasificador"],
            }

    code, reason = classify_by_rules(h)
    return {
        "hallazgo_id": h["hallazgo_id"],
        "fuente": h["fuente"],
        "categoria_owasp": code,
        "nombre_categoria": OWASP_2021[code],
        "mitigacion": MITIGACIONES[code],
        "razon": reason,
        "url_afectada": h["url_afectada"],
        "severidad": h["severidad"],
        "clasificador": "reglas_locales",
    }

def build_heatmap(clasificaciones: List[Dict[str, Any]]) -> Dict[str, int]:
    heatmap = {code: 0 for code in OWASP_2021}
    for c in clasificaciones:
        code = c.get("categoria_owasp")
        if code in heatmap:
            heatmap[code] += 1
    return heatmap

def main() -> int:
    parser = argparse.ArgumentParser(description="Agente 06 - Clasificador OWASP Top 10 2021")
    parser.add_argument("--ag4", default=str(DEFAULT_AG4), help="Ruta de ag4.json")
    parser.add_argument("--ag5", default=str(DEFAULT_AG5), help="Ruta de ag5.json")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT), help="Ruta de salida ag6.json")
    parser.add_argument("--use-ollama", action="store_true", help="Usar Ollama local para clasificar; si falla, usa reglas")
    parser.add_argument("--ollama-model", default=os.getenv("SECDASH_AI_MODEL", "minimax-m3:cloud"), help="Modelo local de Ollama (SecDash)")
    parser.add_argument("--ollama-url", default=os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"), help="URL base de Ollama")
    args = parser.parse_args()

    ag4 = load_json(Path(args.ag4))
    ag5 = load_json(Path(args.ag5))

    hallazgos = []
    hallazgos.extend(extract_hallazgos(ag4, "ag4"))
    hallazgos.extend(extract_hallazgos(ag5, "ag5"))

    clasificaciones = [
        classify_hallazgo(h, args.use_ollama, args.ollama_model, args.ollama_url)
        for h in hallazgos
    ]

    result = {
        "agente": "Agente 06 - OWASP Classifier",
        "framework": "OWASP Top 10 2021",
        "clasificaciones": clasificaciones,
        "heatmap_owasp": build_heatmap(clasificaciones),
        "total_clasificados": len(clasificaciones),
        "fuentes": [str(args.ag4), str(args.ag5)],
        "nota": "El Agente 6 solo clasifica hallazgos; no ejecuta escaneos ni calcula score de riesgo.",
        "timestamp": now_iso(),
    }

    output = Path(args.output)
    ensure_parent(output)
    output.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"[Agente 6] OK -> {output} ({result['total_clasificados']} clasificaciones)")
    return 0

if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"[Agente 6] ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)