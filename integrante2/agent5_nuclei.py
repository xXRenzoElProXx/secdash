#!/usr/bin/env python3
"""
Agente 05 - Template Scanner
Ejecuta Nuclei sobre una URL autorizada y genera shared_data/ag5.json.

Uso seguro:
  python3 agent5_nuclei.py --url http://TU-LAB --i-have-permission
  python3 agent5_nuclei.py --from-file nuclei_out.jsonl
  python3 agent5_nuclei.py --mock
"""

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse


DEFAULT_OUTPUT = Path("shared_data/ag5.json")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def validate_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("La URL debe empezar con http:// o https:// y tener dominio/IP.")
    return url.rstrip("/")


def first_value(d: Dict[str, Any], keys: List[str]) -> Optional[Any]:
    for k in keys:
        if k in d and d[k] not in (None, "", []):
            return d[k]
    return None


def extract_cve(item: Dict[str, Any]) -> Optional[str]:
    info = item.get("info") if isinstance(item.get("info"), dict) else {}
    classification = info.get("classification") if isinstance(info.get("classification"), dict) else {}

    candidates: List[Any] = [
        item.get("cve_id"),
        item.get("cve-id"),
        classification.get("cve-id"),
        classification.get("cve_id"),
        info.get("cve-id"),
        item.get("template-id"),
        item.get("template"),
        info.get("tags"),
    ]

    text = " ".join(str(c) for c in candidates if c)
    match = re.search(r"CVE-\d{4}-\d{4,7}", text, re.IGNORECASE)
    return match.group(0).upper() if match else None


def normalize_nuclei_item(item: Dict[str, Any], idx: int) -> Dict[str, Any]:
    info = item.get("info") if isinstance(item.get("info"), dict) else {}

    template = first_value(item, ["template-id", "template", "templateID", "id"]) or f"template-{idx:03d}"
    severidad = (first_value(info, ["severity"]) or first_value(item, ["severity"]) or "info").upper()
    descripcion = (
        first_value(info, ["description", "name"])
        or first_value(item, ["description", "name", "matcher-name"])
        or "Hallazgo detectado por Nuclei"
    )
    url_afectada = first_value(item, ["matched-at", "url", "host", "ip"]) or "N/A"

    return {
        "id": f"NUCLEI-{idx:03d}",
        "template": str(template),
        "cve_id": extract_cve(item),
        "severidad": str(severidad),
        "descripcion": str(descripcion).strip(),
        "url_afectada": str(url_afectada),
        "evidencia": {
            "matcher": item.get("matcher-name"),
            "type": item.get("type"),
            "extracted_results": item.get("extracted-results"),
        },
    }


def parse_nuclei_file(path: Path) -> List[Dict[str, Any]]:
    raw = path.read_text(encoding="utf-8", errors="ignore")
    hallazgos: List[Dict[str, Any]] = []

    # Nuclei suele usar JSONL: una línea JSON por hallazgo.
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
            if isinstance(item, dict):
                hallazgos.append(normalize_nuclei_item(item, len(hallazgos) + 1))
        except json.JSONDecodeError:
            continue

    if hallazgos:
        return hallazgos

    # Fallback por si el archivo vino como JSON completo.
    try:
        data = json.loads(raw)
        if isinstance(data, list):
            return [normalize_nuclei_item(x, i) for i, x in enumerate(data, start=1) if isinstance(x, dict)]
        if isinstance(data, dict):
            possible = data.get("results") or data.get("findings") or []
            if isinstance(possible, list):
                return [normalize_nuclei_item(x, i) for i, x in enumerate(possible, start=1) if isinstance(x, dict)]
            return [normalize_nuclei_item(data, 1)]
    except json.JSONDecodeError:
        return []

    return []


def run_nuclei(url: str, severities: str, timeout: int) -> Path:
    if not shutil.which("nuclei"):
        raise RuntimeError("Nuclei no está instalado o no está en PATH. Instálalo y ejecuta: nuclei -update-templates")

    tmp = Path(tempfile.gettempdir()) / f"nuclei_out_{abs(hash(url))}.jsonl"

    # En versiones nuevas se recomienda JSONL. Si falla, reintentamos con -json por compatibilidad.
    commands = [
        ["nuclei", "-u", url, "-severity", severities, "-jsonl", "-o", str(tmp), "-silent"],
        ["nuclei", "-u", url, "-severity", severities, "-json", "-o", str(tmp), "-silent"],
    ]

    last_error = ""
    for cmd in commands:
        print(f"[Agente 5] Ejecutando: {' '.join(cmd)}")
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        if tmp.exists():
            return tmp
        last_error = f"STDERR:\n{completed.stderr}\nSTDOUT:\n{completed.stdout}"

    raise RuntimeError("Nuclei falló y no generó salida.\n" + last_error)


def build_result(url: str, hallazgos: List[Dict[str, Any]], mode: str) -> Dict[str, Any]:
    return {
        "agente": "Agente 05 - Template Scanner",
        "url_escaneada": url,
        "herramienta": "nuclei",
        "modo": mode,
        "hallazgos": hallazgos,
        "total_hallazgos": len(hallazgos),
        "timestamp": now_iso(),
    }


def mock_result() -> Dict[str, Any]:
    # Leer la IP desde ag1.json del Integrante 1
    try:
        with open("shared_data/ag1.json", "r") as f:
            data = json.load(f)
            ip = data.get("ip", "142.251.0.139")  # IP de google.com como fallback
    except (FileNotFoundError, json.JSONDecodeError):
        ip = "142.251.0.139"  # IP de google.com por defecto si no se puede leer ag1.json
    
    url = f"http://{ip}"  # Usando HTTP, puedes cambiar a HTTPS si prefieres
    
    hallazgos = [
        {
            "id": "NUCLEI-001",
            "template": "http-missing-security-headers",
            "cve_id": None,
            "severidad": "INFO",
            "descripcion": "Google servers missing some security headers",
            "url_afectada": url,
            "evidencia": {"matcher": "word", "type": "http", "extracted_results": ["X-Content-Type-Options", "Referrer-Policy"]},
        },
        {
            "id": "NUCLEI-002",
            "template": "google-analytics-tracking-id",
            "cve_id": None,
            "severidad": "INFO",
            "descripcion": "Google Analytics tracking ID detected",
            "url_afectada": url,
            "evidencia": {"matcher": "regex", "type": "http", "extracted_results": ["UA-XXXXXXX-X"]},
        }
    ]
    return build_result(url, hallazgos, "mock")


def main() -> int:
    parser = argparse.ArgumentParser(description="Agente 05 - Nuclei a JSON normalizado")
    parser.add_argument("--url", help="URL autorizada a escanear. Ejemplo: http://lab.local")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT), help="Ruta de salida ag5.json")
    parser.add_argument("--timeout", type=int, default=180, help="Tiempo máximo del escaneo en segundos")
    parser.add_argument("--severity", default="critical,high,medium,low,info", help="Severidades de Nuclei")
    parser.add_argument("--from-file", help="Parsear un archivo nuclei JSONL ya generado, sin ejecutar escaneo")
    parser.add_argument("--mock", action="store_true", help="Generar datos de prueba sin escanear")
    parser.add_argument("--i-have-permission", action="store_true", help="Confirma que tienes autorización para analizar esa URL")
    args = parser.parse_args()

    output = Path(args.output)
    ensure_parent(output)

    if args.mock:
        result = mock_result()
    else:
        if not args.url:
            parser.error("Debes usar --url o --mock.")
        url = validate_url(args.url)

        if args.from_file:
            hallazgos = parse_nuclei_file(Path(args.from_file))
            result = build_result(url, hallazgos, "from_file")
        else:
            if not args.i_have_permission:
                parser.error("Para ejecutar Nuclei debes agregar --i-have-permission y usar solo objetivos autorizados/laboratorio.")
            nuclei_file = run_nuclei(url, args.severity, args.timeout)
            hallazgos = parse_nuclei_file(nuclei_file)
            result = build_result(url, hallazgos, "scan")

    output.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"[Agente 5] OK -> {output} ({result['total_hallazgos']} hallazgos)")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"[Agente 5] ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)