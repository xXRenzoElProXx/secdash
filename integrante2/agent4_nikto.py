#!/usr/bin/env python3
"""
Agente 04 - Web Vulnerability
Ejecuta Nikto sobre una URL autorizada y genera shared_data/ag4.json.

Uso seguro:
  python3 agent4_nikto.py --url http://TU-LAB --i-have-permission
  python3 agent4_nikto.py --from-file nikto_out.json
  python3 agent4_nikto.py --mock
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
from urllib.parse import urljoin, urlparse


DEFAULT_OUTPUT = Path("shared_data/ag4.json")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def validate_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("La URL debe empezar con http:// o https:// y tener dominio/IP.")
    return url.rstrip("/")


def severity_from_text(text: str) -> str:
    """Nikto no siempre entrega severidad; usamos una heurística simple y explicable."""
    t = text.lower()
    high_words = [
        "sql injection", "command injection", "remote code", "rce",
        "default credential", "default password", "file upload", "shell",
    ]
    med_words = [
        "outdated", "old version", "directory indexing", "trace method",
        "xss", "cross-site scripting", "backup", "admin", "phpinfo",
        "exposed", "config", "misconfiguration",
    ]
    low_words = [
        "header", "cookie", "information disclosure", "server leaks",
        "x-frame-options", "x-content-type-options", "robots.txt",
    ]
    if any(w in t for w in high_words):
        return "HIGH"
    if any(w in t for w in med_words):
        return "MEDIUM"
    if any(w in t for w in low_words):
        return "LOW"
    return "LOW"


def first_value(d: Dict[str, Any], keys: List[str]) -> Optional[Any]:
    for k in keys:
        if k in d and d[k] not in (None, "", []):
            return d[k]
    return None


def collect_dicts(obj: Any) -> List[Dict[str, Any]]:
    found: List[Dict[str, Any]] = []
    if isinstance(obj, dict):
        # Diccionarios que parecen hallazgos de Nikto
        keys = set(obj.keys())
        useful = {"msg", "message", "description", "uri", "url", "testid", "id", "OSVDB"}
        if keys & useful:
            found.append(obj)
        for value in obj.values():
            found.extend(collect_dicts(value))
    elif isinstance(obj, list):
        for item in obj:
            found.extend(collect_dicts(item))
    return found


def normalize_nikto_json(data: Any, url: str) -> List[Dict[str, Any]]:
    raw_items = collect_dicts(data)
    hallazgos: List[Dict[str, Any]] = []
    seen = set()

    for item in raw_items:
        descripcion = first_value(item, ["msg", "message", "description", "desc", "text"])
        if not descripcion:
            continue
        descripcion = str(descripcion).strip()

        raw_id = first_value(item, ["id", "testid", "OSVDB", "osvdb"])
        uri = first_value(item, ["uri", "url", "path"])
        url_afectada = urljoin(url + "/", str(uri).lstrip("/")) if uri else url

        key = (descripcion, url_afectada)
        if key in seen:
            continue
        seen.add(key)

        hallazgos.append({
            "id": str(raw_id) if raw_id else f"NIKTO-{len(hallazgos)+1:03d}",
            "descripcion": descripcion,
            "severidad": severity_from_text(descripcion),
            "url_afectada": url_afectada,
            "evidencia": descripcion,
        })

    # Renumerar con prefijo uniforme si el id viene vacío o raro
    for i, h in enumerate(hallazgos, start=1):
        if not h["id"] or h["id"].lower() in {"none", "null"}:
            h["id"] = f"NIKTO-{i:03d}"
        elif not str(h["id"]).upper().startswith("NIKTO-"):
            h["id"] = f"NIKTO-{i:03d}"
    return hallazgos


def normalize_nikto_text(text: str, url: str) -> List[Dict[str, Any]]:
    hallazgos: List[Dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("+"):
            continue
        clean = line.lstrip("+").strip()
        if not clean or clean.lower().startswith(("target", "start time", "end time")):
            continue

        # Intenta capturar ruta inicial: /algo: mensaje
        match = re.match(r"(?P<path>/[^: ]+)?\s*:?[ ]*(?P<msg>.+)", clean)
        path = match.group("path") if match else None
        msg = match.group("msg") if match else clean
        url_afectada = urljoin(url + "/", path.lstrip("/")) if path else url

        hallazgos.append({
            "id": f"NIKTO-{len(hallazgos)+1:03d}",
            "descripcion": msg.strip(),
            "severidad": severity_from_text(msg),
            "url_afectada": url_afectada,
            "evidencia": clean,
        })
    return hallazgos


def parse_nikto_file(path: Path, url: str) -> List[Dict[str, Any]]:
    raw = path.read_text(encoding="utf-8", errors="ignore")
    try:
        data = json.loads(raw)
        hallazgos = normalize_nikto_json(data, url)
        if hallazgos:
            return hallazgos
    except json.JSONDecodeError:
        pass
    return normalize_nikto_text(raw, url)


def run_nikto(url: str, timeout: int) -> Path:
    if not shutil.which("nikto"):
        raise RuntimeError("Nikto no está instalado o no está en PATH. Instala con: sudo apt install nikto")

    tmp = Path(tempfile.gettempdir()) / f"nikto_out_{abs(hash(url))}.json"
    cmd = ["nikto", "-h", url, "-output", str(tmp), "-Format", "json"]
    print(f"[Agente 4] Ejecutando: {' '.join(cmd)}")

    completed = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )

    if completed.returncode not in (0, 1):
        # Nikto puede devolver 1 aunque haya generado resultados; por eso solo fallamos si no hay archivo.
        if not tmp.exists():
            raise RuntimeError(
                "Nikto falló y no generó salida.\n"
                f"STDERR:\n{completed.stderr}\nSTDOUT:\n{completed.stdout}"
            )

    if not tmp.exists():
        # Fallback: guardar stdout como texto para parsearlo
        tmp = Path(tempfile.gettempdir()) / f"nikto_out_{abs(hash(url))}.txt"
        tmp.write_text(completed.stdout, encoding="utf-8")
    return tmp


def build_result(url: str, hallazgos: List[Dict[str, Any]], mode: str) -> Dict[str, Any]:
    return {
        "agente": "Agente 04 - Web Vulnerability",
        "url_escaneada": url,
        "herramienta": "nikto",
        "modo": mode,
        "hallazgos": hallazgos,
        "total_hallazgos": len(hallazgos),
        "nota": "Severidad estimada por heurística porque Nikto no siempre entrega severidad normalizada.",
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
            "id": "NIKTO-001",
            "descripcion": "X-Frame-Options header is not present",
            "severidad": "LOW",
            "url_afectada": url,
            "evidencia": "Cabecera X-Frame-Options ausente",
        },
        {
            "id": "NIKTO-002",
            "descripcion": "Directory indexing found",
            "severidad": "MEDIUM",
            "url_afectada": url + "/uploads/",
            "evidencia": "Listado de directorio expuesto",
        },
    ]
    return build_result(url, hallazgos, "mock")


def main() -> int:
    parser = argparse.ArgumentParser(description="Agente 04 - Nikto a JSON normalizado")
    parser.add_argument("--url", help="URL autorizada a escanear. Ejemplo: http://lab.local")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT), help="Ruta de salida ag4.json")
    parser.add_argument("--timeout", type=int, default=180, help="Tiempo máximo del escaneo en segundos")
    parser.add_argument("--from-file", help="Parsear un archivo Nikto ya generado, sin ejecutar escaneo")
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
            hallazgos = parse_nikto_file(Path(args.from_file), url)
            result = build_result(url, hallazgos, "from_file")
        else:
            if not args.i_have_permission:
                parser.error("Para ejecutar Nikto debes agregar --i-have-permission y usar solo objetivos autorizados/laboratorio.")
            nikto_file = run_nikto(url, args.timeout)
            hallazgos = parse_nikto_file(nikto_file, url)
            result = build_result(url, hallazgos, "scan")

    output.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"[Agente 4] OK -> {output} ({result['total_hallazgos']} hallazgos)")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"[Agente 4] ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)