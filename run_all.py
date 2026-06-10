"""
run_all.py — Ejecuta los 3 agentes del Integrante 1 en orden.

Uso:
    python run_all.py example.com
"""

import sys
import os

# Agregar integrante1/ al path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "integrante1"))

from agent1_discovery import run_agent as ag1
from agent2_network   import run_agent as ag2
from agent3_surface   import run_agent as ag3

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: python run_all.py <dominio>")
        print("Ejemplo: python run_all.py scanme.nmap.org")
        sys.exit(1)

    target = sys.argv[1]

    print("=" * 50)
    print(f"  SecDash — Integrante 1")
    print(f"  Objetivo: {target}")
    print("=" * 50)

    ag1(target)   # → shared_data/ag1.json
    ag2()         # lee ag1.json → shared_data/ag2.json
    ag3()         # lee ag1+ag2  → shared_data/ag3.json

    print("\n" + "=" * 50)
    print("  ✅ Los 3 agentes completados.")
    print("  Archivos listos en shared_data/:")
    print("    ag1.json, ag2.json, ag3.json")
    print("  Comparte esta carpeta con tu equipo (git push)")
    print("=" * 50)
