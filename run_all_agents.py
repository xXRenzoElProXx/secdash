#!/usr/bin/env python3

import sys
import os
import subprocess
import argparse
from pathlib import Path

def print_header(text):
    print("\n" + "=" * 60)
    print(f"  {text}")
    print("=" * 60)

def run_command(cmd, description):
    print(f"\n🔄 {description}...")
    try:
        result = subprocess.run(
            cmd,
            check=True,
            capture_output=True,
            text=True
        )
        print(f"✅ {description} completado")
        if result.stdout:
            print(f"   Output: {result.stdout[:200]}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Error en {description}")
        print(f"   {e.stderr[:500]}")
        return False
    except FileNotFoundError:
        print(f"⚠️  Archivo no encontrado para {description}")
        print(f"   Comando: {' '.join(cmd)}")
        return False

def main():
    parser = argparse.ArgumentParser(description="Ejecuta todos los agentes de SecDash")
    parser.add_argument("target", help="Dominio o IP objetivo (ej: scanme.nmap.org)")
    parser.add_argument("--mock", action="store_true", help="Ejecutar en modo demo")
    parser.add_argument("--skip-web", action="store_true", help="Saltar agentes web (4,5)")
    args = parser.parse_args()

    target = args.target
    mock_flag = ["--mock"] if args.mock else []

    print_header(f"🛡️  SECDASH AI SOC - FULL SCAN")
    print(f"   Target: {target}")
    print(f"   Mode: {'DEMO/MOCK' if args.mock else 'REAL SCAN'}")
    
    success_count = 0
    total_count = 0

    print_header("INTEGRANTE 1: Asset Discovery & Network Analysis")
    
    agents_int1 = [
        (["python", "integrante1/agent1_discovery.py", target], "AG1 - Asset Discovery"),
        (["python", "integrante1/agent2_network.py"], "AG2 - Network Scan"),
        (["python", "integrante1/agent3_surface.py"], "AG3 - Attack Surface"),
    ]
    
    for cmd, desc in agents_int1:
        total_count += 1
        if run_command(cmd, desc):
            success_count += 1

    if not args.skip_web:
        print_header("INTEGRANTE 2: Web Vulnerability Assessment")
        
        agents_int2 = [
            (["python", "integrante2/agent4_nikto.py"] + mock_flag, "AG4 - Nikto Web Scan"),
            (["python", "integrante2/agent5_nuclei.py"] + mock_flag, "AG5 - Nuclei Templates"),
            (["python", "integrante2/agent6_owasp_classifier.py"], "AG6 - OWASP Classifier"),
        ]
        
        for cmd, desc in agents_int2:
            total_count += 1
            if run_command(cmd, desc):
                success_count += 1
    else:
        print_header("INTEGRANTE 2: Web Scans SKIPPED")

    print_header("INTEGRANTE 3: Intelligence & Risk Analysis")
    
    agents_int3 = [
        (["python", "integrante3/agent7_cve_intelligence.py"], "AG7 - CVE Intelligence"),
        (["python", "integrante3/agent8_threat_intel.py"], "AG8 - Threat Intelligence"),
        (["python", "integrante3/agent9_risk_correlation.py"], "AG9 - Risk Correlation"),
    ]
    
    for cmd, desc in agents_int3:
        total_count += 1
        if run_command(cmd, desc):
            success_count += 1

    print_header("INTEGRANTE 4: Compliance, Exploit Advisory & Security Chatbot")
    
    agents_int4 = [
        (["python", "integrante4/agent10_compliance.py"], "AG10 - Compliance Checker"),
        (["python", "integrante4/agent11_metasploit.py"], "AG11 - Metasploit Advisor"),
        (["python", "integrante4/agent12_chatbot.py", "--generate-report"], "AG12 - Security Chatbot Report"),
    ]
    
    for cmd, desc in agents_int4:
        total_count += 1
        if run_command(cmd, desc):
            success_count += 1

    print_header("📊 EXECUTION SUMMARY")
    print(f"   Total agents: {total_count}")
    print(f"   Successful: {success_count}")
    print(f"   Failed: {total_count - success_count}")
    print(f"   Success rate: {(success_count/total_count)*100:.1f}%")
    
    print("\n" + "=" * 60)
    print("  📁 Output files generated in shared_data/:")
    print("     ag1.json - ag12.json")
    print("\n  🚀 Next steps:")
    print("     streamlit run dashboard.py")
    print("     python integrante4/agent12_chatbot.py --interactive  # Chat interactivo")
    print("=" * 60)
    
    return 0 if success_count == total_count else 1

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\n⚠️  Execution interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n❌ Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
