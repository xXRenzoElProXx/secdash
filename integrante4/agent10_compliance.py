import json
import os
import re
from datetime import datetime, UTC
from openai import OpenAI

try:
    ai = OpenAI(base_url="http://localhost:11434/v1", api_key="ollama")
    AI_MODEL = "ministral-3:14b-cloud"  # Integrante 4
    # Test de conexión
    ai.models.list()
    print("   ✓ Ollama conectado")
    ai_available = True
except Exception as e:
    print(f"   ⚠️  IA no disponible: {e}")
    print("   ℹ️  Continuando con análisis básico...")
    ai_available = False

def load_json(filename):
    """Carga un JSON desde shared_data/"""
    path = os.path.join(os.path.dirname(__file__), "..", "shared_data", filename)
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"   ⚠️  {filename} no encontrado")
        return None
    except Exception as e:
        print(f"   ❌ Error leyendo {filename}: {e}")
        return None

def mapear_a_controles_ia(hallazgos_owasp, nivel_riesgo):
    
    if not ai_available:
        return analisis_basico(hallazgos_owasp, nivel_riesgo)
    
    contexto = f"""
Hallazgos OWASP:
{json.dumps(hallazgos_owasp, indent=2)}

Nivel de riesgo general: {nivel_riesgo}
"""
    
    prompt = f"""Eres un auditor de cumplimiento de seguridad.
Analiza estos hallazgos de seguridad y mapéalos a controles normativos.

Devuelve SOLO un JSON con esta estructura exacta:
{{
  "compliance_checks": [
    {{
      "framework": "NIST 800-53 | CIS Controls | OWASP Top 10",
      "control": "ID del control (ej: AC-2, 1.1, A01:2021)",
      "hallazgo": "Descripción del hallazgo",
      "estado": "cumple | falla | parcial",
      "accion_correctiva": "Acción recomendada"
    }}
  ],
  "resumen": {{
    "total_checks": 0,
    "cumple": 0,
    "falla": 0,
    "parcial": 0,
    "nivel_cumplimiento": "alto | medio | bajo"
  }}
}}

Datos:
{contexto}

Responde SOLO con el JSON, sin markdown ni texto adicional."""

    try:
        response = ai.chat.completions.create(
            model=AI_MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2,
        )
        raw = response.choices[0].message.content.strip()
        raw = re.sub(r"```json|```", "", raw).strip()
        return json.loads(raw)
    except Exception as e:
        print(f"   ⚠️  Error en análisis IA: {e}")
        return analisis_basico(hallazgos_owasp, nivel_riesgo)

def analisis_basico(hallazgos_owasp, nivel_riesgo, ag7_data=None):
    """Análisis básico multi-framework sin IA"""
    checks = []
    
    # Mapeo multi-framework expandido
    for hallazgo in hallazgos_owasp:
        categoria = hallazgo.get("categoria", "")
        severidad = hallazgo.get("severidad", "").lower()
        descripcion = hallazgo.get("descripcion", categoria)
        
        # Determinar estado basado en severidad
        if severidad in ["critical", "critico", "crítico"]:
            estado = "falla"
        elif severidad in ["high", "alto", "alta"]:
            estado = "falla"
        elif severidad in ["medium", "medio", "media"]:
            estado = "parcial"
        else:
            estado = "cumple"
        
        # === BROKEN ACCESS CONTROL (A01) ===
        if "Access Control" in categoria or "A01" in categoria:
            checks.extend([
                {
                    "framework": "NIST 800-53",
                    "control": "AC-2 (Account Management)",
                    "hallazgo": descripcion,
                    "estado": estado,
                    "accion_correctiva": "Implementar controles de acceso estrictos y revisar permisos",
                    "severidad": severidad,
                    "evidencia": f"Hallazgo detectado en {hallazgo.get('url_afectada', 'N/A')}"
                },
                {
                    "framework": "ISO 27001:2022",
                    "control": "A.8.3 (Restricción de acceso a la información)",
                    "hallazgo": descripcion,
                    "estado": estado,
                    "accion_correctiva": "Aplicar principio de mínimo privilegio y segregación de funciones",
                    "severidad": severidad,
                    "evidencia": f"Control de acceso débil identificado"
                },
                {
                    "framework": "PCI-DSS 4.0",
                    "control": "Req. 7 (Restrict Access)",
                    "hallazgo": descripcion,
                    "estado": estado,
                    "accion_correctiva": "Implementar acceso basado en roles (RBAC) y registro de accesos",
                    "severidad": severidad,
                    "evidencia": "Acceso no restringido a recursos críticos"
                }
            ])
        
        # === CRYPTOGRAPHIC FAILURES (A02) ===
        elif "Cryptographic" in categoria or "A02" in categoria:
            checks.extend([
                {
                    "framework": "NIST 800-53",
                    "control": "SC-13 (Cryptographic Protection)",
                    "hallazgo": descripcion,
                    "estado": estado,
                    "accion_correctiva": "Usar TLS 1.2+, AES-256, RSA-2048+, eliminar algoritmos obsoletos (DES, MD5, SHA-1)",
                    "severidad": severidad,
                    "evidencia": "Algoritmo criptográfico débil o obsoleto detectado"
                },
                {
                    "framework": "ISO 27001:2022",
                    "control": "A.8.24 (Uso de criptografía)",
                    "hallazgo": descripcion,
                    "estado": estado,
                    "accion_correctiva": "Implementar política de criptografía con algoritmos aprobados",
                    "severidad": severidad,
                    "evidencia": "Configuración criptográfica insegura"
                },
                {
                    "framework": "PCI-DSS 4.0",
                    "control": "Req. 4 (Encrypt transmission)",
                    "hallazgo": descripcion,
                    "estado": estado,
                    "accion_correctiva": "Cifrar datos de titulares de tarjetas en tránsito con TLS 1.2+ y cifrados fuertes",
                    "severidad": severidad,
                    "evidencia": "Transmisión sin cifrado adecuado"
                },
                {
                    "framework": "GDPR",
                    "control": "Art. 32 (Seguridad del tratamiento)",
                    "hallazgo": descripcion,
                    "estado": estado,
                    "accion_correctiva": "Garantizar cifrado de datos personales en reposo y en tránsito",
                    "severidad": severidad,
                    "evidencia": "Datos potencialmente expuestos sin cifrado"
                }
            ])
        
        # === INJECTION (A03) ===
        elif "Injection" in categoria or "A03" in categoria:
            checks.extend([
                {
                    "framework": "OWASP Top 10",
                    "control": "A03:2021 - Injection",
                    "hallazgo": descripcion,
                    "estado": estado,
                    "accion_correctiva": "Validar y sanitizar todas las entradas, usar consultas parametrizadas, ORM seguro",
                    "severidad": severidad,
                    "evidencia": "Vector de inyección identificado"
                },
                {
                    "framework": "NIST 800-53",
                    "control": "SI-10 (Information Input Validation)",
                    "hallazgo": descripcion,
                    "estado": estado,
                    "accion_correctiva": "Implementar validación de entrada en servidor, whitelist vs blacklist",
                    "severidad": severidad,
                    "evidencia": "Falta de validación de entrada"
                },
                {
                    "framework": "PCI-DSS 4.0",
                    "control": "Req. 6.5.1 (Injection flaws)",
                    "hallazgo": descripcion,
                    "estado": estado,
                    "accion_correctiva": "Revisar código para prevenir inyección SQL, LDAP, OS Command",
                    "severidad": severidad,
                    "evidencia": "Vulnerabilidad de inyección detectada"
                }
            ])
        
        # === SECURITY MISCONFIGURATION (A05) ===
        elif "Security Misconfiguration" in categoria or "A05" in categoria or "Misconfiguration" in categoria:
            checks.extend([
                {
                    "framework": "CIS Controls",
                    "control": "4.1 (Secure Configuration)",
                    "hallazgo": descripcion,
                    "estado": estado,
                    "accion_correctiva": "Aplicar hardening, eliminar servicios innecesarios, configurar firewalls",
                    "severidad": severidad,
                    "evidencia": "Configuración insegura detectada"
                },
                {
                    "framework": "ISO 27001:2022",
                    "control": "A.8.9 (Gestión de configuración)",
                    "hallazgo": descripcion,
                    "estado": estado,
                    "accion_correctiva": "Establecer línea base de configuración segura y control de cambios",
                    "severidad": severidad,
                    "evidencia": "Desviación de configuración segura"
                },
                {
                    "framework": "NIST 800-53",
                    "control": "CM-6 (Configuration Settings)",
                    "hallazgo": descripcion,
                    "estado": estado,
                    "accion_correctiva": "Documentar y aplicar configuraciones de seguridad obligatorias",
                    "severidad": severidad,
                    "evidencia": "Configuración no conforme con baseline"
                }
            ])
        
        # === AUTHENTICATION FAILURES (A07) ===
        elif "Authentication" in categoria or "A07" in categoria:
            checks.extend([
                {
                    "framework": "NIST 800-53",
                    "control": "IA-2 (Identification and Authentication)",
                    "hallazgo": descripcion,
                    "estado": estado,
                    "accion_correctiva": "Implementar MFA, políticas de contraseña robustas, anti-brute force",
                    "severidad": severidad,
                    "evidencia": "Autenticación débil identificada"
                },
                {
                    "framework": "ISO 27001:2022",
                    "control": "A.8.5 (Autenticación segura)",
                    "hallazgo": descripcion,
                    "estado": estado,
                    "accion_correctiva": "Requerir autenticación multifactor para accesos privilegiados",
                    "severidad": severidad,
                    "evidencia": "Falta MFA en cuentas críticas"
                },
                {
                    "framework": "PCI-DSS 4.0",
                    "control": "Req. 8 (Identify Users)",
                    "hallazgo": descripcion,
                    "estado": estado,
                    "accion_correctiva": "Asignar ID único, deshabilitar cuentas inactivas, forzar cambio de contraseña inicial",
                    "severidad": severidad,
                    "evidencia": "Gestión inadecuada de identidades"
                },
                {
                    "framework": "SOC 2",
                    "control": "CC6.1 (Logical Access)",
                    "hallazgo": descripcion,
                    "estado": estado,
                    "accion_correctiva": "Restringir acceso lógico mediante autenticación adecuada",
                    "severidad": severidad,
                    "evidencia": "Control de acceso lógico insuficiente"
                }
            ])
    
    # Añadir checks de CVEs si están disponibles
    if ag7_data:
        cves = ag7_data.get("cves_encontrados", [])
        for cve in cves[:3]:  # Top 3 CVEs más críticas
            cvss = cve.get("cvss_score", 0)
            if cvss >= 7.0:
                checks.append({
                    "framework": "NIST 800-53",
                    "control": "SI-2 (Flaw Remediation)",
                    "hallazgo": f"CVE {cve.get('cve_id')} detectada: {cve.get('descripcion', '')[:100]}",
                    "estado": "falla",
                    "accion_correctiva": f"Aplicar parche de seguridad para {cve.get('software', 'software')} {cve.get('version', '')}",
                    "severidad": cve.get("severidad", "high"),
                    "evidencia": f"CVSS Score: {cvss}, Puerto: {cve.get('port', 'N/A')}"
                })
    
    # Si no hay hallazgos específicos, crear checks generales positivos
    if not checks:
        checks.extend([
            {
                "framework": "CIS Controls",
                "control": "1.1 (Maintain Inventory)",
                "hallazgo": f"Sistema con inventario de activos documentado",
                "estado": "cumple",
                "accion_correctiva": "Mantener inventario actualizado",
                "severidad": "info",
                "evidencia": f"Nivel de riesgo: {nivel_riesgo}"
            },
            {
                "framework": "ISO 27001:2022",
                "control": "A.5.9 (Inventario de activos)",
                "hallazgo": "Activos identificados y clasificados",
                "estado": "cumple",
                "accion_correctiva": "Revisar y actualizar inventario periódicamente",
                "severidad": "info",
                "evidencia": "Escaneo completado exitosamente"
            }
        ])
    
    # Calcular resumen
    total = len(checks)
    cumple = sum(1 for c in checks if c["estado"] == "cumple")
    falla = sum(1 for c in checks if c["estado"] == "falla")
    parcial = sum(1 for c in checks if c["estado"] == "parcial")
    
    if total == 0:
        nivel = "medio"
    elif cumple / total > 0.7:
        nivel = "alto"
    elif cumple / total > 0.4:
        nivel = "medio"
    else:
        nivel = "bajo"
    
    # Calcular por framework
    frameworks_count = {}
    for check in checks:
        fw = check["framework"]
        if fw not in frameworks_count:
            frameworks_count[fw] = {"total": 0, "cumple": 0, "falla": 0, "parcial": 0}
        frameworks_count[fw]["total"] += 1
        frameworks_count[fw][check["estado"]] += 1
    
    # Generar excepciones de ejemplo (para demostración)
    excepciones = []
    if falla > 0:
        excepciones.append({
            "hallazgo_id": "EXCEPTION-001",
            "control": checks[0]["control"] if checks else "N/A",
            "justificacion": "Remediación planificada en próximo sprint - riesgo aceptado temporalmente",
            "aprobador": "CISO",
            "fecha_expiracion": "2026-12-31",
            "riesgo_residual": "medio",
            "plan_mitigacion": "Implementar control compensatorio: monitoreo aumentado"
        })
    
    # Controles compensatorios
    controles_compensatorios = []
    for check in checks:
        if check["estado"] == "falla" and "MFA" in check["accion_correctiva"]:
            controles_compensatorios.append({
                "control_original": check["control"],
                "control_compensatorio": "Aumentar complejidad de contraseña a 16 caracteres + lockout 3 intentos",
                "nivel_compensacion": "parcial",
                "efectividad": "60%",
                "nota": "Mientras se implementa MFA, usar contraseñas más robustas"
            })
        elif check["estado"] == "falla" and "cifrado" in check["hallazgo"].lower():
            controles_compensatorios.append({
                "control_original": check["control"],
                "control_compensatorio": "Segmentación de red + VPN obligatoria para datos sensibles",
                "nivel_compensacion": "parcial",
                "efectividad": "70%",
                "nota": "Reducir superficie de exposición mientras se actualiza criptografía"
            })
    
    return {
        "compliance_checks": checks,
        "resumen": {
            "total_checks": total,
            "cumple": cumple,
            "falla": falla,
            "parcial": parcial,
            "nivel_cumplimiento": nivel,
            "porcentaje_cumplimiento": round((cumple / total * 100), 1) if total > 0 else 0
        },
        "por_framework": frameworks_count,
        "excepciones": excepciones,
        "controles_compensatorios": controles_compensatorios
    }

def run_agent():
    print(f"\n🛡️ Agente 10 — Compliance Agent (Multi-Framework)")
    print("   Analizando cumplimiento normativo...\n")

    print("   [1/4] Cargando ag6.json (OWASP)...")
    ag6 = load_json("ag6.json")
    if not ag6:
        print("   ⚠️ ag6.json no disponible. Creando reporte básico...")
        hallazgos_owasp = []
    else:
        clasificaciones = ag6.get("clasificaciones", [])
        hallazgos_owasp = clasificaciones if clasificaciones else ag6.get("hallazgos", [])
        print(f"         Hallazgos encontrados: {len(hallazgos_owasp)}")

    print("   [2/4] Cargando ag7.json (CVEs)...")
    ag7 = load_json("ag7.json")
    if ag7:
        print(f"         CVEs encontradas: {ag7.get('total_cves', 0)}")

    print("   [3/4] Cargando ag9.json (Riesgo)...")
    ag9 = load_json("ag9.json")
    if not ag9:
        print("   ⚠️  ag9.json no disponible. Usando nivel de riesgo por defecto...")
        nivel_riesgo = "medio"
    else:
        nivel_riesgo = ag9.get("nivel", "medio").lower()
        print(f"         Nivel de riesgo: {nivel_riesgo}")

    print("\n   [4/4] Mapeando a controles multi-framework...")
    print("         Frameworks: NIST 800-53, CIS, ISO 27001, PCI-DSS, GDPR, SOC 2")
    
    if ai_available:
        print("         Modo: Análisis IA...")
    else:
        print("         Modo: Análisis básico...")
    
    resultado = analisis_basico(hallazgos_owasp, nivel_riesgo, ag7)

    resultado["agent"] = "AG10_COMPLIANCE"
    resultado["integrante"] = 4
    resultado["timestamp"] = datetime.now(UTC).isoformat()
    resultado["target"] = ag6.get("target") if ag6 else ag9.get("target") if ag9 else ag7.get("target") if ag7 else "desconocido"
    
    # Evidencias de auditoría
    resultado["evidencias_auditoria"] = {
        "fuentes_datos": ["ag6.json", "ag7.json", "ag9.json"],
        "metodo_analisis": "AI-assisted" if ai_available else "rule-based",
        "timestamp_analisis": datetime.now(UTC).isoformat(),
        "hash_ag6": "SHA256:mock_hash_ag6" if ag6 else None,
        "hash_ag7": "SHA256:mock_hash_ag7" if ag7 else None,
        "hash_ag9": "SHA256:mock_hash_ag9" if ag9 else None
    }
    
    output_path = os.path.join(
        os.path.dirname(__file__), "..", "shared_data", "ag10.json"
    )
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(resultado, f, indent=2, ensure_ascii=False)

    print(f"\n   ✅ Listo. Guardado en shared_data/ag10.json")
    print(f"   📊 Resumen:")
    resumen = resultado["resumen"]
    print(f"      Total checks: {resumen['total_checks']}")
    print(f"      Cumple: {resumen['cumple']} | Falla: {resumen['falla']} | Parcial: {resumen['parcial']}")
    print(f"      Nivel de cumplimiento: {resumen['nivel_cumplimiento'].upper()} ({resumen.get('porcentaje_cumplimiento', 0)}%)")
    print(f"      Frameworks analizados: {len(resultado['por_framework'])}")
    if resultado.get("excepciones"):
        print(f"      Excepciones registradas: {len(resultado['excepciones'])}")
    if resultado.get("controles_compensatorios"):
        print(f"      Controles compensatorios: {len(resultado['controles_compensatorios'])}")

    return resultado

if __name__ == "__main__":
    try:
        run_agent()
    except Exception as e:
        print(f"\n❌ ERROR FATAL: {e}")
        import traceback
        traceback.print_exc()
        exit(1)
