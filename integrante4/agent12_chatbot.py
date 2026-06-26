#!/usr/bin/env python3
"""
AGENTE 12 — Security Chatbot Assistant
Integrante 4

Chatbot especializado en ciberseguridad que proporciona asistencia contextual
basada en los datos del dashboard y conocimientos de seguridad.

Uso:
  python3 agent12_chatbot.py --query "¿Qué vulnerabilidades son más críticas?"
  python3 agent12_chatbot.py --interactive
  python3 agent12_chatbot.py --context-mode full  # Incluye todos los datos del dashboard
"""

import argparse
import json
import os
import sys
from datetime import datetime, UTC
from pathlib import Path
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv

load_dotenv()

AI_MODEL = os.getenv("SECDASH_AI_MODEL", "minimax-m3:cloud")
AI_AVAILABLE = False
ai = None

try:
    from openai import OpenAI
    ai = OpenAI(
        base_url=os.getenv("OLLAMA_BASE_URL", "http://localhost:11434/v1"),
        api_key=os.getenv("OLLAMA_API_KEY", "ollama"),
    )
    AI_AVAILABLE = True
    # Test de conexión suave; si falla, se deja como no disponible pero sin romper el flujo
    try:
        ai.models.list()
    except Exception as e:
        print(f"⚠️ IA no disponible en el arranque: {e}")
        AI_AVAILABLE = False
except Exception as e:
    print(f"⚠️ IA no disponible: {e}")
    AI_AVAILABLE = False

def root_path():
    return os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

def shared_path(filename):
    return os.path.join(root_path(), "shared_data", filename)

def load_dashboard_context() -> Dict[str, Any]:
    """Carga todos los datos del dashboard para contexto del chatbot"""
    context = {}
    
    # Archivos de datos principales
    data_files = [
        "ag1.json", "ag2.json", "ag3.json", "ag4.json", 
        "ag5.json", "ag6.json", "ag7.json", "ag8.json", 
        "ag9.json", "ag10.json", "ag11.json"
    ]
    
    for file in data_files:
        try:
            path = shared_path(file)
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as f:
                    context[file.replace('.json', '')] = json.load(f)
        except Exception as e:
            print(f"⚠️ No se pudo cargar {file}: {e}")
            context[file.replace('.json', '')] = {}
    
    return context

def build_system_prompt(context_mode: str = "basic") -> str:
    """Construye el prompt del sistema según el modo de contexto"""
    
    base_prompt = """Eres un asistente especializado en ciberseguridad para SecDash.

ROLE: Analista senior de seguridad con experiencia en:
- Análisis de vulnerabilidades y CVEs
- Threat intelligence y IOCs
- Compliance y marcos de seguridad
- Herramientas como Nikto, Nuclei, Nmap, Metasploit
- MITRE ATT&CK Framework
- OWASP Top 10

ESTILO DE RESPUESTA:
- Técnico pero accesible
- Prioriza la acción práctica
- Incluye referencias específicas cuando sea relevante
- Usa emojis para claridad: 🔴 (crítico), 🟡 (medio), 🟢 (bajo), 🤖 (IA), 📊 (datos)

CAPACIDADES:
- Análisis de vulnerabilidades del dashboard
- Recomendaciones de remediación
- Explicación de conceptos de seguridad
- Interpretación de resultados de escaneo
- Priorización de riesgos"""

    if context_mode == "full":
        context_data = load_dashboard_context()
        
        # Resumen de datos disponibles
        summary = []
        for agent, data in context_data.items():
            if data and isinstance(data, dict):
                total_items = 0
                if 'hallazgos' in data:
                    total_items = len(data.get('hallazgos', []))
                elif 'cves_encontrados' in data:
                    total_items = len(data.get('cves_encontrados', []))
                elif 'iocs' in data:
                    total_items = len(data.get('iocs', []))
                
                if total_items > 0:
                    summary.append(f"- {agent.upper()}: {total_items} elementos")
        
        context_prompt = f"""

DATOS ACTUALES DEL DASHBOARD:
{chr(10).join(summary)}

Tienes acceso a todos estos datos para proporcionar respuestas contextualizadas.
Cuando respondas, haz referencia específica a los hallazgos cuando sea relevante.
"""
        return base_prompt + context_prompt
    
    return base_prompt

def generate_fallback_response(query: str, context_mode: str = "basic") -> str:
    """Genera una respuesta local cuando no hay OpenAI/Ollama disponible."""
    query_lower = (query or "").lower()

    if any(word in query_lower for word in ["hola", "hi", "hello", "olá"]):
        return (
            "🤖 Respuesta de respaldo de SecDash.\n\n"
            "El chatbot está funcionando en modo mock porque no hay conexión con OpenAI/Ollama.\n\n"
            "Prueba con consultas como:\n"
            "- ¿Qué vulnerabilidades son críticas?\n"
            "- Explícame los CVEs más relevantes\n"
            "- ¿Qué acciones de remediación priorizaría?\n\n"
            "Para activar la IA real, ejecuta:\n"
            "```bash\n"
            "ollama serve\n"
            f"ollama pull {AI_MODEL}\n"
            "```"
        )

    if any(word in query_lower for word in ["vulnerabilidad", "cve", "critical", "crítico", "alto"]):
        return (
            "🛡️ Respuesta de respaldo: prioriza revisar los hallazgos de los agentes 4, 5 y 7, "
            "especialmente aquellos con severidad alta o crítica, y validar parcheo inmediato."
        )

    if any(word in query_lower for word in ["ioc", "threat", "malware", "amenaza"]):
        return (
            "📡 Respuesta de respaldo: revisa la reputación de los IOCs, valida si hay actividad sospechosa "
            "y aisla los indicadores con mayor score de riesgo antes de tomar acciones."
        )

    return (
        "🤖 Modo mock activado. SecDash puede responder con un resumen local mientras no haya conexión con Ollama/OpenAI.\n\n"
        "Prueba una consulta como 'hola', '¿qué vulnerabilidades son críticas?' o '¿qué harías primero?'."
    )


def chat_with_ai(query: str, context_mode: str = "basic", conversation_history: List[Dict] = None, use_mock: bool = False) -> str:
    """Interactúa con la IA usando el contexto del dashboard"""
    
    if not AI_AVAILABLE or use_mock:
        return generate_fallback_response(query, context_mode)
    
    try:
        # Construir historial de conversación
        messages = [{"role": "system", "content": build_system_prompt(context_mode)}]
        
        if conversation_history:
            messages.extend(conversation_history)
        
        messages.append({"role": "user", "content": query})
        
        # Si es modo full, incluir datos relevantes
        if context_mode == "full":
            context_data = load_dashboard_context()
            
            # Añadir contexto relevante basado en la consulta
            relevant_data = []
            query_lower = query.lower()
            
            if any(word in query_lower for word in ["vulnerabilidad", "cve", "crítico", "alto"]):
                # Incluir datos de vulnerabilidades
                for agent in ['ag4', 'ag5', 'ag7']:
                    if agent in context_data and context_data[agent]:
                        relevant_data.append(f"\n--- Datos de {agent.upper()} ---")
                        relevant_data.append(json.dumps(context_data[agent], indent=2)[:1000])
            
            if any(word in query_lower for word in ["ip", "amenaza", "ioc", "malware"]):
                # Incluir datos de threat intelligence
                if 'ag8' in context_data and context_data['ag8']:
                    relevant_data.append(f"\n--- Datos de AG8 (Threat Intel) ---")
                    relevant_data.append(json.dumps(context_data['ag8'], indent=2)[:1000])
            
            if relevant_data:
                context_message = "DATOS RELEVANTES DEL DASHBOARD:\n" + "\n".join(relevant_data)
                messages.append({"role": "system", "content": context_message})
        
        response = ai.chat.completions.create(
            model=AI_MODEL,
            messages=messages,
            max_tokens=1000,
            temperature=0.3,
            stream=False
        )
        
        return response.choices[0].message.content.strip()
        
    except Exception as e:
        return f"❌ **Error en chatbot**: {e}\n\nVerifica la conexión con Ollama y el modelo {AI_MODEL}."

def interactive_mode(mock_mode: bool = False):
    """Modo interactivo del chatbot"""
    print("🤖 **SecDash Security Chatbot** - Agent 12")
    print(f"Modelo: {AI_MODEL}")
    print("Escribe 'exit' para salir, 'context' para cambiar modo, 'help' para ayuda\n")
    
    conversation_history = []
    context_mode = "basic"
    
    while True:
        try:
            query = input(f"[{context_mode}] 💬 Tu consulta: ").strip()
            
            if query.lower() in ['exit', 'quit', 'salir']:
                print("👋 ¡Hasta luego!")
                break
            
            if query.lower() == 'context':
                context_mode = "full" if context_mode == "basic" else "basic"
                print(f"🔄 Cambiado a modo: {context_mode}")
                continue
            
            if query.lower() == 'help':
                print("""
🤖 **Comandos disponibles:**
- `context`: Cambia entre modo basic/full (con datos del dashboard)
- `exit`: Salir del chat
- `help`: Mostrar esta ayuda

📝 **Ejemplos de consultas:**
- "¿Cuáles son las vulnerabilidades más críticas?"
- "Explícame los CVEs encontrados"
- "¿Qué IOCs son más peligrosos?"
- "Dame recomendaciones de remediación"
- "¿Cómo interpretar el score CVSS?"
""")
                continue
            
            if not query:
                continue
            
            print("🤖 Analizando...")
            response = chat_with_ai(query, context_mode, conversation_history, use_mock=mock_mode)
            print(f"\n{response}\n")
            
            # Guardar en historial
            conversation_history.append({"role": "user", "content": query})
            conversation_history.append({"role": "assistant", "content": response})
            
            # Limitar historial a últimas 10 interacciones
            if len(conversation_history) > 20:
                conversation_history = conversation_history[-20:]
                
        except KeyboardInterrupt:
            print("\n👋 ¡Hasta luego!")
            break
        except Exception as e:
            print(f"❌ Error: {e}")

def generate_security_report(mock_mode: bool = False) -> Dict[str, Any]:
    """Genera un reporte de seguridad usando IA y datos del dashboard"""
    
    if not AI_AVAILABLE or mock_mode:
        return {
            "error": "IA no disponible",
            "modo": "mock",
            "timestamp": datetime.now(UTC).isoformat(),
            "resumen": "Reporte generado en modo mock con respuestas locales de respaldo."
        }
    
    context_data = load_dashboard_context()
    
    # Consultas predefinidas para el reporte
    queries = [
        "Resume las vulnerabilidades más críticas encontradas",
        "¿Cuáles son las principales amenazas identificadas?", 
        "Dame 3 recomendaciones prioritarias de seguridad",
        "¿Qué aspectos de compliance necesitan atención?"
    ]
    
    report = {
        "agent": "AG12_SECURITY_CHATBOT",
        "integrante": 4,
        "modelo_ia": AI_MODEL,
        "timestamp": datetime.now(UTC).isoformat(),
        "analisis_automatico": {}
    }
    
    for i, query in enumerate(queries, 1):
        try:
            response = chat_with_ai(query, "full", use_mock=mock_mode)
            report["analisis_automatico"][f"seccion_{i}"] = {
                "pregunta": query,
                "analisis": response
            }
        except Exception as e:
            report["analisis_automatico"][f"seccion_{i}"] = {
                "pregunta": query,
                "error": str(e)
            }
    
    return report

def main():
    parser = argparse.ArgumentParser(description="Agent 12 - Security Chatbot Assistant")
    parser.add_argument("--query", help="Consulta específica al chatbot")
    parser.add_argument("--interactive", action="store_true", help="Modo interactivo")
    parser.add_argument("--context-mode", choices=["basic", "full"], default="basic", 
                       help="Modo de contexto (basic o full con datos dashboard)")
    parser.add_argument("--generate-report", action="store_true", help="Generar reporte automático")
    parser.add_argument("--mock", action="store_true", help="Usar respuestas locales de respaldo sin Ollama/OpenAI")
    parser.add_argument("--output", default="shared_data/ag12.json", help="Archivo de salida")
    
    args = parser.parse_args()
    
    if args.interactive:
        interactive_mode(mock_mode=args.mock)
        return 0
    
    if args.generate_report:
        print("📊 Generando reporte de seguridad automático...")
        report = generate_security_report(mock_mode=args.mock)
        
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        print(f"✅ Reporte guardado en: {output_path}")
        return 0
    
    if args.query:
        print("🤖 Procesando consulta...")
        response = chat_with_ai(args.query, args.context_mode, use_mock=args.mock)
        print(f"\n{response}")
        return 0
    
    # Sin argumentos, mostrar ayuda
    parser.print_help()
    return 1

if __name__ == "__main__":
    sys.exit(main())