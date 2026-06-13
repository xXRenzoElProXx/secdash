# 🛡️ SecDash AI SOC

**Security Operations Center Dashboard** - Sistema automatizado de análisis de seguridad con 11 agentes especializados.

---

## 📋 Descripción

SecDash es una plataforma de análisis de seguridad automatizada que simula un SOC (Security Operations Center) completo. Utiliza 11 agentes especializados que trabajan en conjunto para analizar objetivos, detectar vulnerabilidades, evaluar riesgos y generar recomendaciones de remediación.

### ✨ Características

- ✅ **Análisis de Red Completo**: Descubrimiento de activos, escaneo de puertos, identificación de servicios
- ✅ **Análisis Web**: Nikto + Nuclei para detección exhaustiva de vulnerabilidades
- ✅ **Clasificación OWASP Top 10**: Mapeo automático de hallazgos a categorías OWASP 2021
- ✅ **Inteligencia de CVEs**: Búsqueda de vulnerabilidades conocidas en NVD
- ✅ **Threat Intelligence**: Verificación de reputación de IPs con AbuseIPDB
- ✅ **Correlación de Riesgo**: Cálculo consolidado de score de riesgo (0-100)
- ✅ **Cumplimiento Normativo**: Mapeo a controles NIST 800-53 y CIS
- ✅ **Dashboard Interactivo**: Visualización en tiempo real con Streamlit
- ✅ **Chat SOC con IA**: Asistente bilingüe (ES/EN) con Ollama

---

## 🏗️ Arquitectura

```
┌─────────────────────────────────────────────────────────────┐
│                     INTEGRANTE 1                            │
│  AG1: Discovery → AG2: Network → AG3: Surface               │
└────────────────┬────────────────────────────────────────────┘
                 │
       ┌─────────┴─────────┐
       │                   │
       ▼                   ▼
┌──────────────┐    ┌──────────────┐
│ INTEGRANTE 2 │    │ INTEGRANTE 3 │
│              │    │              │
│ AG4: Nikto   │    │ AG7: CVE     │
│ AG5: Nuclei  │───▶│ AG8: Threat  │
│ AG6: OWASP   │    │ AG9: Risk    │
└──────┬───────┘    └──────┬───────┘
       │                   │
       └─────────┬─────────┘
                 ▼
       ┌──────────────────┐
       │   INTEGRANTE 4   │
       │ AG10: Compliance │
       │ AG11: Metasploit │
       └────────┬─────────┘
                │
                ▼
        ┌──────────────┐
        │   DASHBOARD  │
        │  + Chat IA   │
        └──────────────┘
```

---

## 🎓 Conceptos del Curso Integrados

**SecDash ahora incluye más de 30 conceptos** del curso de Seguridad en Computación:

### Integrante 1 (Mejorado):
- 🔥 **Firewall/IDS Detection**: Análisis de puertos filtrados, detección de IDS/IPS
- 🔐 **SSL/TLS Analysis**: Protocolos (TLSv1.2/1.3), cifrados (AES, RSA, RC4), certificados X.509
- 🛡️ **Control de Acceso**: Modelos DAC/MAC/RBAC, principio de mínimo privilegio
- ⚙️ **Hardening**: Servicios innecesarios, protocolos inseguros, segmentación de red
- 🎯 **Post-Explotación**: Movimiento lateral, escalamiento de privilegios

### Integrante 2 (Mejorado):
- 🔒 **Criptografía**: Detección de algoritmos débiles (DES, MD5, SSLv3)
- 💉 **Vulnerabilidades de Memoria**: Buffer overflow, stack overflow
- 🚪 **Control de Acceso Roto**: Path traversal, IDOR, privilege escalation
- 🔑 **Autenticación**: Credenciales por defecto, session fixation, MFA
- 📋 **OWASP Top 10**: Clasificación mejorada con 60+ keywords

Ver detalles completos en: **[CONCEPTOS_CURSO_AÑADIDOS.md](CONCEPTOS_CURSO_AÑADIDOS.md)**

---

## 📦 Agentes Implementados

### **Integrante 1: Reconnaissance** ⭐ MEJORADO
| Agente | Herramienta | Función | Salida |
|--------|-------------|---------|--------|
| **AG1** | DNS/WHOIS | Descubrimiento de activos, subdominios | `ag1.json` |
| **AG2** | Nmap + NSE | Escaneo de puertos, **firewall/IDS detection**, **SSL/TLS analysis** | `ag2.json` |
| **AG3** | Análisis IA | Superficie de ataque, **control de acceso**, **hardening**, **post-explotación** | `ag3.json` |

### **Integrante 2: Web Security** ⭐ MEJORADO
| Agente | Herramienta | Función | Salida |
|--------|-------------|---------|--------|
| **AG4** | Nikto | Escaneo web + **análisis criptográfico** + **servicios inseguros** | `ag4.json` |
| **AG5** | Nuclei | Templates + **buffer overflow** + **hashes débiles** + **path traversal** | `ag5.json` |
| **AG6** | Reglas/IA | OWASP Top 10 2021 + **60+ keywords** + **mitigaciones detalladas** | `ag6.json` |

### **Integrante 3: Intelligence & Risk**
| Agente | Herramienta | Función | Salida |
|--------|-------------|---------|--------|
| **AG7** | NVD API | Inteligencia de CVEs | `ag7.json` |
| **AG8** | AbuseIPDB | Threat Intelligence (IOCs) | `ag8.json` |
| **AG9** | Correlación | Análisis consolidado de riesgo | `ag9.json` |

### **Integrante 4: Compliance & Exploitation**
| Agente | Herramienta | Función | Salida |
|--------|-------------|---------|--------|
| **AG10** | Reglas | Mapeo a NIST/CIS/OWASP | `ag10.json` |
| **AG11** | Metasploit DB | Búsqueda de exploits disponibles | `ag11.json` |

---

## 🚀 Instalación

### **Requisitos Previos**

- Python 3.9+
- Ollama (opcional, para análisis con IA)
- Nikto (opcional, para AG4)
- Nuclei (optional, para AG5)

### **Setup Rápido**

```bash
# Clonar repositorio
git clone <tu-repo>
cd secdash

# Ejecutar script de setup (Linux/macOS)
bash setup.sh

# O manualmente:
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt

# Instalar Ollama (opcional)
curl -fsSL https://ollama.com/install.sh | sh
ollama pull minimax-m3:cloud
```

### **Configuración**

Crear archivo `.env` (opcional para APIs reales):

```bash
# Modelos de IA por integrante (Ollama)
# Integrante 1: minimax-m3:cloud (potente)
# Integrante 2: phi3:mini (eficiente)
# Integrante 3: llama3.2:3b (balanceado)
# Integrante 4: qwen2.5-coder:1.5b (rápido)
# Dashboard: minimax-m3:cloud (conversacional)

# APIs reales (opcional)
USE_REAL_APIS=false
NVD_API_KEY=tu_api_key_nvd
ABUSEIPDB_API_KEY=tu_api_key_abuseipdb
```

**Descargar modelos de IA:**

```bash
# Iniciar Ollama
ollama serve

# Descargar todos los modelos
ollama pull minimax-m3:cloud      # Integrante 1 (~20GB)
ollama pull phi3:mini             # Integrante 2 (~2.3GB)
ollama pull llama3.2:3b           # Integrante 3 (~2GB)
ollama pull qwen2.5-coder:1.5b    # Integrante 4 (~900MB)

# Verificar instalación
ollama list
```

---

## 💻 Uso

### **Ejecución Básica**

```bash
# Ejecutar todos los agentes en orden
python run_all_agents.py scanme.nmap.org

# Modo demo (sin herramientas reales)
python run_all_agents.py scanme.nmap.org --mock

# Dashboard
streamlit run dashboard.py
```

### **Ejecución Individual de Agentes**

```bash
# Integrante 1
python integrante1/agent1_discovery.py scanme.nmap.org
python integrante1/agent2_network.py
python integrante1/agent3_surface.py

# Integrante 2
python integrante2/agent4_nikto.py --mock
python integrante2/agent5_nuclei.py --mock
python integrante2/agent6_owasp_classifier.py

# Integrante 3
python integrante3/agent7_cve_intelligence.py
python integrante3/agent8_threat_intel.py
python integrante3/agent9_risk_correlation.py

# Integrante 4
python integrante4/agent10_compliance.py
python integrante4/agent11_metasploit.py
```

---

## 📊 Datos Generados

Todos los agentes generan archivos JSON en `shared_data/`:

```
shared_data/
├── ag1.json    # Activos descubiertos
├── ag2.json    # Servicios detectados
├── ag3.json    # Superficie de ataque
├── ag4.json    # Hallazgos Nikto
├── ag5.json    # Hallazgos Nuclei
├── ag6.json    # Clasificación OWASP
├── ag7.json    # CVEs encontrados
├── ag8.json    # IOCs y reputación
├── ag9.json    # Score de riesgo
├── ag10.json   # Cumplimiento normativo
└── ag11.json   # Exploits disponibles
```

---

## 🎨 Dashboard

El dashboard muestra:

- ✅ **Métricas principales**: Risk Score, CVEs, hallazgos web, puertos abiertos
- ✅ **Servicios expuestos**: Tabla detallada con puertos y versiones
- ✅ **Heatmap OWASP**: Distribución de vulnerabilidades por categoría
- ✅ **Hallazgos web**: Nikto y Nuclei en pestañas separadas
- ✅ **CVE Intelligence**: Tabla con scores CVSS y severidad
- ✅ **Threat Intel**: IOCs con reputación y abuse score
- ✅ **Risk Correlation**: Score consolidado con factores críticos
- ✅ **Compliance**: Mapeo a controles normativos
- ✅ **Chat SOC**: Asistente IA bilingüe

Acceder en: `http://localhost:8501`

---

## 🤖 Chat SOC con IA

El chat integrado permite consultas en español o inglés:

```
Ejemplos de preguntas:

- "¿Cuál es el riesgo más crítico detectado?"
- "Explica los CVEs encontrados"
- "¿Qué servicios están mal configurados?"
- "Dame un resumen del análisis OWASP"
- "What are the priority recommendations?"
```

El asistente cita automáticamente la fuente (AG1-AG11) de cada dato.

---

## ⚙️ Modos de Operación

### **Modo Demo/Mock**
- No requiere herramientas externas
- Genera datos simulados para pruebas
- Ideal para demostraciones y desarrollo

```bash
python run_all_agents.py scanme.nmap.org --mock
```

### **Modo Real**
- Usa Nmap, Nikto, Nuclei
- Consulta APIs reales (NVD, AbuseIPDB)
- **Solo en entornos autorizados**

```bash
# Configurar .env con USE_REAL_APIS=true
python run_all_agents.py <tu-lab.local>
```

---

## 🔐 Consideraciones de Seguridad

⚠️ **IMPORTANTE**: Este proyecto es educativo y para uso en entornos controlados.

- ✅ **Solo escanea objetivos autorizados** (laboratorios propios, scanme.nmap.org)
- ✅ Los agentes incluyen flags de confirmación (`--i-have-permission`)
- ✅ AG11 **NUNCA ejecuta exploits**, solo consulta su existencia
- ❌ **NO usar en producción sin autorización explícita**
- ❌ **NO escanear objetivos sin permiso por escrito**

---

## 📚 Documentación Adicional

- **GUIA_PARA_INTEGRANTES.md**: Guía completa de implementación
- **QUICK_START.md**: Inicio rápido en 5 minutos
- **PROMPTS_PARA_IA.md**: Prompts optimizados para cada agente
- **CHEAT_SHEET.md**: Referencia rápida de 1 página
- **GUION_EXPLICACION.md**: Script para presentaciones

---

## 🛠️ Tecnologías Utilizadas

- **Python 3.9+**: Lenguaje principal
- **Streamlit**: Dashboard interactivo
- **Ollama**: Análisis con IA local
- **Nmap**: Escaneo de red
- **Nikto**: Análisis web básico
- **Nuclei**: Templates de vulnerabilidades
- **NVD API**: Base de datos de CVEs
- **AbuseIPDB**: Threat intelligence

---

## 👥 Créditos

Proyecto desarrollado para el **Curso de Seguridad en Computación**.

**Integrantes:**
- **Integrante 1**: Discovery, Network Scan, Attack Surface
- **Integrante 2**: Web Vulnerability Assessment (Nikto, Nuclei, OWASP)
- **Integrante 3**: CVE Intelligence, Threat Intel, Risk Correlation
- **Integrante 4**: Compliance Mapping, Metasploit Advisory

---

## 📝 Licencia

Este proyecto es educativo y está bajo licencia MIT. Ver `LICENSE` para más detalles.

---

## 🔗 Links Útiles

- [OWASP Top 10 2021](https://owasp.org/www-project-top-ten/)
- [NVD - National Vulnerability Database](https://nvd.nist.gov/)
- [AbuseIPDB](https://www.abuseipdb.com/)
- [Ollama](https://ollama.com/)
- [Nmap](https://nmap.org/)
- [Nikto](https://cirt.net/Nikto2)
- [Nuclei](https://github.com/projectdiscovery/nuclei)

---

**¿Dudas?** Revisa la documentación completa en `GUIA_PARA_INTEGRANTES.md` o contacta al equipo.

**¡Buena caza! 🎯**
