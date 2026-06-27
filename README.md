# SecDash AI SOC

**SecDash AI SOC** es una plataforma académica de análisis automatizado de ciberseguridad basada en agentes especializados e inteligencia artificial. Su objetivo es simular el funcionamiento de un **Security Operations Center (SOC)** mediante la ejecución coordinada de agentes que analizan un objetivo, generan archivos JSON y presentan los resultados en un dashboard desarrollado con **Streamlit**.

La plataforma integra análisis de descubrimiento, red, superficie de ataque, escaneo web, clasificación OWASP, inteligencia CVE, threat intelligence, correlación de riesgo, compliance, explotación conocida y un panel de consulta asistido por IA.

---

## 1. Descripción general del proyecto

SecDash centraliza el trabajo de varios agentes de seguridad. Cada agente ejecuta una tarea específica y guarda sus resultados en la carpeta `shared_data/`. Luego, el archivo principal `dashboard.py` lee esos archivos JSON, calcula métricas y presenta la información en una interfaz visual.

El dashboard no reemplaza a las herramientas de seguridad tradicionales. Su función principal es **orquestar, visualizar y correlacionar resultados** para apoyar el análisis de seguridad en un entorno académico.

---

## 2. Tecnologías utilizadas

| Componente | Tecnología |
|---|---|
| Lenguaje principal | Python 3 |
| Interfaz web | Streamlit |
| Procesamiento de datos | Pandas |
| Formato de intercambio | JSON |
| Ejecución de agentes | subprocess |
| IA conversacional | Ollama compatible con API OpenAI |
| Modelo IA configurado | `minimax-m3:cloud` |
| Entorno recomendado | Kali Linux |
| Carpeta de resultados | `shared_data/` |
| Control de versiones | Git / GitHub |

---

## 3. Arquitectura general

El flujo de SecDash es el siguiente:

```text
Usuario
  ↓
Dashboard Streamlit
  ↓
Ejecución de agentes especializados
  ↓
Generación de archivos JSON en shared_data/
  ↓
Lectura y normalización de resultados
  ↓
Visualización en métricas, tablas, gráficos y tarjetas
  ↓
Consulta mediante chatbot IA con contexto del dashboard
```

---

## 4. Estructura del proyecto

Estructura esperada del repositorio:

```text
secdash/
├── dashboard.py
├── styles.py
├── requirements.txt
├── .env
├── .env.example
├── .gitignore
├── README.md
│
├── integrante1/
│   ├── agent1_discovery.py
│   ├── agent2_network.py
│   └── agent3_surface.py
│
├── integrante2/
│   ├── agent4_nikto.py
│   ├── agent5_nuclei.py
│   └── agent6_owasp_classifier.py
│
├── integrante3/
│   ├── agent7_cve_intelligence.py
│   ├── agent8_threat_intel.py
│   └── agent9_risk_correlation.py
│
├── integrante4/
│   ├── agent10_compliance.py
│   └── agent11_metasploit.py
│
└── shared_data/
    ├── ag1.json
    ├── ag2.json
    ├── ag3.json
    ├── ag4.json
    ├── ag5.json
    ├── ag6.json
    ├── ag7.json
    ├── ag8.json
    ├── ag9.json
    ├── ag10.json
    ├── ag11.json
    └── chat_history.json
```

Nota técnica: en el código se cargan archivos del `ag1.json` al `ag12.json`, y el `AG12` aparece como `CHATBOT`. Sin embargo, la ejecución automática lanza 11 scripts de agentes. El chatbot se encuentra integrado dentro de `dashboard.py` y guarda su historial en `shared_data/chat_history.json`.

---

## 5. Agentes del sistema

| Agente | Nombre | Archivo | Función principal | Salida esperada |
|---|---|---|---|---|
| AG1 | Discovery | `integrante1/agent1_discovery.py` | Identifica el objetivo, dominio o IP inicial. | `shared_data/ag1.json` |
| AG2 | Network | `integrante1/agent2_network.py` | Analiza servicios, puertos, firewall, IDS/IPS y SSL/TLS. | `shared_data/ag2.json` |
| AG3 | Surface | `integrante1/agent3_surface.py` | Evalúa superficie de ataque, activos críticos, hardening y exposición. | `shared_data/ag3.json` |
| AG4 | Nikto | `integrante2/agent4_nikto.py` | Simula o ejecuta hallazgos web con enfoque Nikto. | `shared_data/ag4.json` |
| AG5 | Nuclei | `integrante2/agent5_nuclei.py` | Simula o ejecuta hallazgos web mediante plantillas Nuclei. | `shared_data/ag5.json` |
| AG6 | OWASP | `integrante2/agent6_owasp_classifier.py` | Clasifica hallazgos según OWASP Top 10. | `shared_data/ag6.json` |
| AG7 | CVE Intelligence | `integrante3/agent7_cve_intelligence.py` | Relaciona servicios detectados con vulnerabilidades CVE. | `shared_data/ag7.json` |
| AG8 | Threat Intelligence | `integrante3/agent8_threat_intel.py` | Analiza reputación de IPs, IOCs y señales de amenaza. | `shared_data/ag8.json` |
| AG9 | Risk Correlation | `integrante3/agent9_risk_correlation.py` | Calcula score de riesgo consolidado de 0 a 100. | `shared_data/ag9.json` |
| AG10 | Compliance | `integrante4/agent10_compliance.py` | Evalúa controles, cumplimiento, excepciones y controles compensatorios. | `shared_data/ag10.json` |
| AG11 | Metasploit Advisory | `integrante4/agent11_metasploit.py` | Prioriza CVEs según exploits, Metasploit, ExploitDB, GitHub PoC y mitigaciones. | `shared_data/ag11.json` |
| AG12 | Chatbot | Integrado en `dashboard.py` | Permite consultar los resultados con IA usando contexto del SOC. | `shared_data/chat_history.json` |

---

## 6. Flujo de ejecución de los agentes

Cuando el usuario presiona el botón **EXECUTE ALL AGENTS** en el dashboard, se ejecuta la siguiente secuencia:

```python
steps = [
    ("AG1: Asset discovery",      ["python", "integrante1/agent1_discovery.py", target_input], 9),
    ("AG2: Network scan",         ["python", "integrante1/agent2_network.py"], 18),
    ("AG3: Attack surface",       ["python", "integrante1/agent3_surface.py"], 27),
    ("AG4: Nikto scan (mock)",    ["python", "integrante2/agent4_nikto.py", "--mock"], 36),
    ("AG5: Nuclei scan (mock)",   ["python", "integrante2/agent5_nuclei.py", "--mock"], 45),
    ("AG6: OWASP classifier",     ["python", "integrante2/agent6_owasp_classifier.py"], 54),
    ("AG7: CVE intelligence",     ["python", "integrante3/agent7_cve_intelligence.py"], 63),
    ("AG8: Threat intelligence",  ["python", "integrante3/agent8_threat_intel.py"], 72),
    ("AG9: Risk correlation",     ["python", "integrante3/agent9_risk_correlation.py"], 81),
    ("AG10: Compliance check",    ["python", "integrante4/agent10_compliance.py"], 90),
    ("AG11: Metasploit advisory", ["python", "integrante4/agent11_metasploit.py"], 100),
]
```

Cada agente tiene un tiempo máximo de ejecución de 120 segundos mediante `subprocess.run(..., timeout=120)`.

---

## 7. Setup rápido en Kali

### 7.1. Clonar el repositorio e instalar dependencias

```bash
code

cd ~
git clone https://github.com/xXRenzoElProXx/secdash.git
cd ~/secdash
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
pip install openai
```

### 7.2. Crear archivo `.env`

No se recomienda subir claves reales a GitHub. En el repositorio debe publicarse un archivo `.env.example` y cada usuario debe crear su propio `.env` local.

Crear el archivo `.env`:

```bash
cat > .env <<'EOF'
# ========================================
# CONFIGURACIÓN SECDASH - SecDash AI SOC
# ========================================
# Archivo configurado localmente
# No subir este archivo a GitHub

# === MODO DE OPERACIÓN ===
USE_REAL_APIS=true

# === API KEYS EXTERNAS ===
# NVD API - National Vulnerability Database
NVD_API_KEY=REEMPLAZAR_CON_TU_NVD_API_KEY

# AbuseIPDB API - IP Reputation Database
ABUSEIPDB_API_KEY=REEMPLAZAR_CON_TU_ABUSEIPDB_API_KEY

# === CONFIGURACIÓN IA ===
USE_OLLAMA=true
OLLAMA_BASE_URL=http://127.0.0.1:11434/v1
OLLAMA_API_KEY=ollama
SECDASH_AI_MODEL=minimax-m3:cloud
EOF
```

### 7.3. Levantar Ollama

En una terminal:

```bash
ollama serve
```

En otra terminal, dentro del proyecto:

```bash
source venv/bin/activate
ollama pull minimax-m3:cloud
```

### 7.4. Ejecutar el dashboard

```bash
streamlit run dashboard.py
```

Luego abrir la URL que Streamlit muestre en consola, normalmente:

```text
http://localhost:8501
```

---

## 8. Archivo `.env.example` recomendado

Para documentar la configuración sin exponer secretos, se recomienda crear un archivo `.env.example`:

```bash
cat > .env.example <<'EOF'
USE_REAL_APIS=true

NVD_API_KEY=REEMPLAZAR_CON_TU_NVD_API_KEY
ABUSEIPDB_API_KEY=REEMPLAZAR_CON_TU_ABUSEIPDB_API_KEY

USE_OLLAMA=true
OLLAMA_BASE_URL=http://127.0.0.1:11434/v1
OLLAMA_API_KEY=ollama
SECDASH_AI_MODEL=minimax-m3:cloud
EOF
```

---

## 9. Archivo `.gitignore` recomendado

Para evitar subir información sensible o archivos generados:

```gitignore
venv/
.env
__pycache__/
*.pyc
shared_data/*.json
!shared_data/.gitkeep
.streamlit/
```

## 10. Ejecución manual de agentes

Aunque el dashboard puede ejecutar todos los agentes, también pueden ejecutarse manualmente para pruebas:

```bash
source venv/bin/activate

python integrante1/agent1_discovery.py scanme.nmap.org
python integrante1/agent2_network.py
python integrante1/agent3_surface.py

python integrante2/agent4_nikto.py --mock
python integrante2/agent5_nuclei.py --mock
python integrante2/agent6_owasp_classifier.py

python integrante3/agent7_cve_intelligence.py
python integrante3/agent8_threat_intel.py
python integrante3/agent9_risk_correlation.py

python integrante4/agent10_compliance.py
python integrante4/agent11_metasploit.py
```

---


## 11. Chatbot IA

El dashboard incluye un panel de chat conectado a un modelo compatible con la API de OpenAI. Por defecto usa:

```text
minimax-m3:cloud
```

Configuración relacionada:

```env
USE_OLLAMA=true
OLLAMA_BASE_URL=http://127.0.0.1:11434/v1
OLLAMA_API_KEY=ollama
SECDASH_AI_MODEL=minimax-m3:cloud
```

El chatbot utiliza los datos actuales del dashboard como contexto. Puede responder preguntas como:

```text
¿Qué CVEs son más críticos?
¿Qué puerto representa mayor riesgo?
¿Qué debería parchearse primero?
¿Qué hallazgos están relacionados con OWASP?
¿Qué significa el risk score?
¿Qué controles de compliance fallaron?
```

Si el modelo no está disponible, el dashboard usa una respuesta de respaldo básica.

---

## 14. Archivos JSON generados

Los agentes comparten información mediante la carpeta `shared_data/`.

Ejemplo de archivos esperados:

```text
shared_data/ag1.json   → discovery del objetivo
shared_data/ag2.json   → servicios, puertos, firewall, SSL/TLS
shared_data/ag3.json   → superficie de ataque y activos críticos
shared_data/ag4.json   → hallazgos Nikto
shared_data/ag5.json   → hallazgos Nuclei
shared_data/ag6.json   → clasificación OWASP
shared_data/ag7.json   → CVEs detectados
shared_data/ag8.json   → threat intelligence e IOCs
shared_data/ag9.json   → correlación de riesgo
shared_data/ag10.json  → compliance
shared_data/ag11.json  → exploits y priorización
shared_data/chat_history.json → historial del chatbot
```

---

## 15. Requisitos mínimos

- Kali Linux o Linux compatible.
- Python 3.
- Git.
- pip.
- Entorno virtual de Python.
- Ollama instalado.
- Acceso a internet para instalar dependencias y descargar el modelo.
- API keys externas si se usa `USE_REAL_APIS=true`.

---

## 16. Instalación de herramientas adicionales en Kali

Si el sistema no tiene herramientas básicas instaladas:

```bash
sudo apt update
sudo apt install -y git python3 python3-venv python3-pip
```

Si se desea usar herramientas reales de escaneo web en lugar de datos simulados, se puede instalar Nikto y Nuclei según la configuración de los agentes:

```bash
sudo apt install -y nikto
```

Para Nuclei, revisar la instalación oficial correspondiente al entorno. Si los agentes están en modo `--mock`, Nuclei no es obligatorio para la demostración.

---

## 17. Comandos principales

Activar entorno virtual:

```bash
source venv/bin/activate
```

Instalar dependencias:

```bash
pip install -r requirements.txt
pip install openai
```

Levantar Ollama:

```bash
ollama serve
```

Descargar modelo IA:

```bash
ollama pull minimax-m3:cloud
```

Ejecutar dashboard:

```bash
streamlit run dashboard.py
```


SecDash AI SOC es una plataforma que integra múltiples agentes de ciberseguridad en un único dashboard. Cada agente analiza una parte del problema, genera información estructurada en JSON y el dashboard consolida esos datos en una vista operativa.

El sistema cubre descubrimiento, red, superficie de ataque, escaneo web, OWASP, CVEs, threat intelligence, compliance, exploits y análisis asistido por IA.
