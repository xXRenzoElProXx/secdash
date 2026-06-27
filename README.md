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

También puede crearse el archivo vacío:

```bash
mkdir -p shared_data
touch shared_data/.gitkeep
```

---

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

## 11. Funcionamiento del dashboard

El archivo principal `dashboard.py` realiza estas tareas:

1. Configura la interfaz de Streamlit.
2. Carga estilos visuales desde `styles.py`.
3. Lee archivos JSON desde `shared_data/`.
4. Normaliza datos complejos para poder mostrarlos como tablas.
5. Calcula métricas generales de seguridad.
6. Muestra estado de agentes en la barra lateral.
7. Permite ingresar un dominio o IP objetivo.
8. Ejecuta todos los agentes mediante `subprocess.run`.
9. Presenta resultados en secciones: Overview, Network, Web Scans, OWASP, CVE Intel, Threat Intel, Risk Score, Compliance y Exploits.
10. Integra un chatbot con IA que responde usando el contexto actual del dashboard.

---

## 12. Secciones principales del dashboard

### 12.1. Target Acquisition

Permite ingresar el objetivo a analizar, por ejemplo:

```text
scanme.nmap.org
example.com
192.168.1.1
```

El botón **EXECUTE ALL AGENTS** inicia la ejecución secuencial de los agentes.

### 12.2. Overview

Muestra métricas generales:

- Risk Score.
- CVEs detectados.
- Hallazgos web.
- Puertos abiertos.
- Estado de ejecución de agentes.

### 12.3. Network

Usa datos de `ag2.json` para mostrar:

- Servicios expuestos.
- Puertos abiertos.
- Firewall detectado.
- IDS/IPS detectado.
- Servicios SSL/TLS.
- Problemas de seguridad de red.

### 12.4. Attack Surface

Usa datos de `ag3.json` para mostrar:

- Activos críticos.
- Control de acceso.
- Servicios sin autenticación.
- Puertos administrativos expuestos.
- Recomendaciones ACL.
- Medidas de hardening.
- Vectores de post-explotación.

### 12.5. Web Scans

Usa datos de `ag4.json` y `ag5.json` para mostrar hallazgos de:

- Nikto.
- Nuclei.

En el código actual, ambos agentes se ejecutan con `--mock`, por lo que pueden trabajar con datos simulados o controlados.

### 12.6. OWASP

Usa `ag6.json` para clasificar hallazgos según OWASP Top 10 mediante un mapa o gráfico de severidad.

### 12.7. CVE Intelligence

Usa `ag7.json` para mostrar:

- CVEs encontrados.
- Severidad.
- Servicio asociado.
- Puerto asociado.
- CVSS, si está disponible.
- Análisis generado por IA, si existe.

### 12.8. Threat Intelligence

Usa `ag8.json` para mostrar:

- IOCs.
- IPs maliciosas o sospechosas.
- Reputación.
- Abuse score.
- Técnicas MITRE ATT&CK asociadas.
- Indicadores de amenaza.

### 12.9. Risk Score

Usa `ag9.json` para presentar:

- Score total de 0 a 100.
- Nivel de riesgo.
- Factores críticos.
- Fuentes usadas.
- Fuentes faltantes.
- Recomendación inmediata.

Si `ag9.json` no existe, el dashboard calcula un score básico de respaldo con servicios detectados, presencia de SSH y activos críticos.

### 12.10. Compliance

Usa `ag10.json` para mostrar:

- Total de controles.
- Controles cumplidos.
- Controles fallidos.
- Controles parciales.
- Porcentaje de cumplimiento.
- Evaluación por framework.
- Excepciones.
- Controles compensatorios.

### 12.11. Exploits

Usa `ag11.json` para mostrar:

- CVEs con módulo de Metasploit.
- CVEs con ExploitDB.
- CVEs con PoC en GitHub.
- CVEs sin exploit público.
- Probabilidad de explotación.
- Prioridad de parcheo P0, P1, P2 o P3.
- Mitigaciones recomendadas.

---

## 13. Chatbot IA

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

---

## 18. Consideraciones de seguridad

Este proyecto debe usarse únicamente en entornos autorizados, académicos o de laboratorio.

No ejecutar escaneos sobre sistemas de terceros sin permiso explícito.

No subir el archivo `.env` a GitHub.

No publicar API keys reales dentro del README.

Validar el objetivo antes de ejecutar agentes.

Revisar los hallazgos antes de considerarlos evidencia concluyente.

Los resultados generados por IA deben tomarse como apoyo analítico, no como dictamen final.

---

## 19. Puntos técnicos importantes del código

### 19.1. Carga de JSON

El dashboard usa la función `load_json(n)` para cargar archivos como:

```text
shared_data/ag1.json
shared_data/ag2.json
...
shared_data/ag11.json
```

Si un archivo no existe, devuelve `None` y el dashboard continúa funcionando.

### 19.2. Normalización de datos

El código incluye funciones para convertir listas, diccionarios, fechas, tuplas y conjuntos en valores compatibles con `pandas.DataFrame`.

Esto evita errores al mostrar datos complejos en tablas de Streamlit.

### 19.3. Cálculo de riesgo

Si existe `ag9.json`, el score se toma del agente de correlación:

```python
score = ag[9].get("score_total", 0)
nivel = ag[9].get("nivel", "BAJO")
```

Si no existe, se calcula un score básico a partir de:

- Cantidad de servicios expuestos.
- Cantidad de activos de riesgo alto.
- Presencia de SSH.
- Número de servicios detectados.

### 19.4. Ejecución segura de agentes

Los agentes se ejecutan con `subprocess.run` sin `shell=True`, lo que reduce el riesgo de inyección de comandos.

Además, cada agente tiene un límite de ejecución de 120 segundos.

### 19.5. Interfaz visual

El dashboard usa HTML personalizado con `unsafe_allow_html=True` para mejorar el diseño. Esto permite tarjetas, colores, animaciones y paneles visuales, pero requiere cuidado con datos dinámicos provenientes de archivos externos.

---

## 20. Mejoras recomendadas

- Unificar la numeración: decidir si el sistema tiene 11 agentes más chatbot o 12 agentes formales.
- Reemplazar `except:` genéricos por excepciones específicas.
- Validar dominio o IP antes de ejecutar el agente 1.
- Sanitizar texto antes de insertarlo en HTML.
- Evitar subir `shared_data/*.json` si contienen resultados sensibles.
- Crear documentación para cada agente por separado.
- Separar configuración real y configuración de demostración.
- Permitir elegir entre modo `mock` y modo real desde el dashboard.
- Agregar pruebas unitarias para funciones de carga, normalización y cálculo de score.

---

## 21. Uso académico

SecDash AI SOC fue diseñado como una plataforma académica para demostrar:

- Automatización de análisis de seguridad.
- Orquestación de agentes.
- Uso de JSON como formato común de intercambio.
- Visualización de datos de ciberseguridad.
- Priorización de vulnerabilidades.
- Correlación de riesgo.
- Integración de inteligencia artificial en un SOC simulado.

---

## 22. Resumen final

SecDash AI SOC es una plataforma que integra múltiples agentes de ciberseguridad en un único dashboard. Cada agente analiza una parte del problema, genera información estructurada en JSON y el dashboard consolida esos datos en una vista operativa.

El sistema cubre descubrimiento, red, superficie de ataque, escaneo web, OWASP, CVEs, threat intelligence, compliance, exploits y análisis asistido por IA.
