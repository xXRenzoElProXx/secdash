# SecDash AI SOC

Proyecto de seguridad — 4 integrantes, 12 agentes, 1 dashboard.

## Estructura
```
secdash/
├── shared_data/       ← JSONs de salida de cada agente (compartidos)
├── integrante1/       ← Agentes 1, 2, 3
├── integrante2/       ← Agentes 4, 5, 6
├── integrante3/       ← Agentes 7, 8, 9
├── integrante4/       ← Agentes 10, 11, 12
└── dashboard.py       ← Dashboard Streamlit compartido
```

## Setup rápido
```bash
python3 -m venv env
source env/bin/activate
pip install -r requirements.txt
```

## Correr el dashboard
```bash
streamlit run dashboard.py
```
