# CyberSentinel Log Analyzer

Projeto de cibersegurança em Python 

O **CyberSentinel Log Analyzer** analisa logs de autenticação e identifica padrões suspeitos, como:
- múltiplas tentativas de login falhas;
- possíveis ataques de força bruta;
- usuários mais visados;
- IPs com atividade anormal.

## Objetivo
Este projeto foi criado para demonstrar conhecimentos de:
- Python;
- análise de logs;
- detecção de comportamento suspeito;
- organização de projeto para GitHub;
- geração de relatórios em JSON.

## Estrutura

```bash
cybersentinel-log-analyzer/
├── data/
│   └── sample_auth.log
├── src/
│   ├── __init__.py
│   └── analyzer.py
├── tests/
│   └── test_analyzer.py
├── .gitignore
├── LICENSE
├── requirements.txt
└── README.md
```

## Como executar

### 1. Clonar ou baixar o projeto
```bash
git clone <seu-repositorio>
cd cybersentinel-log-analyzer
```

### 2. Criar ambiente virtual
```bash
python -m venv .venv
```

### 3. Ativar ambiente virtual
**Windows:**
```bash
.venv\Scripts\activate
```

**Linux/macOS:**
```bash
source .venv/bin/activate
```

### 4. Instalar dependências
```bash
pip install -r requirements.txt
```

### 5. Rodar o projeto
```bash
python -m src.analyzer data/sample_auth.log --threshold 5 --output report.json
```

## Exemplo de saída
```bash
=== CyberSentinel Security Report ===
Total events: 18
Failed logins: 14
Successful logins: 4
Unique IPs: 5

Top IPs by activity:
- 203.0.113.77: 6 events
- 192.168.0.10: 6 events
- 172.16.1.8: 2 events
- 198.51.100.22: 3 events
- 10.0.0.5: 1 events
```

## Ideias para melhorar depois
- dashboard web com Flask;
- exportação em CSV;
- geolocalização de IP;
- alertas em tempo real;
- leitura de logs reais do Linux/Windows;
- interface gráfica.


## Observação ética
Este projeto é **defensivo e educacional**, focado em monitoramento e análise de segurança.

## Licença
MIT
