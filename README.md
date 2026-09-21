# CyberSentinel

Dashboard defensivo para análise de logs de autenticação. O sistema processa arquivos `.log`/`.txt` como texto, identifica padrões de tentativas falhas e brute force, persiste resultados em SQLite e apresenta telemetria real no dashboard.

## Recursos

- Dashboard SOC responsivo com métricas calculadas do banco local
- Série histórica real das análises e alertas
- Risk Score derivado de falhas e IPs suspeitos (indicador heurístico, não probabilidade)
- Upload drag-and-drop, threshold configurável e parser seguro
- Histórico pesquisável, detalhes, exclusão e download do relatório JSON
- Login por `.env`, CSRF, cookies HttpOnly e headers de segurança
- SQLite, auditoria, Docker, Gunicorn e exemplo Nginx/HTTPS
- Interface com microinterações, profundidade 3D e suporte a `prefers-reduced-motion`

## Rodar no Windows

```powershell
python -m venv .venv
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env
python app.py
```

Abra `http://127.0.0.1:5000`.

O `.env.example` desta demonstração usa `admin` / `admin123`. Troque a senha e a chave secreta antes de qualquer implantação compartilhada. Para gerar outro hash:

```powershell
python -c "from werkzeug.security import generate_password_hash; print(generate_password_hash('SUA-SENHA-FORTE'))"
```

Cole o hash completo em `CYBERSENTINEL_PASSWORD_HASH`.

## Formato do log

```text
2026-05-01 10:00:00 IP=10.0.0.1 USER=admin ACTION=login STATUS=failed
```

## Testes

```powershell
python -m pip install -r requirements-dev.txt
pytest -q
```

> O Risk Score é uma heurística visual baseada nos dados ingeridos. Ele não representa probabilidade estatística de comprometimento nem substitui SIEM/EDR profissional.
