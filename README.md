# 🛡️ Nerdy Security Platform

> Plataforma de Security Intelligence modular para monitoramento de acessos, análise de logs e detecção de ameaças em tempo real.

---

## 📐 Arquitetura

O projeto é dividido em **duas aplicações Flask independentes**:

```
nerdy-web/
├── Aplicacao_Web/               # Site do "cliente" — autenticação e gestão
│   ├── main.py
│   ├── requirements.txt
│   ├── database/
│   │   ├── db.py
│   │   ├── init_db.py
│   │   └── show_db.py
│   ├── templates/
│   │   ├── home.html
│   │   ├── login.html
│   │   ├── parabens.html
│   │   ├── painel_controle.html
│   │   └── log_detail.html
│   └── static/
│       ├── css/
│       │   ├── global.css
│       │   ├── home.css
│       │   ├── login.css
│       │   └── dashboard.css
│       ├── js/
│       └── images/
│
├── Dashboard/      # Dashboard de análise — logs e métricas
│   ├── main.py
│   ├── requirements.txt
│   ├── templates/
│   │   ├── dashboard.html
│   │   └── log_detail.html
│   └── static/
│       ├── css/
│       │   ├── global.css
│       │   └── dashboard.css
│       ├── js/
│       └── images/
│
└── README.md
```

---

## 🔄 Fluxo de dados

```
[Usuário faz login no client_app]
        │
        ▼
[client_app salva log no banco local (nerdy.db)]
        │
        ▼
[client_app envia log via POST /ingest → analytics_dashboard]
        │
        ▼
[analytics_dashboard salva em analytics.db]
        │
        ▼
[Dashboard exibe métricas em tempo real via polling /logs_json]
```

---

## 🚀 Como rodar

### 1. Aplicacao_Web (porta 5000)

```bash
cd Aplicacao_Web

# Criar e ativar o venv
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # Linux/Mac

# Instalar dependências
pip install -r requirements.txt

# Criar banco de dados (cria admin padrão)
python database\init_db.py

# Iniciar servidor
python main.py
```

Acesse: **http://localhost:5000**

### 2. Dashboard (porta 5001)

```bash
cd dashboard

# Criar e ativar o venv
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # Linux/Mac

# Instalar dependências
pip install -r requirements.txt

# Iniciar servidor (banco criado automaticamente)
python main.py
```

Acesse: **http://localhost:5001**

---

## 🔐 Credenciais padrão

| Campo   | Valor             |
|---------|-------------------|
| Usuário | `admin`           |
| Senha   | `.....` |

### Como alterar a senha do admin

No terminal, dentro de `client_app`:

```python
python3
```

```python
import bcrypt, sqlite3

nova_senha = "SUA_NOVA_SENHA"
hash = bcrypt.hashpw(nova_senha.encode(), bcrypt.gensalt()).decode()

db = sqlite3.connect("database/nerdy.db")
db.execute("UPDATE users SET senha=? WHERE usuario='admin'", (hash,))
db.commit()
db.close()

print("Senha alterada com sucesso!")
```

---

## 🧩 Funcionalidades

### Aplicacao_Web
- ✅ Login com rate limiting (bloqueio após 5 tentativas)
- ✅ Senhas com hash bcrypt (nunca salvas em texto puro)
- ✅ Painel de controle — cadastrar, listar e remover usuários
- ✅ Logs recentes no painel administrativo
- ✅ Envio automático de logs para o analytics via `POST /ingest`
- ✅ Página de boas-vindas para usuário comum

### Dashboard
- ✅ Recebe logs via `POST /ingest`
- ✅ Dashboard com gráfico doughnut (Chart.js)
- ✅ Mapa de acessos ao vivo (Leaflet + ip-api) — funciona com IPs públicos
- ✅ Polling automático a cada 3 segundos
- ✅ Filtro de logs por IP ou usuário
- ✅ Expandir/recolher tabela de logs
- ✅ Detalhes completos do log com parsing do raw_log
- ✅ Detecção de brute force (≥ 20 falhas por IP)
- ✅ Top 5 IPs mais ativos

---

## 🛠️ Stack

| Camada    | Tecnologia                    |
|-----------|-------------------------------|
| Backend   | Python + Flask                |
| Segurança | bcrypt                        |
| Banco     | SQLite                        |
| Frontend  | HTML5 + CSS3 (vanilla)        |
| Gráficos  | Chart.js                      |
| Mapa      | Leaflet.js + ip-api.com       |
| Parsing   | RegEx (Python)                |
| Fontes    | IBM Plex Mono + Syne (Google) |

---

## 📊 Endpoints

### Aplicacao_Web (`:5000`)

| Método   | Rota                | Descrição                       |
|----------|---------------------|---------------------------------|
| GET      | `/`                 | Landing page                    |
| GET/POST | `/login`            | Autenticação                    |
| GET      | `/parabens`         | Pós-login usuário comum         |
| GET      | `/painel`           | Painel de controle (admin)      |
| GET/POST | `/register`         | Cadastrar usuário (admin)       |
| GET      | `/delete_user/<id>` | Remover usuário (admin)         |
| GET      | `/reset_logs`       | Apagar todos os logs (admin)    |
| GET      | `/logs_json`        | API JSON de logs (admin)        |
| GET      | `/check_block`      | Verificar bloqueio de IP (AJAX) |
| GET      | `/logout`           | Encerrar sessão                 |

### Dashboard (`:5001`)

| Método | Rota          | Descrição                        |
|--------|---------------|----------------------------------|
| GET    | `/`           | Dashboard visual                 |
| POST   | `/ingest`     | Receber log do client_app        |
| GET    | `/log/<id>`   | Detalhe de um log                |
| GET    | `/logs_json`  | Retornar todos os eventos (JSON) |
| GET    | `/stats_json` | Retornar estatísticas (JSON)     |
| GET    | `/reset_logs` | Limpar eventos                   |

---

## 📁 Utilitários

```bash
# Ver usuários e logs no banco
cd client_app
python database\show_db.py
```

---

## 🗺️ Mapa de acessos

O mapa usa a API pública `ip-api.com` para geolocalizar IPs.
- IPs privados (`127.0.0.1`, `192.168.x.x`, etc.) **não aparecem** no mapa — comportamento esperado
- Em ambiente local o mapa fica aguardando — funciona normalmente em produção com IPs públicos reais

---

## 📝 Observações

- Em produção configure `SECRET_KEY` e `DASHBOARD_SECRET` como variáveis de ambiente seguras
- O `analytics_dashboard` não possui autenticação própria — recomenda-se colocá-lo em rede interna ou atrás de VPN em produção
- O banco `.db` **não deve ser commitado** no Git (já incluso no `.gitignore`)

---

## 👥 Projeto

Desenvolvido para apresentação acadêmica — **Projeto Unip 2026**
Plataforma: **Nerdy Security Intelligence**