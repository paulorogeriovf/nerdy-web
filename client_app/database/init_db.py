"""
Inicializa o banco de dados da Client App.

Usuário padrão criado:
  usuario : admin
  senha   : projetounip2026

Para alterar a senha do admin depois:
  1. Abra o Python na raiz do client_app:
       python3
  2. Execute:
       import bcrypt, sqlite3
       nova = bcrypt.hashpw(b"SUA_NOVA_SENHA", bcrypt.gensalt()).decode()
       db = sqlite3.connect("nerdy.db")
       db.execute("UPDATE users SET senha=? WHERE usuario='admin'", (nova,))
       db.commit()
       db.close()
       print("Senha alterada!")
"""

import sqlite3
import bcrypt
import os

DB_PATH = os.environ.get("DB_PATH", os.path.join(os.path.dirname(os.path.abspath(__file__)), "nerdy.db"))

db  = sqlite3.connect(DB_PATH)
cur = db.cursor()

# ── Tabela de usuários (com coluna is_admin) ──────────────────────────────────
cur.execute("""
CREATE TABLE IF NOT EXISTS users (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    nome     TEXT    NOT NULL,
    usuario  TEXT    NOT NULL UNIQUE,
    senha    TEXT    NOT NULL,
    ip       TEXT,
    is_admin INTEGER NOT NULL DEFAULT 0
)
""")

# ── Tabela de logs ────────────────────────────────────────────────────────────
cur.execute("""
CREATE TABLE IF NOT EXISTS logs (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    usuario TEXT,
    ip      TEXT,
    data    TEXT,
    status  TEXT,
    raw_log TEXT
)
""")

# ── Admin padrão (só cria se não existir) ─────────────────────────────────────
cur.execute("SELECT id FROM users WHERE usuario='admin'")
if not cur.fetchone():
    senha_hash = bcrypt.hashpw(b"projetounip2026", bcrypt.gensalt()).decode()
    cur.execute(
        "INSERT INTO users(nome, usuario, senha, ip, is_admin) VALUES(?,?,?,?,?)",
        ("Administrador", "admin", senha_hash, "", 1)
    )
    print("Usuário admin criado  →  usuario: admin  |  senha: projetounip2026")
else:
    print("Usuário admin já existe, pulando criação.")

db.commit()
db.close()

print("Banco de dados inicializado com sucesso!")
print()
print("Para alterar a senha do admin, veja as instruções no topo deste arquivo.")