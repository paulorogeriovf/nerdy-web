import sqlite3

db = sqlite3.connect("nerdy.db")
cur = db.cursor()

# tabela de usuarios
cur.execute("""
CREATE TABLE IF NOT EXISTS users(
id INTEGER PRIMARY KEY AUTOINCREMENT,
nome TEXT,
usuario TEXT,
senha TEXT,
ip TEXT
)
""")

# tabela de logs
cur.execute("""
CREATE TABLE IF NOT EXISTS logs(
id INTEGER PRIMARY KEY AUTOINCREMENT,
usuario TEXT,
ip TEXT,
data TEXT,
status TEXT,
raw_log TEXT
)
""")

db.commit()

print("Banco criado!")