import sqlite3

db = sqlite3.connect("nerdy.db")
cur = db.cursor()

cur.execute("""
CREATE TABLE IF NOT EXISTS users(
id INTEGER PRIMARY KEY AUTOINCREMENT,
nome TEXT,
usuario TEXT,
senha TEXT,
ip TEXT
)
""")

cur.execute("""
CREATE TABLE IF NOT EXISTS logs(
id INTEGER PRIMARY KEY AUTOINCREMENT,
usuario TEXT,
ip TEXT,
data TEXT,
status TEXT
)
""")

db.commit()

print("Banco criado!")