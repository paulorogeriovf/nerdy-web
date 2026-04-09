"""
Exibe usuários e logs recentes do banco de dados.
Execute: python3 show_db.py
"""
import sqlite3
import os

DB_PATH = os.environ.get("DB_PATH", os.path.join(os.path.dirname(os.path.abspath(__file__)), "nerdy.db"))
db  = sqlite3.connect(DB_PATH)
cur = db.cursor()

print("=" * 60)
print("USUÁRIOS")
print("=" * 60)
for row in cur.execute("SELECT id, nome, usuario, ip, is_admin FROM users"):
    admin_tag = " [ADMIN]" if row[4] else ""
    print(f"  ID={row[0]}  nome={row[1]}  usuario={row[2]}  ip={row[3]}{admin_tag}")

print()
print("=" * 60)
print("LOGS (últimos 10)")
print("=" * 60)
for row in cur.execute("SELECT id, usuario, ip, data, status FROM logs ORDER BY data DESC LIMIT 10"):
    print(f"  ID={row[0]}  usuario={row[1]}  ip={row[2]}  data={row[3]}  status={row[4]}")

db.close()