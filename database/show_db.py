import sqlite3

db = sqlite3.connect("nerdy.db")
cur = db.cursor()

print("USERS")

for row in cur.execute("SELECT * FROM users"):
    print(row)

print("\nLOGS")

for row in cur.execute("SELECT * FROM logs ORDER BY data DESC LIMIT 10"):
    print(row)

db.close()