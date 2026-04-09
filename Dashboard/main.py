"""
Analytics Dashboard — Nerdy Security
Aplicação independente que:
  • Recebe logs tratados via POST /ingest
  • Expõe os dados via GET /logs_json
  • Serve o dashboard visual em /
"""
from flask import Flask, render_template, request, jsonify, redirect, session
import sqlite3
import os

app = Flask(__name__)
app.secret_key = os.environ.get("DASHBOARD_SECRET", "nerdy_dash_secret")

DB_PATH = os.environ.get("DASHBOARD_DB", os.path.join(os.path.dirname(__file__), "analytics.db"))


# ─── DB ───────────────────────────────────────────────────────────────────────
def get_db():
    return sqlite3.connect(DB_PATH)


def init_db():
    db  = get_db()
    cur = db.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario  TEXT,
            ip       TEXT,
            data     TEXT,
            status   TEXT,
            raw_log  TEXT,
            received TEXT DEFAULT (datetime('now'))
        )
    """)
    db.commit()
    db.close()


# ─── INGEST (recebe logs do client_app) ──────────────────────────────────────
@app.route("/ingest", methods=["POST"])
def ingest():
    """
    Endpoint chamado pelo client_app após cada evento de login.
    Payload esperado (JSON):
      { usuario, ip, data, status, raw_log, user_agent, endpoint }
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "invalid payload"}), 400

    db  = get_db()
    cur = db.cursor()
    cur.execute(
        "INSERT INTO events(usuario, ip, data, status, raw_log) VALUES(?,?,?,?,?)",
        (
            data.get("usuario", ""),
            data.get("ip", ""),
            data.get("data", ""),
            data.get("status", ""),
            data.get("raw_log", ""),
        )
    )
    db.commit()
    db.close()
    return jsonify({"ok": True}), 201


# ─── API JSON (para o dashboard JS) ──────────────────────────────────────────
@app.route("/logs_json")
def logs_json():
    db  = get_db()
    cur = db.cursor()
    cur.execute(
        "SELECT id, usuario, ip, data, status, raw_log FROM events ORDER BY data DESC"
    )
    logs = [
        {"id": r[0], "usuario": r[1], "ip": r[2], "data": r[3], "status": r[4], "raw_log": r[5]}
        for r in cur.fetchall()
    ]
    db.close()
    return jsonify({"logs": logs})


# ─── STATS JSON (para cards do dashboard) ────────────────────────────────────
@app.route("/stats_json")
def stats_json():
    db  = get_db()
    cur = db.cursor()

    cur.execute("SELECT COUNT(*) FROM events")
    total = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM events WHERE status='sucesso'")
    sucessos = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM events WHERE status='falha'")
    falhas = cur.fetchone()[0]

    cur.execute("""
        SELECT ip, COUNT(*) as c FROM events
        GROUP BY ip ORDER BY c DESC LIMIT 5
    """)
    top_ips = [{"ip": r[0], "total": r[1]} for r in cur.fetchall()]

    cur.execute("""
        SELECT ip, COUNT(*) as c FROM events
        WHERE status='falha'
        GROUP BY ip HAVING c >= 20
    """)
    brute_force = [{"ip": r[0], "total": r[1]} for r in cur.fetchall()]

    db.close()
    return jsonify({
        "total_logs": total,
        "sucessos":   sucessos,
        "falhas":     falhas,
        "top_ips":    top_ips,
        "brute_force": brute_force,
    })


# ─── DASHBOARD HTML ───────────────────────────────────────────────────────────
@app.route("/")
def dashboard():
    db  = get_db()
    cur = db.cursor()

    cur.execute("SELECT COUNT(*) FROM events")
    total_logs = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM events WHERE status='sucesso'")
    sucessos = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM events WHERE status='falha'")
    falhas = cur.fetchone()[0]

    cur.execute("""
        SELECT ip, COUNT(ip) as total FROM events
        GROUP BY ip ORDER BY total DESC LIMIT 5
    """)
    ips = cur.fetchall()

    cur.execute("""
        SELECT ip, COUNT(*) as total FROM events
        WHERE status='falha'
        GROUP BY ip HAVING total >= 20
    """)
    alerta = cur.fetchall() or None

    db.close()
    return render_template(
        "dashboard.html",
        total_logs = total_logs,
        sucessos   = sucessos,
        falhas     = falhas,
        ips        = ips,
        alerta     = alerta,
    )


# ─── DETALHE DO LOG ───────────────────────────────────────────────────────────
import re

def parse_raw_log(raw):
    if not raw:
        return {}
    parsed = {}
    m = re.match(r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})', raw)
    if m: parsed['date'] = m.group(1)
    m = re.search(r'\d{2}:\d{2}:\d{2}\s+(\S+)\s+', raw)
    if m: parsed['host'] = m.group(1)
    m = re.search(r'(\w+\[(\d+)\])', raw)
    if m: parsed['process'] = m.group(1)
    m = re.search(r'(Accepted password|Failed password)', raw)
    if m: parsed['event'] = m.group(1)
    m = re.search(r'for\s+(\S+)\s+from', raw)
    if m: parsed['user'] = m.group(1)
    m = re.search(r'from\s+([\d.]+)', raw)
    if m: parsed['ip'] = m.group(1)
    m = re.search(r'port\s+(\d+)', raw)
    if m: parsed['port'] = m.group(1)
    m = re.search(r'method=(\S+)', raw)
    if m: parsed['method'] = m.group(1)
    m = re.search(r'endpoint="?([^"\s]+)"?', raw)
    if m: parsed['endpoint'] = m.group(1)
    m = re.search(r'user-agent="([^"]+)"', raw)
    if m: parsed['user_agent'] = m.group(1)
    return parsed


@app.route("/log/<int:log_id>")
def log_detail(log_id):
    db  = get_db()
    cur = db.cursor()
    cur.execute("SELECT * FROM events WHERE id=?", (log_id,))
    row = cur.fetchone()
    if not row:
        return "Log não encontrado.", 404

    log    = {"id": row[0], "usuario": row[1], "ip": row[2], "data": row[3], "status": row[4], "raw_log": row[5] if len(row) > 5 else None}
    parsed = parse_raw_log(log["raw_log"])
    return render_template("log_detail.html", log=log, parsed=parsed)


# ─── RESET (dev only) ────────────────────────────────────────────────────────
@app.route("/reset_logs")
def reset_logs():
    db  = get_db()
    cur = db.cursor()
    cur.execute("DELETE FROM events")
    db.commit()
    db.close()
    return redirect("/")


# ─── INICIAR ──────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    init_db()
    app.run(debug=True, port=5001)
