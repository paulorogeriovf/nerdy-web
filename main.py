from flask import Flask, render_template, request, redirect, session, jsonify
from database.db import get_db
from datetime import datetime, timedelta
import os

app = Flask(__name__)
app.secret_key = "nerdy_secret"

# --------------------- RATE LIMITING (em memória) ---------------------
# { ip: { "tentativas": N, "bloqueado_ate": datetime ou None } }
_tentativas = {}
LIMITE_TENTATIVAS = 5
BLOQUEIO_MINUTOS  = 2

def verificar_bloqueio(ip):
    """Retorna (bloqueado: bool, segundos_restantes: int)"""
    info = _tentativas.get(ip)
    if not info:
        return False, 0
    ate = info.get("bloqueado_ate")
    if ate and datetime.now() < ate:
        restam = int((ate - datetime.now()).total_seconds())
        return True, restam
    return False, 0

def registrar_falha(ip):
    """Incrementa falhas e bloqueia se atingir o limite."""
    if ip not in _tentativas:
        _tentativas[ip] = {"tentativas": 0, "bloqueado_ate": None}
    # reset se bloqueio anterior já expirou
    ate = _tentativas[ip].get("bloqueado_ate")
    if ate and datetime.now() >= ate:
        _tentativas[ip] = {"tentativas": 0, "bloqueado_ate": None}
    _tentativas[ip]["tentativas"] += 1
    if _tentativas[ip]["tentativas"] >= LIMITE_TENTATIVAS:
        _tentativas[ip]["bloqueado_ate"] = datetime.now() + timedelta(minutes=BLOQUEIO_MINUTOS)
        _tentativas[ip]["tentativas"] = 0

def limpar_falhas(ip):
    """Limpa contagem após login bem-sucedido."""
    if ip in _tentativas:
        del _tentativas[ip]


# --------------------- HOME ---------------------
@app.route("/")
def index():
    return render_template("index.html")


# --------------------- LOGIN ---------------------
@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":
        usuario = request.form["usuario"]
        senha = request.form["senha"]
        ip = request.remote_addr

        # ── Checa bloqueio ──────────────────────
        bloqueado, restam = verificar_bloqueio(ip)
        if bloqueado:
            minutos = restam // 60
            segundos = restam % 60
            erro = f"IP bloqueado por tentativas excessivas. Aguarde {minutos:02d}:{segundos:02d}."
            return render_template("login.html", erro=erro, bloqueado=True, restam=restam)

        db = get_db()
        cur = db.cursor()
        cur.execute(
            "SELECT * FROM users WHERE usuario=? AND senha=?",
            (usuario, senha)
        )
        user = cur.fetchone()

        if user:
            limpar_falhas(ip)
            session["user"] = usuario
            session["user_id"] = user[0]
            session["is_admin"] = (usuario == "admin" and senha == "1234")

            log(usuario, ip, "sucesso")

            if session["is_admin"]:
                return redirect("/dashboard")
            else:
                return redirect("/parabens")
        else:
            registrar_falha(ip)
            bloqueado2, restam2 = verificar_bloqueio(ip)
            if bloqueado2:
                erro = f"Muitas tentativas! IP bloqueado por {BLOQUEIO_MINUTOS} minutos."
                return render_template("login.html", erro=erro, bloqueado=True, restam=restam2)
            info = _tentativas.get(ip, {})
            tentativas_feitas = info.get("tentativas", 0)
            faltam = LIMITE_TENTATIVAS - tentativas_feitas
            log(usuario, ip, "falha")
            return render_template("login.html", erro=f"Usuário ou senha inválidos. ({faltam} tentativa(s) restante(s) antes do bloqueio)")

    return render_template("login.html")


# --------------------- PÁGINA USUÁRIO COMUM ---------------------
@app.route("/parabens")
def parabens():

    if "user" not in session:
        return redirect("/login")

    db = get_db()
    cur = db.cursor()

    cur.execute("SELECT COUNT(*) FROM logs")
    total_logs = cur.fetchone()[0]

    ip = request.remote_addr

    return render_template(
        "parabens.html",
        usuario=session["user"],
        total_logs=total_logs,
        ip=ip
    )


# --------------------- REGISTRAR LOG ---------------------
def log(usuario, ip, status):

    data = datetime.now()

    if status == "falha":
        evento = "Failed password"
    else:
        evento = "Accepted password"

    # informações extras do request
    metodo = request.method
    endpoint = request.path
    user_agent = request.headers.get("User-Agent")

    raw_log = (
        f"{data.strftime('%b %d %H:%M:%S')} nerdy-web "
        f"flask[{os.getpid()}]: {evento} for {usuario} "
        f"from {ip} port 443 "
        f'method={metodo} endpoint="{endpoint}" '
        f'user-agent="{user_agent}"'
    )

    db = get_db()
    cur = db.cursor()

    cur.execute("""
    INSERT INTO logs(usuario, ip, data, status, raw_log)
    VALUES(?,?,?,?,?)
    """, (usuario, ip, data, status, raw_log))

    db.commit()

# --------------------- DASHBOARD (ADMIN) ---------------------
@app.route("/dashboard")
def dashboard():
    if "user" not in session or not session.get("is_admin"):
        return redirect("/login")

    db = get_db()
    cur = db.cursor()

    # logs completos
    cur.execute("SELECT * FROM logs ORDER BY data DESC")
    logs = cur.fetchall()

    # usuarios
    cur.execute("SELECT * FROM users")
    users = cur.fetchall()

    # estatisticas
    cur.execute("SELECT COUNT(*) FROM logs")
    total_logs = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM logs WHERE status='sucesso'")
    sucessos = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM logs WHERE status='falha'")
    falhas = cur.fetchone()[0]

    # ips mais ativos
    cur.execute("""
        SELECT ip, COUNT(ip) as total
        FROM logs
        GROUP BY ip
        ORDER BY total DESC
        LIMIT 5
    """)
    ips = cur.fetchall()

    # detecção simples brute force
    alerta = None
    cur.execute("""
        SELECT ip, COUNT(*) as total
        FROM logs
        WHERE status='falha'
        GROUP BY ip
        HAVING total >= 20
    """)
    ataque = cur.fetchall()
    if ataque:
        alerta = ataque

    return render_template(
        "dashboard.html",
        logs=logs,
        users=users,
        total_logs=total_logs,
        sucessos=sucessos,
        falhas=falhas,
        ips=ips,
        alerta=alerta,
        chart_sucesso=sucessos,
        chart_falha=falhas
    )


# --------------------- CADASTRAR USUARIO ---------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if "user" not in session or not session.get("is_admin"):
        return redirect("/login")

    if request.method == "POST":
        nome = request.form["nome"]
        usuario = request.form["usuario"]
        senha = request.form["senha"]
        ip = request.form["ip"]

        db = get_db()
        cur = db.cursor()
        cur.execute("""
            INSERT INTO users(nome, usuario, senha, ip)
            VALUES (?, ?, ?, ?)
        """, (nome, usuario, senha, ip))
        db.commit()

        return redirect("/dashboard")

    return render_template("register.html")


# --------------------- REMOVER USUARIO ---------------------
@app.route("/delete_user/<int:user_id>")
def delete_user(user_id):
    if "user" not in session or not session.get("is_admin"):
        return redirect("/login")

    if user_id == 1:
        return "Não é permitido remover o administrador."

    db = get_db()
    cur = db.cursor()
    cur.execute("DELETE FROM users WHERE id=?", (user_id,))
    db.commit()
    return redirect("/dashboard")


# --------------------- LOGOUT ---------------------
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


# --------------------- DETALHE DO LOG ---------------------
import re

def parse_raw_log(raw):
    """Extrai campos do raw_log no formato syslog/flask."""
    if not raw:
        return {}
    parsed = {}

    # data prefix: "Mar 12 14:32:01"
    m = re.match(r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})', raw)
    if m:
        parsed['date'] = m.group(1)

    # hostname antes do processo
    m = re.search(r'\d{2}:\d{2}:\d{2}\s+(\S+)\s+', raw)
    if m:
        parsed['host'] = m.group(1)

    # processo[pid]
    m = re.search(r'(\w+\[(\d+)\])', raw)
    if m:
        parsed['process'] = m.group(1)

    # evento (Accepted/Failed password)
    m = re.search(r'(Accepted password|Failed password)', raw)
    if m:
        parsed['event'] = m.group(1)

    # usuário: "for USERNAME"
    m = re.search(r'for\s+(\S+)\s+from', raw)
    if m:
        parsed['user'] = m.group(1)

    # IP
    m = re.search(r'from\s+([\d.]+)', raw)
    if m:
        parsed['ip'] = m.group(1)

    # porta
    m = re.search(r'port\s+(\d+)', raw)
    if m:
        parsed['port'] = m.group(1)

    # method=
    m = re.search(r'method=(\S+)', raw)
    if m:
        parsed['method'] = m.group(1)

    # endpoint=
    m = re.search(r'endpoint="?([^"\s]+)"?', raw)
    if m:
        parsed['endpoint'] = m.group(1)

    # user-agent=
    m = re.search(r'user-agent="([^"]+)"', raw)
    if m:
        parsed['user_agent'] = m.group(1)

    return parsed


@app.route("/log/<int:log_id>")
def log_detail(log_id):
    if "user" not in session or not session.get("is_admin"):
        return redirect("/login")

    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT * FROM logs WHERE id=?", (log_id,))
    row = cur.fetchone()

    if not row:
        return "Log não encontrado.", 404

    # monta dict com nomes de coluna
    log = {
        "id":       row[0],
        "usuario":  row[1],
        "ip":       row[2],
        "data":     row[3],
        "status":   row[4],
        "raw_log":  row[5] if len(row) > 5 else None,
    }

    parsed = parse_raw_log(log["raw_log"])

    return render_template("log_detail.html", log=log, parsed=parsed)


# --------------------- API STATUS BLOQUEIO ---------------------
@app.route("/check_block")
def check_block():
    ip = request.remote_addr
    bloqueado, restam = verificar_bloqueio(ip)
    return jsonify({"bloqueado": bloqueado, "restam": restam})


# --------------------- API LOGS JSON ---------------------
@app.route("/logs_json")
def logs_json():

    db = get_db()
    cur = db.cursor()

    cur.execute("""
        SELECT id, usuario, ip, data, status, raw_log
        FROM logs
        ORDER BY data DESC
    """)

    logs = cur.fetchall()

    resultado = []

    for l in logs:
        resultado.append({
            "id":      l[0],
            "usuario": l[1],
            "ip":      l[2],
            "data":    l[3],
            "status":  l[4],
            "raw_log": l[5],
        })

    return {"logs": resultado}


# --------------------- LIMPAR LOGS ---------------------
@app.route("/reset_logs")
def reset_logs():
    if "user" not in session or not session.get("is_admin"):
        return redirect("/login")

    db = get_db()
    cur = db.cursor()
    cur.execute("DELETE FROM logs")
    db.commit()
    return redirect("/dashboard")


# --------------------- INICIAR SERVIDOR ---------------------
if __name__ == "__main__":
    app.run(debug=True)