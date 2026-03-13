from flask import Flask, render_template, request, redirect, session, jsonify
from database.db import get_db  # banco em client_app/database/nerdy.db
from datetime import datetime, timedelta
import os
import bcrypt
import requests as http_requests

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "nerdy_secret_change_in_production")

# ─── URL da API de analytics (serviço do parceiro) ───────────────────────────
ANALYTICS_API_URL = os.environ.get("ANALYTICS_API_URL", "http://localhost:5001/ingest")

# ─── RATE LIMITING (em memória) ──────────────────────────────────────────────
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


# ─── HELPERS ─────────────────────────────────────────────────────────────────

def hash_senha(senha_plain: str) -> str:
    """Retorna hash bcrypt da senha."""
    return bcrypt.hashpw(senha_plain.encode(), bcrypt.gensalt()).decode()


def verificar_senha(senha_plain: str, senha_hash: str) -> bool:
    """Verifica senha contra hash bcrypt."""
    return bcrypt.checkpw(senha_plain.encode(), senha_hash.encode())


def enviar_log_para_analytics(payload: dict):
    """
    Envia o log para a API de analytics de forma não-bloqueante.
    Se falhar, apenas loga o erro — não interrompe o fluxo.
    """
    try:
        http_requests.post(ANALYTICS_API_URL, json=payload, timeout=2)
    except Exception as e:
        app.logger.warning(f"[analytics] Falha ao enviar log: {e}")


# ─── HOME ─────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("home.html")


# ─── LOGIN ───────────────────────────────────────────────────────────────────
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        usuario = request.form["usuario"]
        senha   = request.form["senha"]
        ip      = request.remote_addr

        # Checa bloqueio
        bloqueado, restam = verificar_bloqueio(ip)
        if bloqueado:
            minutos  = restam // 60
            segundos = restam % 60
            erro = f"IP bloqueado por tentativas excessivas. Aguarde {minutos:02d}:{segundos:02d}."
            return render_template("login.html", erro=erro, bloqueado=True, restam=restam)

        db  = get_db()
        cur = db.cursor()
        cur.execute("SELECT * FROM users WHERE usuario=?", (usuario,))
        user = cur.fetchone()

        # Verifica senha com bcrypt
        if user and verificar_senha(senha, user[3]):
            limpar_falhas(ip)
            session["user"]     = usuario
            session["user_id"]  = user[0]
            session["is_admin"] = bool(user[5])   # coluna is_admin

            registrar_log(usuario, ip, "sucesso")

            return redirect("/painel" if session["is_admin"] else "/parabens")

        else:
            registrar_falha(ip)
            bloqueado2, restam2 = verificar_bloqueio(ip)
            if bloqueado2:
                erro = f"Muitas tentativas! IP bloqueado por {BLOQUEIO_MINUTOS} minutos."
                return render_template("login.html", erro=erro, bloqueado=True, restam=restam2)

            info  = _tentativas.get(ip, {})
            faltam = LIMITE_TENTATIVAS - info.get("tentativas", 0)
            registrar_log(usuario, ip, "falha")
            return render_template(
                "login.html",
                erro=f"Usuário ou senha inválidos. ({faltam} tentativa(s) restante(s) antes do bloqueio)"
            )

    return render_template("login.html")


# ─── PARABÉNS (usuário comum) ────────────────────────────────────────────────
@app.route("/parabens")
def parabens():
    if "user" not in session:
        return redirect("/login")

    db  = get_db()
    cur = db.cursor()
    cur.execute("SELECT COUNT(*) FROM logs")
    total_logs = cur.fetchone()[0]

    return render_template(
        "parabens.html",
        usuario   = session["user"],
        total_logs= total_logs,
        ip        = request.remote_addr
    )


# ─── REGISTRAR LOG ────────────────────────────────────────────────────────────
def registrar_log(usuario, ip, status):
    data       = datetime.now()
    evento     = "Accepted password" if status == "sucesso" else "Failed password"
    metodo     = request.method
    endpoint   = request.path
    user_agent = request.headers.get("User-Agent", "")

    raw_log = (
        f"{data.strftime('%b %d %H:%M:%S')} nerdy-web "
        f"flask[{os.getpid()}]: {evento} for {usuario} "
        f"from {ip} port 443 "
        f'method={metodo} endpoint="{endpoint}" '
        f'user-agent="{user_agent}"'
    )

    db  = get_db()
    cur = db.cursor()
    cur.execute(
        "INSERT INTO logs(usuario, ip, data, status, raw_log) VALUES(?,?,?,?,?)",
        (usuario, ip, data, status, raw_log)
    )
    db.commit()

    # Envia para API de analytics
    payload = {
        "usuario":    usuario,
        "ip":         ip,
        "data":       data.isoformat(),
        "status":     status,
        "raw_log":    raw_log,
        "user_agent": user_agent,
        "endpoint":   endpoint,
    }
    enviar_log_para_analytics(payload)


# ─── PAINEL DE CONTROLE (admin) ───────────────────────────────────────────────
@app.route("/painel")
def painel():
    if "user" not in session or not session.get("is_admin"):
        return redirect("/login")

    db  = get_db()
    cur = db.cursor()

    cur.execute("SELECT * FROM users ORDER BY id")
    users = cur.fetchall()

    cur.execute("SELECT * FROM logs ORDER BY data DESC LIMIT 50")
    logs = cur.fetchall()

    cur.execute("SELECT COUNT(*) FROM logs")
    total_logs = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM logs WHERE status='sucesso'")
    sucessos = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM logs WHERE status='falha'")
    falhas = cur.fetchone()[0]

    return render_template(
        "painel_controle.html",
        users      = users,
        logs       = logs,
        total_logs = total_logs,
        sucessos   = sucessos,
        falhas     = falhas,
    )


# ─── CADASTRAR USUÁRIO ────────────────────────────────────────────────────────
@app.route("/register", methods=["GET", "POST"])
def register():
    if "user" not in session or not session.get("is_admin"):
        return redirect("/login")

    erro    = None
    sucesso = None

    if request.method == "POST":
        nome     = request.form["nome"].strip()
        usuario  = request.form["usuario"].strip()
        senha    = request.form["senha"]
        ip_auth  = request.form.get("ip", "").strip()
        is_admin = 1 if request.form.get("is_admin") else 0

        if not nome or not usuario or not senha:
            erro = "Preencha todos os campos obrigatórios."
        else:
            db  = get_db()
            cur = db.cursor()
            cur.execute("SELECT id FROM users WHERE usuario=?", (usuario,))
            if cur.fetchone():
                erro = f"Usuário '{usuario}' já existe."
            else:
                senha_hash = hash_senha(senha)
                cur.execute(
                    "INSERT INTO users(nome, usuario, senha, ip, is_admin) VALUES(?,?,?,?,?)",
                    (nome, usuario, senha_hash, ip_auth, is_admin)
                )
                db.commit()
                return redirect("/painel")

    return render_template("register.html", erro=erro, sucesso=sucesso)


# ─── REMOVER USUÁRIO ─────────────────────────────────────────────────────────
@app.route("/delete_user/<int:user_id>")
def delete_user(user_id):
    if "user" not in session or not session.get("is_admin"):
        return redirect("/login")
    if user_id == 1:
        return "Não é permitido remover o administrador.", 403

    db  = get_db()
    cur = db.cursor()
    cur.execute("DELETE FROM users WHERE id=?", (user_id,))
    db.commit()
    return redirect("/painel")


# ─── LOGS JSON (para o painel interno) ───────────────────────────────────────
@app.route("/logs_json")
def logs_json():
    if "user" not in session or not session.get("is_admin"):
        return jsonify({"error": "unauthorized"}), 401

    db  = get_db()
    cur = db.cursor()
    cur.execute("SELECT id, usuario, ip, data, status, raw_log FROM logs ORDER BY data DESC")
    logs = [
        {"id": r[0], "usuario": r[1], "ip": r[2], "data": r[3], "status": r[4], "raw_log": r[5]}
        for r in cur.fetchall()
    ]
    return jsonify({"logs": logs})


# ─── LIMPAR LOGS ─────────────────────────────────────────────────────────────
@app.route("/reset_logs")
def reset_logs():
    if "user" not in session or not session.get("is_admin"):
        return redirect("/login")
    db  = get_db()
    cur = db.cursor()
    cur.execute("DELETE FROM logs")
    db.commit()
    return redirect("/painel")


# ─── CHECK BLOQUEIO (AJAX) ────────────────────────────────────────────────────
@app.route("/check_block")
def check_block():
    ip = request.remote_addr
    bloqueado, restam = verificar_bloqueio(ip)
    return jsonify({"bloqueado": bloqueado, "restam": restam})


# ─── LOGOUT ───────────────────────────────────────────────────────────────────
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


# ─── INICIAR ──────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app.run(debug=True, port=5000)