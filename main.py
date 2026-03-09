from flask import Flask, render_template, request, redirect, session
from database.db import get_db
from datetime import datetime

app = Flask(__name__)
app.secret_key = "nerdy_secret"


# HOME
@app.route("/")
def index():
    return render_template("index.html")


# LOGIN
@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        usuario = request.form["usuario"]
        senha = request.form["senha"]
        ip = request.remote_addr

        db = get_db()
        cur = db.cursor()

        cur.execute(
            "SELECT * FROM users WHERE usuario=? AND senha=?",
            (usuario, senha)
        )

        user = cur.fetchone()

        if user:

            session["user"] = usuario
            log(usuario, ip, "sucesso")

            return redirect("/dashboard")

        else:

            log(usuario, ip, "falha")
            return render_template("login.html", erro="Usuário ou senha inválidos")

    return render_template("login.html")


# REGISTRAR LOG
def log(usuario, ip, status):

    db = get_db()
    cur = db.cursor()

    cur.execute("""
    INSERT INTO logs(usuario,ip,data,status)
    VALUES(?,?,?,?)
    """, (usuario, ip, datetime.now(), status))

    db.commit()


# DASHBOARD
@app.route("/dashboard")
def dashboard():

    if "user" not in session:
        return redirect("/login")

    db = get_db()
    cur = db.cursor()

    # logs recentes
    cur.execute("SELECT * FROM logs ORDER BY data DESC LIMIT 20")
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
    HAVING total >= 15
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


# CADASTRAR USUARIO
@app.route("/register", methods=["GET", "POST"])
def register():

    if "user" not in session:
        return redirect("/login")

    if request.method == "POST":

        nome = request.form["nome"]
        usuario = request.form["usuario"]
        senha = request.form["senha"]
        ip = request.form["ip"]

        db = get_db()
        cur = db.cursor()

        cur.execute("""
        INSERT INTO users(nome,usuario,senha,ip)
        VALUES(?,?,?,?)
        """, (nome, usuario, senha, ip))

        db.commit()

        return redirect("/dashboard")

    return render_template("register.html")


# REMOVER USUARIO
@app.route("/delete_user/<int:user_id>")
def delete_user(user_id):

    if "user" not in session:
        return redirect("/login")

    # impedir apagar admin
    if user_id == 1:
        return "Não é permitido remover o administrador."

    db = get_db()
    cur = db.cursor()

    cur.execute("DELETE FROM users WHERE id=?", (user_id,))
    db.commit()

    return redirect("/dashboard")


# LOGOUT
@app.route("/logout")
def logout():

    session.clear()
    return redirect("/")


# API PARA ATUALIZAR LOGS AUTOMATICAMENTE
@app.route("/logs_json")
def logs_json():

    db = get_db()
    cur = db.cursor()

    cur.execute("""
    SELECT usuario, ip, data, status
    FROM logs
    ORDER BY data DESC
    LIMIT 20
    """)

    logs = cur.fetchall()

    resultado = []

    for l in logs:
        resultado.append({
            "usuario": l[0],
            "ip": l[1],
            "data": l[2],
            "status": l[3]
        })

    return {"logs": resultado}

# LIMPAR LOGS
@app.route("/reset_logs")
def reset_logs():

    if "user" not in session:
        return redirect("/login")

    db = get_db()
    cur = db.cursor()

    cur.execute("DELETE FROM logs")
    db.commit()

    return redirect("/dashboard")


# INICIAR SERVIDOR
if __name__ == "__main__":
    app.run(debug=True)