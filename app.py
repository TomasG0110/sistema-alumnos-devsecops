"""!
@file app.py
@brief "Sistema Alumnos" de SecureDev: API y portal web de alumnos (Evaluación Parcial 3, OCY1102).
"""
import os
import re
import secrets
import sqlite3
import time
from collections import defaultdict

from flask import Flask, Response, g, jsonify, render_template_string, request, session
from markupsafe import escape
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)

# VULN-01: Secreto y credenciales cargados desde entorno con hash seguro PBKDF2-SHA256
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

ADMIN_USUARIO = os.environ.get("ADMIN_USUARIO", "admin")
_CLAVE_INICIAL = os.environ.get("ADMIN_PASSWORD", secrets.token_urlsafe(16))
ADMIN_CLAVE_HASH = os.environ.get("ADMIN_PASSWORD_HASH") or generate_password_hash(_CLAVE_INICIAL)

VERSION = os.environ.get("APP_VERSION", "dev")
DB_PATH = os.environ.get("DB_PATH", "alumnos.db")

ALUMNOS_INICIALES = [
    (1, "Ana Pérez", "Ingeniería en Informática", 6.1),
    (2, "Benjamín Rojas", "Ingeniería en Ciberseguridad", 5.4),
    (3, "Camila Soto", "Analista Programador", 6.8),
    (4, "Diego Muñoz", "Ingeniería en Informática", 4.9),
]

# Control de tasa (Rate Limiting) contra fuerza bruta en /login
INTENTOS_LOGIN = defaultdict(list)
MAX_INTENTOS = 5
VENTANA_SEGUNDOS = 60

# ---------------------------------------------------------------- métricas (no modificar los nombres)
HTTP_PETICIONES = Counter("http_requests_total", "Peticiones HTTP atendidas", ["method", "endpoint", "status"])
HTTP_LATENCIA = Histogram("http_request_duration_seconds", "Duración de las peticiones HTTP", ["endpoint"])
LOGIN_FALLIDOS = Counter("login_fallidos_total", "Intentos de inicio de sesión fallidos")
LOGIN_EXITOSOS = Counter("login_exitosos_total", "Inicios de sesión correctos")
SOSPECHOSAS = Counter("peticiones_sospechosas_total", "Peticiones con patrones de ataque", ["tipo"])
APP_INFO = Gauge("app_info", "Versión desplegada de la aplicación", ["version"])
APP_INFO.labels(version=VERSION).set(1)

PATRONES_ATAQUE = {
    "xss": re.compile(r"<\s*script|javascript:|onerror\s*=|onload\s*=|<\s*img", re.I),
    "sqli": re.compile(r"('|%27)\s*(or|and|union)\b|union\s+select|--|;\s*drop\b|sleep\(", re.I),
    "path_traversal": re.compile(r"\.\./|\.\.\\|%2e%2e", re.I),
}

PORTADA = """<!doctype html>
<html lang="es">
<head><meta charset="utf-8"><title>Sistema Alumnos</title></head>
<body>
<h1>Sistema Alumnos · SecureDev</h1>
<p>Versión {{ version }}</p>
<ul>
  <li><a href="/alumnos">Listado de alumnos (JSON)</a></li>
  <li><a href="/alumnos/1">Alumno 1</a></li>
  <li><a href="/hello?name=Ana">Saludo</a></li>
</ul>
<h2>Buscar alumno</h2>
<form action="/alumnos/buscar" method="get">
  <input name="nombre" value="Ana"> <button type="submit">Buscar</button>
</form>
<h2>Acceso administrador</h2>
<form action="/login" method="post">
  <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
  <input name="usuario" value="admin"> <input name="clave" type="password" value="">
  <button type="submit">Entrar</button>
</form>
</body>
</html>"""


def obtener_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(24)
    return session["csrf_token"]


def conectar():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def cerrar_db(_error):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def iniciar_db():
    db = sqlite3.connect(DB_PATH)
    db.execute("CREATE TABLE IF NOT EXISTS alumnos (id INTEGER PRIMARY KEY, nombre TEXT, carrera TEXT, promedio REAL)")
    if db.execute("SELECT COUNT(*) FROM alumnos").fetchone()[0] == 0:
        db.executemany("INSERT INTO alumnos VALUES (?, ?, ?, ?)", ALUMNOS_INICIALES)
    db.commit()
    db.close()


@app.before_request
def antes_de_la_peticion():
    g.inicio = time.perf_counter()
    valores = list(request.args.values()) + list(request.form.values())
    for tipo, patron in PATRONES_ATAQUE.items():
        if any(patron.search(v) for v in valores):
            SOSPECHOSAS.labels(tipo=tipo).inc()
            app.logger.warning("Petición sospechosa (%s) desde %s a %s", tipo, request.remote_addr, request.path)


@app.after_request
def despues_de_la_peticion(respuesta):
    endpoint = request.url_rule.rule if request.url_rule else "desconocido"
    if endpoint != "/metrics":
        HTTP_PETICIONES.labels(request.method, endpoint, str(respuesta.status_code)).inc()
        HTTP_LATENCIA.labels(endpoint).observe(time.perf_counter() - g.get("inicio", time.perf_counter()))

    # VULN-06: Cabeceras de endurecimiento HTTP (mitiga alertas pasivas de OWASP ZAP)
    respuesta.headers["X-Content-Type-Options"] = "nosniff"
    respuesta.headers["X-Frame-Options"] = "DENY"
    respuesta.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    respuesta.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    respuesta.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'"
    )
    return respuesta


@app.route("/")
def portada():
    return render_template_string(PORTADA, version=VERSION, csrf_token=obtener_csrf_token())


@app.route("/hello")
def hello():
    # VULN-04: Escape explícito contra XSS reflejado
    name = escape(request.args.get("name", "visitante"))
    return f"<h1>Hola, {name}!</h1>"


@app.route("/health")
def health():
    return jsonify({"estado": "ok"})


@app.route("/version")
def version():
    return jsonify({"aplicacion": "Sistema Alumnos", "version": VERSION})


@app.route("/alumnos")
def listar_alumnos():
    filas = conectar().execute("SELECT * FROM alumnos ORDER BY id").fetchall()
    return jsonify([dict(f) for f in filas])


@app.route("/alumnos/<int:alumno_id>")
def obtener_alumno(alumno_id):
    fila = conectar().execute("SELECT * FROM alumnos WHERE id = ?", (alumno_id,)).fetchone()
    if fila is None:
        return jsonify({"error": "Alumno no encontrado"}), 404
    return jsonify(dict(fila))


@app.route("/alumnos/buscar")
def buscar_alumnos():
    nombre = request.args.get("nombre", "")
    # VULN-02: Consulta parametrizada contra SQL Injection
    consulta = "SELECT * FROM alumnos WHERE nombre LIKE ?"
    try:
        filas = conectar().execute(consulta, (f"%{nombre}%",)).fetchall()
    except sqlite3.Error:
        # VULN-03: Sin exposición de detalles internos de SQLite
        app.logger.exception("Error de base de datos en /alumnos/buscar")
        return jsonify({"error": "Error interno al procesar la búsqueda"}), 500
    return jsonify([dict(f) for f in filas])


@app.route("/login", methods=["POST"])
def login():
    # VULN-05: Validación de token CSRF y rate-limiting contra fuerza bruta
    token_enviado = request.form.get("csrf_token", "")
    token_sesion = session.get("csrf_token", "")
    if not token_sesion or not secrets.compare_digest(token_enviado, token_sesion):
        LOGIN_FALLIDOS.inc()
        return jsonify({"error": "Token CSRF inválido o ausente"}), 403

    ip = request.remote_addr or "desconocida"
    ahora = time.time()
    INTENTOS_LOGIN[ip] = [t for t in INTENTOS_LOGIN[ip] if ahora - t < VENTANA_SEGUNDOS]
    if len(INTENTOS_LOGIN[ip]) >= MAX_INTENTOS:
        LOGIN_FALLIDOS.inc()
        return jsonify({"error": "Demasiados intentos fallidos. Intenta más tarde."}), 429

    usuario = request.form.get("usuario", "")
    clave = request.form.get("clave", "")
    usuario_valido = secrets.compare_digest(usuario, ADMIN_USUARIO)
    clave_valida = check_password_hash(ADMIN_CLAVE_HASH, clave)

    if usuario_valido and clave_valida:
        INTENTOS_LOGIN.pop(ip, None)
        LOGIN_EXITOSOS.inc()
        return jsonify({"mensaje": "Bienvenido, administrador"})

    INTENTOS_LOGIN[ip].append(ahora)
    LOGIN_FALLIDOS.inc()
    app.logger.warning("Login fallido para el usuario '%s' desde %s", usuario, ip)
    return jsonify({"error": "Credenciales inválidas"}), 401


@app.route("/metrics")
def metrics():
    return Response(generate_latest(), mimetype=CONTENT_TYPE_LATEST)


iniciar_db()

if __name__ == "__main__":
    # VULN-07: debug desactivado y enlace restringido a localhost por defecto
    app.run(host=os.environ.get("FLASK_HOST", "127.0.0.1"), port=5000, debug=False)