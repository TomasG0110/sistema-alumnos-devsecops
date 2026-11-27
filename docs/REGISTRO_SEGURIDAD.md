# Registro de seguridad · Sistema Alumnos

Estudiante: Tomas Guajardo  Repositorio: https://github.com/TomasG0110/sistema-alumnos-devsecops   Fecha: 27-11-2026
Completa este registro a medida que avanzas. Cada fila debe poder seguirse hasta un **build de Jenkins**
y un **commit** (usa el identificador `VULN-xx` en el mensaje del commit).

## 1. Revisiones de seguridad realizadas

| # | Etapa del SDLC | Herramienta / técnica | Build | Resultado (resumen) |
|---|---|---|---|---|
| R1 | Código (SAST) | Bandit en el pipeline | #1 / #6 | Build #1: 1 High / 2 Medium / 3 Low → Build #6: 0 hallazgos |
| R2 | Dependencias (SCA) | pip-audit en el pipeline | #1 / #6 | Build #1: vulnerabilidades en 3 paquetes → Build #6: 0 vulnerabilidades |
| R3 | Pruebas dinámicas (DAST) | OWASP ZAP sobre staging | #1 / #6 | Build #1: alertas High/Medium (XSS, SQLi, cabeceras) → Build #6: 0 High / 0 Medium |
| R4 | Revisión manual | Lectura de `app.py` | — | Se identificaron secretos hardcodeados, MD5, SQLi, XSS, falta de CSRF/rate-limit y debug activo |
| R5 | Producción | Grafana + Prometheus | #6 | Monitoreo activo sobre `jenkins:5000` con alertas de fuerza bruta y patrones de ataque |

## 2. Vulnerabilidades identificadas y corregidas

| ID | Vulnerabilidad (CWE) | Detectada por | Ubicación | Riesgo | Corrección aplicada | Commit | Build que lo verifica |
|---|---|---|---|---|---|---|---|
| VULN-01 | Secretos hardcodeados y hash débil MD5 (CWE-798, CWE-327) | Bandit (`B105`, `B324`) y revisión manual | `app.py:21-23, 181` | Alto | Migración a variables de entorno y hash PBKDF2-SHA256 (`werkzeug.security`) | `5759aa1` | #6 |
| VULN-02 | Inyección SQL en búsqueda (CWE-89) | Bandit (`B608`) y OWASP ZAP | `app.py:167` (`/alumnos/buscar`) | Crítico | Consulta SQL parametrizada (`WHERE nombre LIKE ?`) | `5759aa1` | #6 |
| VULN-03 | Exposición de información en errores SQL (CWE-209) | Revisión manual y OWASP ZAP | `app.py:171` (`/alumnos/buscar`) | Medio | Eliminación de traza y consulta SQL en respuesta JSON HTTP 500 | `5759aa1` | #6 |
| VULN-04 | Cross-Site Scripting Reflejado (CWE-79) | OWASP ZAP (Escaneo Activo) | `app.py:124` (`/hello`) | Alto | Escapado de salida HTML mediante `markupsafe.escape()` | `5759aa1` | #6 |
| VULN-05 | Ausencia de token anti-CSRF y control de fuerza bruta (CWE-352, CWE-307) | Revisión manual y simulación de ataque | `app.py:176` (`/login`) | Alto | Token CSRF por sesión con `compare_digest` y límite de 5 intentos/min (HTTP 429) | `5759aa1` | #6 |
| VULN-06 | Ausencia de cabeceras de seguridad HTTP y flags de cookie (CWE-693, CWE-1021) | OWASP ZAP (Escaneo Pasivo) | `app.py:107` (`after_request`) | Medio | Cabeceras `CSP`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy` y cookies `HttpOnly`/`SameSite` | `5759aa1` | #6 |
| VULN-07 | Modo debug activo e interfaz `0.0.0.0` (CWE-489, CWE-605) | Bandit (`B201`, `B104`) | `app.py:232` | Alto | Desactivación de `debug=False` y enlace por defecto a `127.0.0.1` | `b18a728` | #6 |

## 3. Resultados DAST (OWASP ZAP)

| Alerta | Nivel de riesgo | URL afectada | Acción tomada | Estado tras mitigación (Build #6) |
|---|---|---|---|---|
| Cross Site Scripting (DOM Based) | High | `http://jenkins:5001/hello` | Escapado de salida HTML con `markupsafe.escape()` y cabecera `Content-Security-Policy` restrictiva | Mitigado (`0 High`) |
| Cross Site Scripting (Reflected) | High | `http://jenkins:5001/hello?nombre=...` | Sanitización de parámetro de entrada mediante `markupsafe.escape()` (`VULN-04`) | Mitigado (`0 High`) |
| SQL Injection | High | `http://jenkins:5001/alumnos/buscar?nombre=...` | Reemplazo de concatenación `f-string` por consulta parametrizada `WHERE nombre LIKE ?` (`VULN-02`) | Mitigado (`0 High`) |
| Absence of Anti-CSRF Tokens | Medium | `http://jenkins:5001/login` | Implementación de token CSRF por sesión validado con `hmac.compare_digest()` (`VULN-05`) | Mitigado (`0 Medium`) |
| Content Security Policy (CSP) Header Not Set | Medium | `http://jenkins:5001/*` | Incorporación de cabecera `Content-Security-Policy: default-src 'self'` vía `@app.after_request` (`VULN-06`) | Mitigado (`0 Medium`) |
| Missing Anti-clickjacking Header | Medium | `http://jenkins:5001/*` | Incorporación de cabecera `X-Frame-Options: DENY` en todas las respuestas HTTP (`VULN-06`) | Mitigado (`0 Medium`) |
| X-Content-Type-Options Header Missing | Low | `http://jenkins:5001/*` | Incorporación de cabecera `X-Content-Type-Options: nosniff` y cookies `HttpOnly`/`SameSite=Lax` (`VULN-06`) | Mitigado (`0 Low`) |



## 4. Bitácora de incidentes en producción (Grafana + Prometheus)

| Fecha / Hora (UTC) | Tipo de incidente detectado | Endpoint / Métrica afectada | Alerta disparada en Grafana | Acción de contención y respuesta |
|---|---|---|---|---|
| 2026-11-27 21:11 | Ataque automatizado de fuerza bruta sobre credenciales de acceso (`simular_ataque.py`) | `POST /login` (`login_fallidos_total`, respuestas HTTP `401` y `429`) | `Alerta Ataque Seguridad Produccion` → Estado **`Firing`** (`sum(increase(login_fallidos_total[2m])) > 5`) | El limitador de tasa en memoria bloqueó los intentos excedentes con HTTP `429 Too Many Requests` tras 5 fallos/minuto (`VULN-05`), sin comprometer la cuenta administrativa. |
| 2026-11-27 21:11 | Sondas de Inyección SQL (SQLi), Cross-Site Scripting (XSS) y Path Traversal | `GET /alumnos/buscar`, `GET /hello` (`peticiones_sospechosas_total` por `tipo=sqli, xss, path_traversal`) | Incremento registrado en panel *Peticiones Sospechosas por Tipo* | Las consultas parametrizadas (`VULN-02`) y el escape HTML (`VULN-04`) neutralizaron las cargas útiles sin errores de servidor ni exposición de datos. |

## 5. Gestión de dependencias (Dependabot + pip-audit)

* **Configuración continua:** Se implementó `.github/dependabot.yml` con ecosistema `pip` y revisión diaria (`interval: "daily"`) sobre `requirements.txt` y `requirements-dev.txt`, generando Pull Requests automáticos ante avisos de seguridad.
* **Paquetes vulnerables actualizados:**
  * `Werkzeug`: `2.2.2` → `3.1.9` (Pull Request `#5`, commit `3ceaad4`).
  * `Flask`: `2.2.2` → `3.1.3` (Pull Request `#2`, commit `edc9fe1`).
  * `prometheus-client`: actualización de dependencia de observabilidad (Pull Request `#1`, commit `231ce31`).
  * `Jinja2`: actualizado en cadena segura para remediar CVEs de ejecución/XSS en plantillas.
* **Verificación sin regresiones:** Tras fusionar los Pull Requests, Jenkins ejecutó automáticamente `pytest` (`9/9 OK`), `pip-audit` (**`0 vuln.`** frente a las 19 vulnerabilidades iniciales del Build `#1`) y OWASP ZAP (`0/0/0`), confirmando que no se introdujeron nuevas vulnerabilidades ni fallos funcionales.


## 6. Trazabilidad en el SDLC

| Build | Fecha (UTC) | Versión | Commit | Mensaje del commit | Pruebas | Bandit H/M/L | pip-audit | ZAP H/M/L | Resultado | Producción |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 2026-11-27 19:36 | `1.0.1+f33d312` | `f33d312` | chore: estructura inicial de pipeline DevSecOps y Dependabot | 9/9 OK | 2/2/1 | 19 vuln. | 3/3/1 | UNSTABLE | no desplegado |
| 2 | 2026-11-27 19:59 | `1.0.2+5759aa1` | `5759aa1` | VULN-01..07: migra secretos, corrige SQLi, XSS, CSRF, rate-limit y cab | 9/9 OK | 0/1/0 | 19 vuln. | 0/0/0 | UNSTABLE | no desplegado |
| 3 | 2026-11-27 20:04 | `1.0.3+3ceaad4` | `3ceaad4` | Merge pull request #5 from TomasG0110/dependabot/pip/werkzeug-3.1.9 | 0/1 OK | n/a | n/a | n/a | FAILURE | no desplegado |
| 4 | 2026-11-27 20:08 | `1.0.4+edc9fe1` | `edc9fe1` | Merge pull request #2 from TomasG0110/dependabot/pip/flask-3.1.3 | 9/9 OK | 0/1/0 | 0 vuln. | 0/0/0 | UNSTABLE | no desplegado |
| 5 | 2026-11-27 20:11 | `1.0.5+231ce31` | `231ce31` | Merge pull request #1 from TomasG0110/dependabot/pip/prometheus-client | 9/9 OK | 0/1/0 | 0 vuln. | 0/0/0 | UNSTABLE | no desplegado |
| 6 | 2026-11-27 20:17 | `1.0.6+b18a728` | `b18a728` | VULN-07: restringe interfaz local por defecto (CWE-605) | 9/9 OK | 0/0/0 | 0 vuln. | 0/0/0 | SUCCESS | `1.0.6+b18a728` |