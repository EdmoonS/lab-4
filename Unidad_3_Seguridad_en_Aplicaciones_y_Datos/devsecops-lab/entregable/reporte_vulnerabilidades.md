# Reporte de Vulnerabilidades — Lab 4 DevSecOps
**Alumno:** Apellidos, Nombre  
**Repositorio:** https://github.com/tu-usuario/devsecops-lab-apellido  
**Fecha:** Mayo 2026

---

## Paso 2.1 — Análisis manual de app.py (antes del pipeline)

### Vulnerabilidad 1 — Hardcoded Secrets

| Campo | Detalle |
|-------|---------|
| **Líneas** | 14–16 |
| **Tipo** | Credenciales hardcodeadas (CWE-798) |
| **Código** | `DB_PASSWORD = 'SuperSecret123!'` / `SECRET_KEY = 'hardcoded-secret-key-never-do-this'` |
| **¿Por qué es peligrosa?** | Cualquier persona con acceso al repositorio obtiene credenciales de base de datos y la clave de sesión. Con `SECRET_KEY` se pueden forjar cookies firmadas y escalar privilegios. |
| **Payload de ataque** | No requiere payload — la credencial está en texto claro en el código fuente. |
| **Corrección** | `DB_PASSWORD = os.environ['DB_PASSWORD']` — almacenar en GitHub Secrets o un vault. |

---

### Vulnerabilidad 2 — SQL Injection

| Campo | Detalle |
|-------|---------|
| **Línea** | 80 |
| **Tipo** | SQL Injection (OWASP A03:2021, CWE-89) |
| **Código** | `query = f"SELECT ... WHERE username = '{username}'"` |
| **¿Por qué es peligrosa?** | El input del usuario se concatena directamente en la query SQL. Permite extraer toda la base de datos o ejecutar operaciones destructivas. |
| **Payload de ataque** | `GET /user?username=' OR '1'='1` → devuelve todos los usuarios |
| **Corrección** | Consulta parametrizada: `cursor.execute("SELECT ... WHERE username = ?", (username,))` |

---

### Vulnerabilidad 3 — Command Injection

| Campo | Detalle |
|-------|---------|
| **Líneas** | 130–136 |
| **Tipo** | Command Injection (OWASP A03:2021, CWE-78) |
| **Código** | `subprocess.run(f'ping {flag} 1 {host}', shell=True, ...)` |
| **¿Por qué es peligrosa?** | El parámetro `host` se pasa sin sanitizar a un shell. Un atacante puede encadenar comandos arbitrarios. |
| **Payload de ataque** | `GET /ping?host=8.8.8.8; cat /etc/passwd` → lee archivos del sistema |
| **Corrección** | `subprocess.run(['ping', flag, '1', host], shell=False)` + validar `host` con regex |

---

### Vulnerabilidad 4 — Debug Mode en producción

| Campo | Detalle |
|-------|---------|
| **Línea** | 161 |
| **Tipo** | Security Misconfiguration (OWASP A05:2021, CWE-11) |
| **Código** | `app.run(host='0.0.0.0', debug=True)` |
| **¿Por qué es peligrosa?** | Expone el debugger interactivo de Werkzeug y stack traces completos con rutas internas. Con el PIN del debugger se ejecuta código Python arbitrario. |
| **Corrección** | `app.run(debug=False)` o controlar con `FLASK_ENV=production` |

---

### Vulnerabilidad 5 — Path Traversal

| Campo | Detalle |
|-------|---------|
| **Líneas** | 142–149 |
| **Tipo** | Path Traversal (OWASP A01:2021, CWE-22) |
| **Código** | `log_path = os.path.join('/var/log', log_file)` sin validar |
| **¿Por qué es peligrosa?** | Permite salir de `/var/log` con `../` y leer archivos arbitrarios del sistema. |
| **Payload de ataque** | `GET /logs?file=../../etc/passwd` |
| **Corrección** | Validar con `os.path.realpath()` que la ruta empiece en `/var/log/` antes de abrir |

---

## Paso 2.2 — Análisis de requirements.txt

| Paquete | Versión actual | CVE | CVSS | Versión segura |
|---------|---------------|-----|------|----------------|
| `Werkzeug` | 2.0.1 | CVE-2023-25577 | 7.5 High | 3.0.6+ |
| `cryptography` | 38.0.0 | CVE-2023-0286 | 7.4 High | 42.0.0+ |
| `requests` | 2.25.0 | CVE-2023-32681 | 6.1 Medium | 2.31.0+ |
| `Jinja2` | 3.0.1 | CVE-2024-22195 | 5.4 Medium | 3.1.3+ |
| `Flask` | 2.0.1 | — | — | — |

---

## Paso 5.1 — Resultados reales de Semgrep (pipeline)

> **Semgrep detectó 7 findings bloqueantes en 4 archivos.**  
> Nota: las vulnerabilidades 1 (Hardcoded Secrets) y 5 (Path Traversal) **no fueron detectadas** por los rulesets usados — requieren revisión manual o reglas adicionales. Ver reflexión Q1.

### Finding 1 — SQL Injection (Django rule)

| Campo | Detalle |
|-------|---------|
| **Rule ID** | `python.django.security.injection.sql.sql-injection-using-db-cursor-execute.sql-injection-db-cursor-execute` |
| **Severidad** | ERROR — Blocking |
| **Archivo / Líneas** | `app/app.py` líneas 75–81 |
| **Descripción** | Dato controlado por el usuario (`request.args`) llega a `execute()` — SQL injection |
| **Riesgo real** | Extracción o modificación de toda la base de datos de usuarios |
| **Corrección** | Usar consultas parametrizadas con `?` en lugar de f-strings |

### Finding 2 — SQL Injection (Flask rule)

| Campo | Detalle |
|-------|---------|
| **Rule ID** | `python.flask.security.injection.tainted-sql-string.tainted-sql-string` |
| **Severidad** | ERROR — Blocking |
| **Archivo / Línea** | `app/app.py` línea 80 |
| **Descripción** | Input de usuario usado para construir un string SQL manualmente |
| **Riesgo real** | Mismo que Finding 1 — dos reglas distintas detectan el mismo problema |
| **Corrección** | ORM como SQLAlchemy o consulta parametrizada |

### Finding 3 — Command Injection (subprocess)

| Campo | Detalle |
|-------|---------|
| **Rule ID** | `python.flask.security.injection.subprocess-injection.subprocess-injection` |
| **Severidad** | ERROR — Blocking |
| **Archivo / Líneas** | `app/app.py` líneas 130–136 |
| **Descripción** | Input de usuario (`request.args`) llega sin sanitizar a `subprocess.run()` |
| **Riesgo real** | Ejecución de comandos arbitrarios en el servidor host |
| **Corrección** | Argumentos como lista, `shell=False`, validar `host` con regex |

### Finding 4 — Dangerous Subprocess

| Campo | Detalle |
|-------|---------|
| **Rule ID** | `python.lang.security.dangerous-subprocess-use.dangerous-subprocess-use` |
| **Severidad** | ERROR — Blocking |
| **Archivo / Línea** | `app/app.py` línea 131 |
| **Descripción** | Función `subprocess.run` con datos controlados por el usuario |
| **Riesgo real** | Command injection — misma raíz que Finding 3, regla más genérica |
| **Corrección** | `shlex.escape()` o reemplazar con lista de argumentos sin shell |

### Finding 5 — subprocess shell=True

| Campo | Detalle |
|-------|---------|
| **Rule ID** | `python.lang.security.audit.subprocess-shell-true.subprocess-shell-true` |
| **Severidad** | ERROR — Blocking |
| **Archivo / Línea** | `app/app.py` línea 132 |
| **Descripción** | `subprocess.run()` con `shell=True` propaga el entorno del shell |
| **Riesgo real** | Facilita la explotación de command injection — agrava Finding 3 y 4 |
| **Corrección** | `shell=False` — pasar argumentos como lista `['ping', flag, '1', host]` |

### Finding 6 — Host 0.0.0.0

| Campo | Detalle |
|-------|---------|
| **Rule ID** | `python.flask.security.audit.app-run-param-config.avoid_app_run_with_bad_host` |
| **Severidad** | ERROR — Blocking |
| **Archivo / Línea** | `app/app.py` línea 161 |
| **Descripción** | Flask corriendo con `host='0.0.0.0'` — expone el servidor a todas las interfaces de red |
| **Riesgo real** | La aplicación queda accesible desde cualquier interfaz de red del servidor |
| **Corrección** | `host='127.0.0.1'` en desarrollo; usar un proxy reverso (Nginx) en producción |

### Finding 7 — Debug Mode

| Campo | Detalle |
|-------|---------|
| **Rule ID** | `python.flask.security.audit.debug-enabled.debug-enabled` |
| **Severidad** | ERROR — Blocking |
| **Archivo / Línea** | `app/app.py` línea 161 |
| **Descripción** | `debug=True` expone el debugger interactivo de Werkzeug |
| **Riesgo real** | Con acceso al debugger → ejecución de código Python arbitrario (RCE) |
| **Corrección** | `debug=False` o `debug=os.environ.get('FLASK_DEBUG', False)` |

---

## Paso 5.2 — Resultados reales de pip-audit

### CVE-2023-25577 — Werkzeug

| Campo | Detalle |
|-------|---------|
| **Paquete / Versión** | `Werkzeug` 2.0.1 |
| **CVE ID** | CVE-2023-25577 |
| **CVSS** | 7.5 — High |
| **Descripción** | Parser de multipart/form-data sin límite de partes → DoS por consumo ilimitado de CPU/memoria |
| **Versión segura** | 2.2.3+ |

### CVE-2023-0286 — cryptography

| Campo | Detalle |
|-------|---------|
| **Paquete / Versión** | `cryptography` 38.0.0 |
| **CVE ID** | CVE-2023-0286 |
| **CVSS** | 7.4 — High |
| **Descripción** | Confusión de tipos en procesamiento de certificados X.400 → DoS o lectura de memoria |
| **Versión segura** | 42.0.0+ |

### CVE-2023-32681 — requests

| Campo | Detalle |
|-------|---------|
| **Paquete / Versión** | `requests` 2.25.0 |
| **CVE ID** | CVE-2023-32681 |
| **CVSS** | 6.1 — Medium |
| **Descripción** | Leak del header `Proxy-Authorization` a servidores destino al redirigir a HTTPS |
| **Versión segura** | 2.31.0+ |

### CVE-2024-22195 — Jinja2

| Campo | Detalle |
|-------|---------|
| **Paquete / Versión** | `Jinja2` 3.0.1 |
| **CVE ID** | CVE-2024-22195 |
| **CVSS** | 5.4 — Medium |
| **Descripción** | XSS mediante el filtro `xmlattr` — permite inyectar atributos HTML arbitrarios |
| **Versión segura** | 3.1.3+ |

---

## ⚠️ Vulnerabilidades NO detectadas por Semgrep

| Vulnerabilidad | ¿Por qué no la detectó? | Cómo detectarla |
|----------------|------------------------|-----------------|
| Hardcoded Secrets (líneas 14–15) | Los rulesets `p/secrets` buscan patrones conocidos de servicios externos (AWS keys, tokens). Strings genéricos como `SuperSecret123!` no coinciden con los patrones. | Reglas custom de Semgrep + Secret Scanning de GitHub |
| Path Traversal (líneas 142–149) | `os.path.join()` no es marcado por defecto — la vulnerabilidad está en la lógica de validación ausente, no en una función inherentemente peligrosa. | DAST (OWASP ZAP) o revisión manual de endpoints que leen archivos |

> Esto ilustra la respuesta a la **Pregunta de Reflexión 1**: SAST detecta patrones sintácticos, no lógica de negocio incorrecta.
