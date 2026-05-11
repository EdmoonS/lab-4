# Preguntas de Reflexión — Lab 4 DevSecOps
**Alumno:** Apellidos, Nombre

---

## Pregunta 1
> Semgrep detectó las vulnerabilidades en el código. Sin embargo, SAST no puede detectar vulnerabilidades que solo aparecen en tiempo de ejecución. Da un ejemplo concreto de una vulnerabilidad en app.py que Semgrep no podría detectar y que requeriría DAST o revisión manual.

**Respuesta:**

El pipeline ejecutado con los rulesets `p/python`, `p/owasp-top-ten`, `p/secrets` y `p/sql-injection` detectó **7 findings** — pero dejó pasar al menos dos vulnerabilidades presentes en el código:

**Ejemplo 1 — Hardcoded Secrets (líneas 14–15) — no detectado por Semgrep:**
```python
DB_PASSWORD = 'SuperSecret123!'
SECRET_KEY  = 'hardcoded-secret-key-never-do-this'
```
El ruleset `p/secrets` busca patrones de tokens conocidos (AWS keys, JWT, API keys con prefijos reconocibles). Un string genérico como `'SuperSecret123!'` no coincide con ningún patrón, por lo que Semgrep no lo marca. Sin embargo, es una credencial de base de datos expuesta en texto claro. Para detectarla se requiere Secret Scanning de GitHub (que sí la encontró) o una regla Semgrep personalizada que busque asignaciones a variables llamadas `*PASSWORD*` o `*SECRET*`.

**Ejemplo 2 — Broken Access Control en POST /user (líneas 93–94) — no detectado:**
```python
role = data.get('role', 'user').strip()
db.execute('INSERT INTO users (..., role) VALUES (?, ?, ?)', (username, email, role))
```
Un atacante envía `{"username":"hacker","email":"h@x.com","role":"admin"}` y obtiene privilegios de administrador. Semgrep no puede detectarlo porque:
1. La query usa parámetros correctamente — no hay SQL injection sintáctica
2. La vulnerabilidad es **lógica**: el campo `role` nunca debería aceptarse del cliente
3. Solo se detecta ejecutando la aplicación con DAST (OWASP ZAP) o con revisión manual del flujo de autorización

Esto demuestra que SAST y DAST son **complementarios**, no sustitutos. SAST detecta patrones peligrosos en el código; DAST detecta comportamientos incorrectos en tiempo de ejecución.

---

## Pregunta 2
> El pipeline está configurado para mostrar las vulnerabilidades sin bloquear el merge. En un equipo real, ¿qué criterios usarías para decidir qué nivel de severidad bloquea el merge automáticamente?

**Respuesta:**

Propongo esta política de umbrales basada en severidad CVSS y tipo de hallazgo:

| Nivel | Criterio | Acción en pipeline |
|-------|----------|--------------------|
| **CRITICAL** (CVSS ≥ 9.0) | RCE, SQLi, Command Injection sin autenticación | ❌ Bloqueo automático — merge bloqueado hasta remediación |
| **HIGH** (CVSS 7.0–8.9) | Credenciales hardcodeadas, Path Traversal, SSRF | ❌ Bloqueo automático con excepción documentada obligatoria |
| **MEDIUM** (CVSS 4.0–6.9) | Debug mode, información expuesta, CSRF | ⚠️ Advertencia — merge permitido con issue creado automáticamente |
| **LOW** (CVSS < 4.0) | Prácticas de código deficientes, deprecaciones | ℹ️ Solo registro — no bloquea ni advierte |

**Consideraciones adicionales:**
- En el **primer sprint** de un proyecto legacy con mucha deuda técnica, bajar temporalmente el umbral a CRITICAL para evitar que el equipo pierda velocidad mientras sanea el código gradualmente
- Implementar **excepciones documentadas** (con `# nosemgrep: rule-id` + justificación en comentario) para casos de falsos positivos — sin excepciones el equipo desarrolla "security fatigue" e ignora las alertas
- Separar **nuevas vulnerabilidades** (introducidas en el PR) de las existentes — solo bloquear las nuevas para no paralizar proyectos en curso

---

## Pregunta 3
> pip-audit detectó CVEs en las dependencias. Describe el proceso para actualizar `cryptography` de 38.0.0 a la versión segura en producción sin interrumpir el servicio ni introducir regresiones.

**Respuesta:**

**Proceso de actualización segura en 5 pasos:**

**1. Inventario y análisis de impacto**
```bash
pip show cryptography          # versión actual y dependientes
pip index versions cryptography # versiones disponibles
```
Identificar todos los módulos que importan `cryptography` en el proyecto y leer el CHANGELOG entre 38.0.0 y la versión objetivo para detectar breaking changes.

**2. Entorno de staging aislado**
```bash
python -m venv venv-test
source venv-test/bin/activate
pip install cryptography==42.0.8  # versión segura
pip install -r requirements.txt   # resto de dependencias
```
Ejecutar la suite completa de tests: `pytest tests/ -v --tb=short`
Si hay tests de integración relacionados con cifrado (TLS, JWT, certificados), ejecutarlos específicamente.

**3. Actualizar `requirements.txt` con pinning exacto**
```
cryptography==42.0.8   # fix CVE-2023-0286, actualizado YYYY-MM-DD
```
Usar pin exacto (no `>=`) para garantizar reproducibilidad. Documentar la razón del cambio en el commit message referenciando el CVE.

**4. Despliegue con zero-downtime (rolling update)**
En contenedores/Kubernetes:
```bash
kubectl set image deployment/user-api app=user-api:v2.1.0
kubectl rollout status deployment/user-api
```
El rolling update reemplaza instancias una a una manteniendo el servicio disponible. Si algo falla: `kubectl rollout undo deployment/user-api`

**5. Verificación post-despliegue**
```bash
# Verificar versión desplegada
kubectl exec -it <pod> -- pip show cryptography

# Monitorear métricas 15 minutos post-deploy
# - Tasa de error 5xx
# - Latencia p99
# - Logs de excepción relacionados con TLS/crypto
```
Si las métricas son normales, marcar el CVE como remediado en el sistema de gestión (Jira, GitHub Issues).
