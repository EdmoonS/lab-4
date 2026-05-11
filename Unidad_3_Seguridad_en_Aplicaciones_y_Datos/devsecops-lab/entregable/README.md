# Entregable — Lab 4 DevSecOps
> Esta carpeta muestra cómo debe verse una entrega **completa y correcta** del lab.
> Úsala como referencia, **no copies las respuestas**.

## Contenido de este entregable

| Archivo | Descripción |
|---------|-------------|
| `reporte_vulnerabilidades.md` | Tabla completa con las 5 vulnerabilidades de `app.py` + análisis manual + resultados del pipeline |
| `reflexion.md` | Respuestas a las 3 preguntas de reflexión |
| `semgrep-results.json` | Artefacto real generado por Semgrep en el pipeline |
| `audit-report.json` | Artefacto real generado por pip-audit en el pipeline |

## Pipeline en acción

El pipeline (`security.yml`) está configurado en `.github/workflows/`. Al hacer fork y
habilitar Actions, verás estas etapas ejecutarse automáticamente:

```
✅ SCA - pip-audit       → detecta 4 CVEs en dependencias
❌ SAST - Semgrep        → detecta 5 vulnerabilidades (ROJO = correcto)  
✅ Tests - pytest        → corre aunque SAST falle
✅ Estado final pipeline → resumen de resultados
```

> ⚠️ Que SAST aparezca en **rojo** es el comportamiento **correcto** —
> significa que el pipeline detectó las vulnerabilidades intencionales.

## Lo que debes entregar como alumno

1. **URL de tu fork** en GitHub con el pipeline configurado y ejecutándose
2. **Screenshots** de:
   - Pestaña Actions con el workflow y sus etapas
   - Salida de Semgrep con los Rule IDs
   - Salida de pip-audit con los CVEs
   - Security tab con alertas de Dependabot (si lo activaste)
3. **Tu propio `reporte_vulnerabilidades`** — con tus palabras, no copiado
4. **Tu propia `reflexion`** — análisis propio, no generado por IA sin análisis
5. **Los artifacts descargados** del pipeline: `semgrep-results.json` y `audit-report.json`

Todo en un solo PDF: `Apellidos_Nombre_Lab4.pdf`
