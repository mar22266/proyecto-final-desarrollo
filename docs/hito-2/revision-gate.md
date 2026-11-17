# Revisión del umbral del security gate

## Propuesta técnica para el grupo

El workflow mantiene `SECURITY_GATE: "reporte"` durante el laboratorio, porque la aplicación se usa para demostrar vulnerabilidades conocidas. El umbral propuesto para pasar posteriormente a `bloqueo` es:

| Control | Umbral propuesto | Acción si se supera |
|---|---|---|
| Semgrep | 0 resultados `ERROR` | Corregir o justificar un falso positivo concreto. |
| SCA de producción | 0 vulnerabilidades `high` o `critical` | Actualizar la dependencia o registrar una excepción temporal con riesgo y fecha de revisión. |
| ZAP baseline público | 0 alertas de riesgo alto | Comprobar el hallazgo y corregirlo o documentar su alcance. |
| SBOM | Artefacto CycloneDX generado y disponible | Reparar la generación; no se propone un umbral numérico independiente. |

La [corrida de `main`](evidencia-pipeline-2026-11-10.md) confirma que los cuatro controles corrieron y publicaron artefactos. Su resultado verde en modo `reporte` no equivale a que el umbral de bloqueo se cumpla. El análisis SCA de la línea base registró avisos altos/críticos; el grupo debe comprobar el artefacto actual antes de decidir excepciones.

## Decisión del grupo

El grupo revisó el umbral propuesto y acordó adoptarlo sin modificaciones para el cierre de Hito 3. Los hallazgos SCA actuales son conocidos y corresponden a dependencias del entorno de laboratorio; se aceptan como riesgo temporal hasta las correcciones de H4.

| Decisión | Estado | Responsable | Fecha |
|---|---|---|---|
| Aprobar el umbral anterior | **Aprobado** | Grupo completo | 2026-11-17 |
| Revisar hallazgos SCA actuales y excepciones necesarias | **Aprobado** — riesgo aceptado hasta H4 | Grupo completo | 2026-11-17 |

## Firmas de aprobación

| Integrante | Equipo | Acuerdo |
|---|---|---|
| Davis Roldán | Rojo | Aprobado |
| Julio Lemus | Rojo | Aprobado |
| André Marroquín | Azul | Aprobado |
| Gabriel Paz | Azul | Aprobado |
