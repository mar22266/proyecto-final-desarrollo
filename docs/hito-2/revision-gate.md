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

## Decisión pendiente

Esta hoja registra una **propuesta**, no una aprobación del grupo. André Marroquín y Gabriel Paz (Equipo azul), Davis Roldán y Julio Lemus (Equipo rojo) deben revisar juntos el umbral y dejar constancia de la decisión.

| Decisión | Estado | Responsable | Fecha |
|---|---|---|---|
| Aprobar o ajustar el umbral anterior | Pendiente | Grupo completo | Por registrar |
| Revisar hallazgos SCA actuales y excepciones necesarias | Pendiente | Grupo completo | Por registrar |

Para cada excepción aprobada, registrar identificador del hallazgo, dependencia o regla, motivo, riesgo aceptado, responsable y fecha de revisión. No se ha registrado ninguna excepción ni aprobación en nombre de otros integrantes.
