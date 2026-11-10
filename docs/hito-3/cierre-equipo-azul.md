# Cierre del Hito 3 · Equipo azul

Revisión del **10 de noviembre de 2026** contra el PDF original del proyecto, el [enunciado web](https://locano-uvg.github.io/proyecto_integrador/#h3) y la [guía del Equipo azul](https://locano-uvg.github.io/proyecto_integrador/blue-team/). Este registro distingue configuración comprobada, evidencia que falta capturar y actividades de la demo conjunta.

| Criterio de la guía | Estado comprobado | Para cerrarlo |
|---|---|---|
| Data view `filebeat-*` y eventos del WAF en Discover | Hecho. El data view forma parte de `waf-siem/kibana-export.ndjson`; Elasticsearch conserva eventos `waf-audit`. | Captura de Discover con hora y evento visible para la entrega. |
| Al menos tres detecciones sobre ataques reales | Hay cinco búsquedas. `DET-01` ve SQLi del login en `waf-audit`; `DET-02` y `DET-03` ven JWT e IDOR en `app-security`; `DET-04` ve XSS por CRS `941*` y `DET-05` método no permitido por CRS `911100`. Todas encontraron eventos de pruebas locales. | Durante la repetición de Davis y Julio, guardar capturas con hora y ruta de las detecciones que correspondan a sus PoC. Las dos búsquedas adicionales del WAF no equivalen a PoC del Equipo rojo hasta que ellos reproduzcan esos ataques. Los logs de aplicación omiten tokens y payloads deliberadamente; acompañarlos con request/response redactado de Burp o Postman. |
| Dashboard con tiempo, reglas, rutas e IP | Hecho. El dashboard `H3 · Detección Blue Team` contiene cuatro visualizaciones y las tres búsquedas. | Captura con rango horario de la repetición y los cuatro paneles visibles. La IP local puede corresponder a la red de Docker. |
| WAF en `On`, CRS activo y bloqueo de PoC | Hecho para SQLi: el contenedor tiene `SecRuleEngine On` y la prueba devolvió `403`. XSS de prueba también devolvió `403`. | Red repite los PoC en la demo; Blue muestra el `403` de SQLi y la detección simultánea. JWT e IDOR siguen devolviendo `200`: no afirmar que el WAF los bloquea. La guía pide bloqueo de los PoC y este punto **no está cumplido para los tres**. |
| Tráfico legítimo y falsos positivos | Se comprobaron salud, login, listado, búsqueda, detalle, dashboard y ciclo crear/editar/borrar ticket, sin `403`. `PUT` y `DELETE` están en `ALLOWED_METHODS`. Sigue la exclusión preexistente `id:10001` para `Host: 127.0.0.1` y regla `920350`, con riesgo documentado en el README. | En la demo, repetir una acción legítima junto al ataque y capturar su respuesta correcta. Si aparece un falso positivo nuevo, investigar `ruleId` y `details.data`, aplicar la exclusión mínima y repetir ambos flujos. La app no tiene registro de usuarios ni carga de archivos; esos ejemplos genéricos de la guía no aplican. |
| Exportación de objetos | Hecho. `waf-siem/kibana-export.ndjson` incluye data view, cinco búsquedas, cuatro Lens y dashboard; 11 objetos y referencias internas comprobadas. | Guardar la captura de Saved Objects con las búsquedas y el dashboard seleccionados, como pide la guía. |
| Demo Purple Team | Pendiente de ejecución conjunta. | Acordar hora UTC; Red repite un PoC por el WAF; Blue muestra evento, regla y respuesta `403` del mismo intento. Guardar capturas y hora para el informe. |

La guía también pide que el umbral del *security gate* esté justificado con el grupo. [La hoja de revisión de Hito 2](../hito-2/revision-gate.md) está preparada, pero no registra todavía el acuerdo de los cuatro integrantes. Esa aprobación grupal no se puede completar por cuenta del Equipo azul.

El PDF pide **al menos cuatro vulnerabilidades explotadas** en Hito 2. El repositorio contiene tres PoC de Burp confirmados; Davis y Julio deben completar o verificar el cuarto. El PDF usa Juice Shop como aplicación de referencia y un fork suyo como repositorio, pero este grupo trabaja con Secure CRM. Antes de declarar el proyecto conforme, el grupo debe confirmar con el docente que esa sustitución fue autorizada; no hay constancia de esa excepción en el repositorio.

## Orden para la sesión de cierre

1. Mantener `MODSEC_RULE_ENGINE=On` y usar únicamente `http://localhost:8080` para el ataque y la prueba legítima. Confirmar que Kibana y Filebeat están levantados.
2. Davis y Julio repiten SQLi, JWT e IDOR con cuentas de prueba y anotan la hora UTC de cada request. El PoC de SQLi sirve para la demostración de bloqueo. Los otros dos demuestran detección y riesgo residual.
3. André y Gabriel filtran Discover por la hora de cada intento y guardan las capturas de data view, búsquedas `DET-*`, dashboard, exportación de Saved Objects y la pareja `403` de SQLi / `200` de acción legítima. No incluir contraseñas ni JWT completos en capturas o commits.
4. Añadir las capturas a `docs/hito-3/`, registrar cualquier falso positivo realmente observado y completar la matriz del informe. Si no aparece ninguno, dejar explícito que no se necesitó exclusión nueva.

No se incluyen capturas de una repetición que todavía no ocurrió ni se atribuye una aprobación grupal no registrada.

## Relación con el Hito 4

El Hito 4 **puede iniciarse en una rama separada** con los tres PoC ya documentados en Hito 2. Se pueden escribir pruebas de regresión que reproduzcan al menos dos fallos y fallen antes de la corrección; después, corregir la API, auditar el diff, pasar SAST y documentar herramienta, prompt, respuesta y cambios humanos, como exige el [enunciado de Hito 4](https://locano-uvg.github.io/proyecto_integrador/#h4). JWT e IDOR son dos candidatos directos; SQLi también lo es.

Conviene conservar `main` y el entorno de Hito 3 sin esas correcciones hasta capturar la demo Purple Team, porque cambiar la API ahora alteraría las respuestas de los PoC. El cierre de Hito 4 sí depende de que el Equipo rojo repita los mismos PoC con el WAF en `DetectionOnly` y confirme que ya fallan por la corrección del código. En H4 deben quedar en `docs/hito-4/` los commits, pruebas antes/después, auditoría y evidencia de la repetición.
