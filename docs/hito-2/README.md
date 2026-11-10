# Hito 2 · Pipeline DevSecOps y aporte del Equipo azul

Aplicación: Secure CRM. El pipeline es responsabilidad de los cuatro integrantes. En este hito, el Equipo azul verifica los controles automáticos y justifica el umbral del *security gate* junto con el grupo. El Equipo rojo realiza por separado ZAP y Burp contra la instancia local a través del WAF en `DetectionOnly`, confirma al menos tres PoC y documenta OWASP Top 10:2025, CWE y CVSS v3.1.

**Avance local del 10 de noviembre:** [verificación del entorno](verificacion-entorno-2026-11-10.md) y [exploración y escaneo ZAP por el WAF](zap-escaneo-2026-11-10.md). Este escaneo se ejecutó desde la computadora de André para preparar la evidencia del grupo; Davis y Julio deben revisarlo e integrarlo con sus PoC de Burp.

## Pipeline del grupo

El workflow [`.github/workflows/devsecops.yml`](../../.github/workflows/devsecops.yml) se ejecuta en `push`, `pull_request` y manualmente. Usa el Compose de la raíz para el ZAP baseline automático sobre `http://localhost:3000/login`. La sesión ofensiva del Equipo rojo usa el Compose de `waf-siem/` y el puerto `8080`; son evidencias distintas.

| Control | Ejecución | Artefacto |
|---|---|---|
| SAST | Semgrep con `p/default` y `p/owasp-top-ten` | `semgrep.sarif` |
| SCA | `pnpm audit --prod --json` sobre el lockfile del monorepo | `pnpm-audit.json` |
| SBOM | Syft, formato CycloneDX JSON | `sbom.cdx.json` |
| DAST automático | ZAP baseline pasivo sobre `/login`, después de verificar web y API | `reporte-zap.html` y `reporte-zap.json` |

El baseline de ZAP es pasivo y solo recorre lo alcanzable desde la página pública. No demuestra que los PoC autenticados o los fallos de lógica de la API estén ausentes; esa evidencia corresponde a las pruebas del Equipo rojo y a las regresiones de H4.

## Evidencia de una corrida real

Corrida completa del PR el **9 de noviembre de 2026**, commit [`a5e8073`](https://github.com/mar22266/proyecto-final-desarrollo/commit/a5e8073afddb2d207d340489acd031f4a487cefe): [DevSecOps #42673196820](https://github.com/mar22266/proyecto-final-desarrollo/actions/runs/42673196820). Los cuatro jobs terminaron correctamente y se publicaron los cuatro artefactos. La [corrida de la rama anterior al ajuste de Dockerfiles](https://github.com/mar22266/proyecto-final-desarrollo/actions/runs/42665284624) sirve como línea base de comparación.

| Control | Resultado observado en el reporte | Evidencia |
|---|---|---|
| SAST | 14 resultados en SARIF; el paso del gate encontró **0 `ERROR`** después de ajustar los Dockerfiles. | [Artefacto Semgrep](https://github.com/mar22266/proyecto-final-desarrollo/actions/runs/42673196820/artifacts/13698503098) |
| SCA | 159 dependencias de producción; 4 avisos `low`, 24 `moderate`, **19 `high` y 6 `critical`**. El gate contó 25 `high/critical`. | [Artefacto SCA](https://github.com/mar22266/proyecto-final-desarrollo/actions/runs/42673196820/artifacts/13699696636) |
| SBOM | CycloneDX 1.6; 308 componentes y 124 relaciones de dependencia en el JSON generado. | [Artefacto SBOM](https://github.com/mar22266/proyecto-final-desarrollo/actions/runs/42673196820/artifacts/13700370165) |
| ZAP baseline | 12 tipos de alerta: 0 de riesgo alto, 2 medio, 6 bajo y 4 informativas. Entre las medias figuran CSP y protección contra *clickjacking* ausentes. | [Artefacto ZAP](https://github.com/mar22266/proyecto-final-desarrollo/actions/runs/42673196820/artifacts/13698398427) |

**Cómo leer el verde de Actions:** `SECURITY_GATE: "reporte"` permite que los pasos del gate registren hallazgos sin hacer fallar el job. En esta corrida, el paso de SCA devolvió código 1 por sus 25 avisos `high/critical`, aunque el job concluyó `success`; Semgrep y ZAP sí quedaron bajo sus umbrales. Por tanto, `success` confirma que los controles corrieron y publicaron evidencia; no significa que todos los hallazgos se hayan remediado.

### Lectura inicial de los hallazgos del gate

Los **25 avisos `high/critical`** de SCA son avisos del inventario de dependencias, no 25 explotaciones confirmadas. El JSON del artefacto muestra estas rutas de dependencia:

| Paquete afectado | Ruta y versión directa del proyecto | Avisos `critical` | Avisos `high` | Prioridad de revisión |
|---|---|---:|---:|---|
| `next` | `apps/web` → `next@14.2.15` | 4 | 11 | Revisar qué avisos aplican a las funciones usadas y planificar actualización compatible. |
| `lodash` | `apps/api` → `lodash@4.17.11` | 1 | 3 | Revisar el uso de Lodash y una versión corregida. |
| `jsonwebtoken` | `apps/api` → `jsonwebtoken@8.5.1` | 0 | 1 | Revisar actualización junto con la corrección de verificación de firma prevista en H4. |
| `proxy-addr`, `body-parser` | Transitivas de `express` en `apps/api` | 1 | 1 | Revisar la cadena de Express y sus versiones resueltas en el lockfile. |
| `postcss`, `source-map-js` | Transitivas de `next` en `apps/web` | 0 | 3 | Revisar si la actualización de Next corrige también la cadena transitiva. |

El gate de Semgrep encontró **dos `ERROR` en la línea base** por la ausencia de un `USER` explícito en [`apps/api/Dockerfile`](../../apps/api/Dockerfile) y [`apps/web/Dockerfile`](../../apps/web/Dockerfile). Esto describe la ejecución de los contenedores; no se atribuye a un PoC de aplicación del Equipo rojo. El baseline pasivo de ZAP no tuvo alertas altas, aunque sí señaló cabeceras faltantes de riesgo medio.

### Ajuste del Equipo azul tras la línea base

El commit [`87600ac`](https://github.com/mar22266/proyecto-final-desarrollo/commit/87600acd512521b7c1f397d724967f52dc7df9c1) hace que API y web arranquen como el usuario `node`. El Dockerfile de la API da permisos de escritura a `apps/api/data` para la semilla y SQLite; el de la web da permisos a `.next` para la caché. En la corrida completa enlazada arriba, Semgrep encontró **0 `ERROR`** y el job de DAST construyó ambas imágenes, verificó que la web y la API respondieran y completó el baseline de ZAP.

## Umbral del security gate

El umbral configurado y propuesto al grupo para este laboratorio es **cero hallazgos de severidad `ERROR` en Semgrep, cero vulnerabilidades `high/critical` en dependencias de producción y cero alertas de riesgo alto en el ZAP baseline**. El SBOM debe generarse como artefacto, pero no tiene un umbral de vulnerabilidades propio.

| Control | Umbral y razón | Línea base → corrida actual |
|---|---|---|
| Semgrep | Cualquier `ERROR` exige revisión porque indica un riesgo de código o configuración de alta severidad. | 2 → 0: ahora pasa el gate. |
| `pnpm audit --prod` | Un aviso `high` o `critical` en dependencias usadas al ejecutar la app exige remediación o una excepción documentada. Los avisos `low/moderate` quedan visibles en el reporte. | 25: superaría el gate. |
| ZAP baseline | Una alerta de riesgo alto en páginas públicas exige revisión. Las demás se conservan como evidencia para priorizar. | 0: pasaría el gate. |

El workflow queda en `reporte` mientras Secure CRM siga deliberadamente vulnerable. En `bloqueo`, un resultado por encima de cualquiera de esos umbrales hace fallar el job correspondiente. Un fallo técnico del escaneo o un reporte faltante **sí** debe fallar incluso en `reporte`; el workflow valida el JSON de SCA y ZAP, el código de salida de ZAP y la existencia de los artefactos.

Este gate no sustituye las pruebas de autorización por objeto, firma JWT o regresión de H4. Al revisar una corrección se debe comparar su resultado con los PoC del Equipo rojo, además de mirar el pipeline.

## Relación con el diseño del Hito 1

Los controles automáticos dan una señal parcial sobre los [requisitos de seguridad](../hito-1/README.md#5-requisitos-de-seguridad-verificables): Semgrep revisa patrones de código y configuración; SCA revisa dependencias; ZAP revisa pasivamente la superficie pública; el SBOM inventaría componentes. Los requisitos RS-01 a RS-05 necesitan también los PoC y pruebas de regresión. RS-06 a RS-08 requieren evidencia del WAF/SIEM en H3. La matriz final debe distinguir qué control observó realmente cada hallazgo.

## Evidencia pendiente para cerrar H2 completo

- Conservar la corrida de Actions de esta rama y el artefacto SBOM enlazados arriba; agregar las capturas de la corrida y del artefacto que pide la guía visual antes de la entrega en Canvas.
- Equipo rojo: revisar el nuevo reporte de ZAP por `localhost:8080` que ya está en esta carpeta; incorporar las parejas petición/respuesta de **al menos tres PoC** de Burp, la clasificación y el CVSS justificado métrica por métrica.
- Equipo rojo: repetir los PoC confirmados en Postman y anotar hora, ruta y resultado para que el Equipo azul pueda encontrarlos en Kibana durante H3.
- Grupo: revisar conjuntamente el umbral anterior y registrar cualquier excepción con hallazgo, justificación, responsable y fecha de revisión.

No se atribuyen al Equipo rojo los reportes del baseline automático ni se presentan como evidencia de sus PoC manuales.

## Uso de IA en esta entrega

Se usó **Codex (OpenAI)** para analizar el workflow y los artefactos de la corrida, proponer validaciones de reportes, ajustar los Dockerfiles y redactar esta línea base. También asistió en la ejecución y documentación del escaneo local de ZAP del 10 de noviembre. Los cambios generados son el ajuste de fiabilidad en `devsecops.yml`, el arranque de API y web como `node`, la definición de alcance de ZAP y esta documentación. El grupo debe revisar los reportes y hallazgos antes de presentarlos; no se han agregado dependencias ni secretos.
