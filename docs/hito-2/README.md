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

Los controles automáticos dan una señal parcial sobre los [requisitos de seguridad](../hito-1/README.md#5-requisitos-de-seguridad-verificables): Semgrep revisa patrones de código y configuración; SCA revisa dependencias; ZAP revisa pasivamente la superficie pública; el SBOM inventaría componentes. Los requisitos RS-01 a RS-05 necesitan también los PoC y pruebas de regresión. RS-06 a RS-08 requieren evidencia del WAF/SIEM en H3.

### Trazabilidad por operación de negocio

Los códigos A1–A2, T1–T5, U1–U3 y O1 proceden del [DFD detallado de Hito 1](../hito-1/dfd-casos.svg) y de su [tabla de navegación](../hito-1/README.md). Esta matriz separa lo demostrado en H2 de lo que solo se identificó como riesgo o quedó para otra fase. Las señales del Equipo azul se explican en [Hito 3](../hito-3/README.md).

| Operación de H1 | Riesgo relacionado | Evidencia disponible en H2 | Alcance real / continuación |
|---|---|---|---|
| A1 · Login | H-01 SQLi; H-09 intentos ilimitados | [PoC-02 Burp](poc-burp.md) y [repetición Postman](poc-postman.json) confirman login de administrador sin contraseña; [ZAP por el WAF](zap-escaneo-2026-11-10.md) señaló SQLi en `username` con confianza baja. | SQLi sí tiene PoC; H-09 no tiene una PoC individual en esta entrega. `DET-01` de H3 observa SQLi. |
| A1–U3 · JWT compartido | H-04 firma no verificada | [PoC-01 Burp](poc-burp.md) envió JWT forjado a `GET /api/users` y recibió 200; Postman repitió el resultado. | La PoC confirma el fallo común de autenticación, no que se hayan atacado por separado todas las rutas. `DET-02` de H3 registra la firma inválida. |
| A2 · Panel | Acceso mediante H-04 | La PoC de JWT prueba el middleware compartido; no hay PoC específica de `GET /api/dashboard`. | La ruta se incluye como flujo legítimo en H3. |
| T1 · Lista y búsqueda | H-02 XSS reflejado; SQLi potencial en `q` | El [ZAP activo](zap-escaneo-2026-11-10.md) señaló SQLi en `q` con confianza baja. | Ni ese resultado ni el ZAP baseline equivalen a una PoC Burp de XSS o SQLi de búsqueda. `DET-04` de H3 procede de una prueba local de XSS. |
| T2 · Leer ticket | H-03 IDOR | [PoC-03 Burp](poc-burp.md) y Postman documentan lectura de tickets ajenos con HTTP 200. | `DET-03` de H3 registra el acceso, pero la respuesta vulnerable sigue siendo 200. |
| T3–T5 · Crear, editar/cerrar, eliminar | Autorización por rol u objeto insuficiente, descrita en [superficie de ataque](../hito-1/superficie.md). | No hay PoC individual de abuso de estas tres operaciones en H2. | H3 comprobó el ciclo **legítimo** 201/200/200; eso no demuestra autorización correcta. |
| U1 · Listar usuarios | H-05 hashes expuestos; H-04 JWT | [PoC-01 Burp](poc-burp.md) muestra la lista con `passwordHash` al usar un JWT forjado. | Se observó la exposición de hashes en esa respuesta; no es una cuarta PoC independiente. `DET-02` de H3 se activa por la firma inválida. |
| U2–U3 · Crear usuario/cambiar rol | H-08 escalada por rol | La [superficie de H1](../hito-1/superficie.md) documenta las rutas y el riesgo. No hay PoC individual de H2 en estas operaciones. | Su verificación ofensiva y la regresión de autorización siguen pendientes. |
| O1 · Investigar | Pérdida de atribución si faltan actor, objeto o resultado | Las [marcas de tiempo de Postman](verificacion-postman-2026-11-10.md) y los logs del WAF permiten buscar las solicitudes. | H3 dispone de búsquedas y dashboard; falta la correlación y captura de la demo conjunta con Red. |

Semgrep, SCA y SBOM son controles del código, dependencias e inventario, respectivamente: sus resultados no se atribuyen a una operación concreta sin evidencia adicional. El ZAP baseline automático solo recorre la web pública; las PoC autenticadas de esta tabla vienen de Burp/Postman por el WAF.

## Evidencia del Equipo rojo · Hito 2

### PoC Burp Suite

Los tres PoC confirmados están documentados en [`poc-burp.md`](poc-burp.md) con clasificación OWASP Top 10:2025, CWE y métricas CVSS v3.1 justificadas individualmente.

| PoC | Hallazgo | OWASP | CWE | CVSS | Capturas |
|---|---|---|---|---|---|
| PoC-01 | JWT sin verificación de firma | A07 | CWE-347 | 9.1 Crítica | [Burp](../shots/burp/repeater-jwt-forged.png) |
| PoC-02 | SQL Injection en login | A05 | CWE-89 | 9.1 Crítica | [Burp](../shots/burp/repeater-sqli.png) |
| PoC-03 | IDOR en tickets | A01 | CWE-639 | 8.1 Alta | [Burp](../shots/burp/repeater-idor.png) |

Las dos puntuaciones 9.1 corresponden al vector `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`; el IDOR (PR:L) calcula 8.1. Se verificaron con la [calculadora CVSS v3.1 de FIRST](https://www.first.org/cvss/calculator/3-1).

### Ejecución en Postman con marca de tiempo

Los PoC se reprodujeron el **2026-11-10 en entorno local** (UTC-6 / CST). La colección completa está en [`poc-postman.json`](poc-postman.json).

| Request | Ruta | Hora UTC | Resultado |
|---|---|---|---|
| PoC-01a · Login viewer | `POST /api/auth/login` | 2026-11-10T17:47:24Z | 200 — token viewer obtenido |
| PoC-01b · JWT forjado `role:admin` | `GET /api/users` | 2026-11-10T17:47:26Z | 200 — lista de usuarios con `passwordHash` |
| PoC-02 · SQLi `admin'--` | `POST /api/auth/login` | 2026-11-10T17:47:28Z | 200 — token de admin sin contraseña |
| PoC-03b · IDOR ticket #1 | `GET /api/tickets/1` | 2026-11-10T17:47:30Z | 200 — datos del ticket ajeno expuestos |
| PoC-03c · IDOR ticket #2 | `GET /api/tickets/2` | 2026-11-10T17:47:30Z | 200 — enumeración confirmada |

> **Para el Equipo azul (H3):** buscar en Kibana en el índice `filebeat-*` el rango `2026-11-10T17:47:00Z` → `2026-11-10T17:48:00Z` filtrando por las rutas `/api/users`, `/api/auth/login` y `/api/tickets/`.

La colección también se [verificó de forma independiente](verificacion-postman-2026-11-10.md) en el entorno local de André: 7 solicitudes, 8 aserciones correctas y 0 fallos. Esa corrida está separada de los horarios registrados por Davis.

### ZAP activo contra el WAF

El escaneo ZAP activo contra `http://localhost:8080` está documentado en [`zap-escaneo-2026-11-10.md`](zap-escaneo-2026-11-10.md). Los reportes son [`zap-reporte.html`](zap-reporte.html) y [`zap-reporte.json`](zap-reporte.json). ZAP detectó SQLi (confianza baja) en `username` del login y en el parámetro `q` de tickets, coincidiendo con PoC-02. IDOR y JWT forjado no son detectables por escaneo automático — se confirman únicamente con los PoC de Burp.

## Pendiente para cierre definitivo de H2

- [ ] Grupo: validar conjuntamente el umbral del security gate y registrar cualquier excepción con hallazgo, justificación, responsable y fecha. La [hoja de revisión](revision-gate.md) está preparada, pero no contiene una aprobación atribuida a integrantes que no la han dado.
- [ ] Guardar las capturas de la corrida de Actions y del artefacto SBOM que se solicitan para Canvas. Los [enlaces y metadatos comprobados](evidencia-pipeline-2026-11-10.md) están listos para obtenerlas.

No se atribuyen al Equipo rojo los reportes del baseline automático ni se presentan como evidencia de sus PoC manuales.

## Uso de IA en esta entrega

Se usó **Codex (OpenAI)** para analizar el workflow y los artefactos de la corrida, proponer validaciones de reportes, ajustar los Dockerfiles y redactar esta línea base. También asistió en la ejecución y documentación del escaneo local de ZAP del 10 de noviembre. Los cambios generados son el ajuste de fiabilidad en `devsecops.yml`, el arranque de API y web como `node`, la definición de alcance de ZAP y esta documentación. El grupo debe revisar los reportes y hallazgos antes de presentarlos; no se han agregado dependencias ni secretos.

En la revisión del 10 de noviembre se utilizó también para recalcular las puntuaciones CVSS contra sus vectores, ejecutar una verificación local de la colección con Newman y redactar los resúmenes de evidencia. Las respuestas sin filtrar de Newman no se publicaron porque contienen tokens y datos de prueba. El grupo debe revisar estos cambios y validar el umbral antes de la entrega.
