# ZAP contra la instancia local por el WAF

Fecha: 10 de noviembre de 2026, aproximadamente 11:29 (Guatemala).
Aplicación: Secure CRM. Herramienta: OWASP ZAP 2.17.0 en Docker.

## Alcance y preparación

Se usó el entorno de [`waf-siem/`](../../waf-siem/README.md), con ModSecurity
en `DetectionOnly`. ZAP compartió la red del contenedor del WAF; por eso
`http://localhost:8080` en sus reportes es el **mismo WAF** publicado como
`127.0.0.1:8080` en la computadora. No se escaneó la API por el puerto interno
`4000`, ni se añadieron objetivos externos.

El alcance reproducible está en [zap-scope.json](zap-scope.json):
`GET /api/health`, `POST /api/auth/login`, `GET /api/tickets` con búsqueda,
`GET /api/tickets/{id}` y `GET /api/users`. Solo se incluyeron rutas de lectura
y login. Las rutas que crean, editan o borran datos quedaron fuera para que el
escaneo automático no alterara la base de prueba. Las rutas protegidas se
exploraron con un JWT temporal de la cuenta de prueba `viewer`; ese token no se
guardó en el repositorio ni aparece en los reportes.

## Exploración con spider

Se ejecutó `zap-baseline.py` con spider de un minuto, tomando
`http://localhost:8080/api/health` como punto de partida. Observó **6 URL**.
El [reporte HTML](zap-spider.html), el [reporte JSON](zap-spider.json) y el
[plan generado por ZAP](zap.yaml) conservan la evidencia.

**Límite de esta exploración:** `/` devuelve HTTP 404 y la API no publica
enlaces HTML hacia sus rutas. ZAP avisó que el spider no pudo acceder a la raíz
con HTTP 200. Por ello el spider no representa un inventario completo de la
API. Para cubrir rutas reales se importó el alcance OpenAPI anterior y se
ejecutó un escaneo activo separado.

## Escaneo activo de la API

`zap-api-scan.py` importó **9 URL** desde la definición OpenAPI y observó
**38 URL** durante el escaneo. Los reportes son [HTML](zap-reporte.html) y
[JSON](zap-reporte.json). El único sitio incluido en el JSON es
`http://localhost:8080`. La autenticación se comprobó porque ZAP obtuvo HTTP
200 en `GET /api/tickets?q=factura`, `GET /api/tickets/1` y `GET /api/users`.

| Resultado de ZAP | Evidencia observada | Interpretación |
|---|---|---|
| SQL Injection, riesgo alto, **confianza baja** | 2 alertas: parámetro `username` de `POST /api/auth/login` y `q` de `GET /api/tickets`; una comilla provocó HTTP 500 | Señal de inyección que debe contrastarse con las peticiones y respuestas reproducibles de Burp. El HTTP 500 por sí solo no prueba extracción de datos. |
| Error del servidor | HTTP 500 en login y búsqueda durante el escaneo | Coincide con las entradas que dispararon los errores; no es un tercer PoC independiente. |
| Cabeceras | Falta `X-Content-Type-Options`; se expone `X-Powered-By` | Hallazgos de configuración para la matriz de remediación. |
| Content-Type inesperado | 17 URL, principalmente rutas inexistentes creadas por el escáner | Se revisan por separado; no se atribuyen a una vulnerabilidad confirmada. |

ZAP no confirmó por sí mismo IDOR, JWT forjado ni XSS. Esas pruebas de lógica
requieren las peticiones y respuestas de Burp del Equipo rojo. El escaneo de
este documento es **distinto** del ZAP baseline automático de GitHub Actions,
que usa el Compose antiguo de la raíz, y del
[reconocimiento pasivo anterior](../../Documentacion_ZAP/reporte-zap-original-h1.pdf).

## Comprobaciones de la evidencia

- Ambos reportes JSON incluyen únicamente el sitio `http://localhost:8080`.
- Los cuatro reportes (HTML y JSON de spider y API) se abren y no contienen el
  JWT temporal usado para las rutas protegidas.
- Después de ZAP, `/api/health` siguió respondiendo HTTP 200 por el WAF y el
  acceso directo a `localhost:4000` siguió rechazado.
- Los logs del WAF y el índice `filebeat-*` registraron las peticiones de las
  pruebas. Los conteos acumulados están en
  [verificación del entorno](verificacion-entorno-2026-11-10.md).

Este escaneo entrega la evidencia técnica de ZAP para Hito 2. El Equipo rojo
debe revisar los hallazgos, integrarlos con sus PoC de Burp y explicar la
clasificación CVSS de cada PoC en la entrega común.
