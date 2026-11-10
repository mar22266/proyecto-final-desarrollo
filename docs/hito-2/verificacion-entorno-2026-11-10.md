# Verificación del entorno local para Hito 2

Fecha: 10 de noviembre de 2026, aproximadamente 11:30 (Guatemala).

Se inició el laboratorio con `docker compose up -d --build` desde `waf-siem/`.
La configuración local conservó `WAF_BIND=127.0.0.1` y
`MODSEC_RULE_ENGINE=DetectionOnly`. No se cambió el modo del WAF ni se publicó
el puerto interno de la API.

| Comprobación | Resultado observado |
|---|---|
| Web `http://127.0.0.1:3000/login` | HTTP 200 |
| API por WAF `http://127.0.0.1:8080/api/health` | HTTP 200 |
| API directa `http://127.0.0.1:4000/api/health` | Conexión rechazada |
| WAF | Contenedor sano; modo `DetectionOnly` confirmado dentro del contenedor |
| Elasticsearch | Estado `yellow`, aceptable para el nodo único del laboratorio |
| Kibana | Estado `available` |
| Filebeat | Salida a Elasticsearch comprobada por `scripts/verificar.sh todo` |
| Eventos indexados tras las pruebas | 925 de acceso y 672 de auditoría del WAF en `filebeat-*` |

Se inició sesión con la cuenta de prueba `viewer` y se comprobaron por `8080`
las rutas de lectura `GET /api/tickets?q=factura` y `GET /api/users`: ambas
respondieron HTTP 200. Estos conteos de eventos incluyen tráfico anterior
conservado en los volúmenes; no representan exclusivamente el escaneo de esta
fecha.

El Compose usado es [`waf-siem/docker-compose.yml`](../../waf-siem/docker-compose.yml).
El Compose de la raíz es el laboratorio DAST previo y no se usó para estas
pruebas locales.
