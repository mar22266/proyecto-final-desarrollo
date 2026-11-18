# Cuatro reglas propias del WAF para Secure CRM

**Fecha de la prueba local:** 17 de noviembre de 2026 (Guatemala). Este complemento se implemento despues de la repeticion historica de H3 y de las correcciones de H4. No se atribuye a la demo anterior de Davis.

La regla `10001` de `REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf` ya existia en la plantilla del laboratorio: solo excluye `Host: 127.0.0.1` de la regla CRS `920350`. **No se cuenta como regla propia de defensa.** Las cuatro reglas del Equipo Azul estan en [`REQUEST-901-CRM-CUSTOM-RULES.conf`](../../waf-siem/waf/REQUEST-901-CRM-CUSTOM-RULES.conf), montado por [`docker-compose.yml`](../../waf-siem/docker-compose.yml) antes de las reglas CRS.

| Regla | Flujo protegido | Condicion acotada | Evidencia en Kibana |
|---|---|---|---|
| `10020` | `POST /api/auth/login` | `username` JSON contiene comilla seguida de `OR` o `--`; PoC de SQLi del login. | `WAF-01 SQLi login (10020)` |
| `10021` | `GET /api/tickets` | `q` contiene comilla seguida de `OR` o `--`; cubre la busqueda SQL concatenada observada en el codigo. | `WAF-02 SQLi tickets (10021)` |
| `10022` | `GET /api/tickets` | `q` contiene apertura de etiqueta `script`, `svg` o `img`; cubre una forma concreta de XSS reflejado. | `WAF-03 XSS tickets (10022)` |
| `10023` | `GET /api/users/:id` | Bloquea el detalle individual de usuario, que expone `passwordHash` y no es usado por la interfaz actual. | `WAF-04 Detalle usuario (10023)` |

Cada regla usa `deny,status:403,log,auditlog`, un ID unico y una ruta y metodo concretos. Con `MODSEC_RULE_ENGINE=On` bloquea y deja un evento `waf-audit`; en `DetectionOnly` solo registra. Las cuatro busquedas quedaron exportadas en [`kibana-export.ndjson`](../../waf-siem/kibana-export.ndjson) junto con las detecciones historicas `DET-*` y el dashboard. En Discover se selecciona la busqueda `WAF-*` y un rango de tiempo que incluya la prueba.

## Verificacion ejecutada

Se recreo el contenedor del WAF con las reglas montadas y `nginx -t` confirmo que ModSecurity cargo la configuracion. Las peticiones se enviaron **solo al WAF local**. En esta computadora se uso `127.0.0.1:8081` porque otro proyecto ocupaba `8080`; la configuracion versionada conserva `8080` como valor por defecto.

| Peticion | HTTP observado | Regla propia en `waf-audit` |
|---|---:|---|
| Login con `admin' OR 1=1 --` | 403 | `10020` |
| Busqueda de tickets con `q=' OR 1=1 --` | 403 | `10021` |
| Busqueda de tickets con `q=<script>alert(1)</script>` | 403 | `10022` |
| Detalle `GET /api/users/1` | 403 | `10023` |
| Login valido de `viewer` | 200 | Sin bloqueo propio |
| Busqueda normal de `factura` | 200 | Sin bloqueo propio |
| Lista `GET /api/users` | 200 | Sin bloqueo propio |

Filebeat indexo los cuatro eventos en `filebeat-*`. Al examinar `modsec.transaction.messages.details.ruleId` se observaron los IDs `10020`, `10021`, `10022` y `10023`. La importacion de los 15 objetos del archivo NDJSON en Kibana concluyo sin errores.

## Alcance y falsos positivos

Las reglas `10020` a `10022` reconocen **patrones concretos**; no prueban que todas las variantes de SQLi o XSS esten bloqueadas. La correccion de SQLi del login de H4 sigue siendo necesaria. `10021` y `10022` son defensas temporales para la busqueda de tickets, que aun tiene riesgo residual en la API. `10023` es un parche virtual: un consumidor legitimo de la ruta individual recibiria 403, aunque la interfaz del CRM no usa esa ruta. La lista `/api/users` aun puede exponer hashes; el WAF no sustituye la correccion del JSON de la API.

Estas reglas **no validan la firma JWT ni la propiedad de un ticket**. Esas dos PoC se detectaron en H3 y se corrigieron en la API en H4. La regla original `10001` permanece limitada al falso positivo de loopback; ninguna regla CRS se desactivo de forma general.
