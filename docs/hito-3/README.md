# Hito 3 · Detección y respuesta del Equipo azul

## Estado comprobado

El laboratorio local usa `waf-siem/docker-compose.yml`: la API escucha solo en la red de Docker, el WAF publica `127.0.0.1:8080` y Filebeat envía eventos a Elasticsearch y Kibana. El archivo versionado `waf-siem/.env.example` configura `MODSEC_RULE_ENGINE=On`; la copia local `.env` también quedó en `On` durante la verificación del **10 de noviembre de 2026**. El dashboard y las búsquedas están exportados en [`waf-siem/kibana-export.ndjson`](../../waf-siem/kibana-export.ndjson).

| Entregable del Equipo azul | Estado y evidencia |
|---|---|
| Tres detecciones ligadas a PoC de H2 | `DET-01` SQLi, `DET-02` JWT con firma inválida y `DET-03` lectura de ticket ajeno. Cada búsqueda encontró el evento de una prueba local. |
| Dashboard | Cuatro visualizaciones: eventos en el tiempo, reglas CRS, rutas atacadas e IP de origen; incluye las tres búsquedas DET. |
| WAF en bloqueo | `SecRuleEngine On` comprobado dentro del contenedor; SQLi y XSS de prueba devolvieron `403`. |
| Tráfico legítimo | Salud, login, listado, búsqueda, dashboard, usuarios, detalle y ciclo crear/editar/borrar ticket respondieron `200` o `201` según corresponde. El ticket de prueba se borró. |
| Exclusiones | La exclusión acotada preexistente para `Host: 127.0.0.1` y regla `920350` sigue activa. No se necesitó otra para los flujos probados. |
| Demo conjunta | Pendiente: Davis y Julio deben repetir sus PoC y registrar hora, respuesta HTTP y captura de Kibana durante la sesión. |

La [guía del Equipo azul](https://locano-uvg.github.io/proyecto_integrador/blue-team/) pide que las detecciones observen ataques reales, el dashboard muestre tiempo/reglas/rutas/IP, el WAF quede en `On` y se exporten los objetos. La validación conjunta con el Equipo rojo sigue pendiente; estas pruebas locales sirven para dejar preparado el lado azul.

## Detecciones guardadas

La instalación local de Kibana tiene la seguridad de Elastic deshabilitada. Las `DET-*` son **búsquedas guardadas de Discover**, como describe la guía del laboratorio; no generan alertas automáticas del motor de Elastic Security. Para verlas, abrir Kibana en `http://localhost:5601`, ir a Discover y seleccionar la búsqueda. Ajustar el rango de tiempo a la hora de la repetición del PoC.

| Búsqueda | KQL | Señal comprobada |
|---|---|---|
| `DET-01 SQLi en login` | `fields.fuente : "waf-audit" and modsec.transaction.messages.details.ruleId : "942100"` | Regla CRS `942100` sobre `POST /api/auth/login`; también se activó el umbral `949110`. |
| `DET-02 JWT con firma inválida` | `fields.fuente : "app-security" and security.event : "jwt_invalid_signature"` | `GET /api/users` con un JWT cuyo payload fue alterado conservando la firma anterior. |
| `DET-03 Acceso a ticket ajeno` | `fields.fuente : "app-security" and security.event : "ticket_foreign_access"` | El usuario `viewer` consultó `GET /api/tickets/1`, que no le pertenece. |

`DET-01` usa el log de auditoría de ModSecurity. Las otras dos señales se generan en la API y pasan por el volumen `security-logs` y la entrada `app-security` de Filebeat. El registro JSON contiene hora, tipo, método y ruta; para el ticket incluye ID y rol. No contiene el JWT, contraseñas ni el cuerpo de la respuesta. La observación de firma se limita al error `invalid signature`; no cambia la autenticación todavía vulnerable de H2. La observación de ticket registra lecturas de usuarios no administradores ajenas a su asignación y autoría; tampoco cambia la respuesta. Las correcciones pertenecen a H4.

## Dashboard y exportación

El dashboard **`H3 · Detección Blue Team`** contiene:

1. Las tres búsquedas `DET-*`, para relacionar el evento con su ruta y hora.
2. Una serie temporal que cuenta eventos de `waf-audit` y `app-security`.
3. El top de IDs de reglas CRS activadas.
4. El top de rutas del log de auditoría.
5. El top de IP de origen vistas por ModSecurity.

El archivo NDJSON incluye **9 objetos**: un data view `filebeat-*`, tres búsquedas, cuatro visualizaciones Lens y un dashboard con sus referencias. Se generó mediante la exportación de objetos guardados de Kibana y se verificó que cada línea es JSON válido. Para restaurarlo en otra instalación: Stack Management → Saved Objects → Import → seleccionar `waf-siem/kibana-export.ndjson`, aceptando reemplazo solo si se pretende actualizar estos mismos objetos. Después, abrir el dashboard y elegir un rango que incluya la nueva prueba.

La IP de origen observada al atacar desde esta misma laptop suele ser la de la red de Docker; el panel no distingue a dos integrantes que usen el mismo host. No se debe interpretar esa IP como identidad del atacante.

## Verificación local con WAF en `On`

Pruebas ejecutadas el **2026-11-10 UTC** contra `http://127.0.0.1:8080`, sin usar el puerto interno de la API:

| Flujo | Resultado |
|---|---|
| `GET /api/health`, login `jperez`, listado/búsqueda/detalle de tickets, dashboard y usuarios | `200` |
| Crear ticket de prueba, actualizarlo y borrarlo | `201`, `200`, `200` |
| SQLi en `username` de `POST /api/auth/login` | `403`; `waf-audit` registró `942100` y `949110` cerca de `18:26:46Z` |
| XSS en `q` de `/api/tickets` | `403`; `waf-audit` registró reglas `941100`, `941110`, `941160`, `941390` y `949110` cerca de `18:26:46Z` |
| JWT de `viewer` con payload alterado a `role:admin`, conservando la firma | `200`; Filebeat indexó `jwt_invalid_signature` cerca de `18:28:16Z` |
| Lectura de `/api/tickets/1` por `viewer` | `200`; Filebeat indexó `ticket_foreign_access` cerca de `18:28:16Z` |

El `200` de JWT e IDOR es una **limitación comprobada**, no un bloqueo exitoso. El CRS analiza contenido HTTP, pero no valida la firma criptográfica de un JWT ni consulta la propiedad de un ticket en la base de datos. Bloquear indiscriminadamente `/api/users` o los IDs de tickets impediría funciones legítimas y sería un falso positivo. La remediación de ambos fallos en la API y su regresión corresponden a H4. Así, la condición de la guía que pide `403` para todos los PoC aún no se cumple para esos dos ataques; debe indicarse en la demo y en el informe, no ocultarse.

No se agregaron exclusiones nuevas porque las rutas normales probadas no tuvieron `403`. Ya existe la excepción `id:10001` para `Host: 127.0.0.1` frente a `920350`, limitada a loopback y únicamente a ese encabezado; permite usar la URL local de la demo. El riesgo aceptado es que la regla `920350` no evalúa ese encabezado en solicitudes con ese Host, aunque las demás reglas siguen activas. Si en la repetición aparece otro falso positivo, registrar método, ruta, parámetro, ID de regla y hora; agregar solo una excepción acotada en `waf-siem/waf/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf` o `RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf`, reiniciar el WAF y repetir la acción legítima y el ataque. No excluir `949110` ni desactivar el CRS.

## Repetición pendiente del Equipo rojo

1. Davis y Julio confirman que sus reportes y PoC de H2 son los definitivos y acuerdan una hora UTC con el Equipo azul. Si todavía necesitan reproducir las respuestas vulnerables de H2, ponen el `.env` local en `DetectionOnly` y recrean `waf`; al terminar, restablecen `On`.
2. Con `On`, repiten **los mismos tres PoC** por `localhost:8080`: SQLi en login, JWT forjado y acceso a ticket ajeno. Guardan request/response de Burp o Postman con hora. Usan solo cuentas y datos de prueba y no publican tokens completos.
3. El Equipo azul fija en Kibana un rango que incluya esa hora y verifica `DET-01`, `DET-02` y `DET-03`; conserva capturas del dashboard y de cada búsqueda con hora y ruta visibles. Comprueba el `403` de SQLi junto a una acción legítima `200`. Registra el `200` residual de JWT e IDOR como pendientes para H4.
4. Se agregan al informe los resultados de esa sesión y cualquier exclusión realmente necesaria. Hasta entonces, la demo conjunta y la condición de bloqueo de todos los PoC siguen abiertas.

## Uso de IA

Se utilizó Codex (OpenAI) para apoyar la configuración de la telemetría, las búsquedas, el dashboard, las pruebas locales y esta documentación. El Equipo azul debe revisar los objetos exportados y validar las conclusiones en su propia demo antes de entregar el hito.
