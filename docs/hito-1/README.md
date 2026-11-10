# Hito 1 · Diseño seguro de Secure CRM

Aplicación del grupo: Secure CRM, la misma del laboratorio DAST. Este documento modela el entorno local del [Hito 0](../hito-0/README.md). Las vulnerabilidades descritas proceden del código y de la guía DAST del repositorio; su explotación, clasificación final y evidencias por el WAF corresponden al Hito 2.

| Integrante | Equipo | Responsabilidad en H1 |
|---|---|---|
| Davis Roldán | Rojo | Reconocimiento y superficie de ataque; pendiente de su entrega |
| Julio Lemus | Rojo | Confirmar hallazgos DAST que pasarán a H2; pendiente de su entrega |
| Andre Marroquín | Azul | Requisitos y controles de verificación |
| Gabriel Paz | Azul | Límites de confianza y controles de monitoreo |

El DFD, STRIDE y PASTA se revisan entre los cuatro. Esta versión deja preparada la parte común y del Equipo azul; la sección de superficie de ataque queda a cargo del Equipo rojo.

## 1. DFD y límites de confianza

![DFD de Secure CRM detrás del WAF](dfd.svg)

[Fuente editable del diagrama](dfd.dot).

**Procesos y almacenes.** El navegador carga la web Next.js en `127.0.0.1:3000`. La web usa `NEXT_PUBLIC_API_URL=http://localhost:8080`, por lo que sus peticiones a la API cruzan ModSecurity y OWASP CRS. El WAF reenvía a Express en la red interna de Docker; la API lee y escribe usuarios y tickets en SQLite. Los logs de acceso y auditoría del WAF pasan por Filebeat a Elasticsearch y se consultan en Kibana.

**Límite 1, usuario → servicios locales.** El navegador, Postman y sus datos de entrada no son confiables. El WAF y Kibana solo publican puertos en `127.0.0.1`; la web también. La API no publica el `4000` al host en esta configuración. Las cuentas de prueba no son datos de producción.

**Límite 2, WAF → API y datos.** La API recibe datos incluso cuando el WAF está en `DetectionOnly`: observar una petición no la vuelve segura. Express debe autenticar y autorizar cada operación y tratar como no confiables los parámetros que luego llegan a SQLite. SQLite y los registros del WAF son almacenes distintos. Los logs de auditoría pueden incluir el cuerpo de un login; por ello solo se envían credenciales de prueba.

**Límite 3, telemetría → análisis.** Filebeat lee el volumen de logs del WAF y envía eventos a Elasticsearch. Kibana consulta esos eventos. Esta cadena ayuda a detectar y reconstruir incidentes, pero no sustituye la autorización de la API. Elasticsearch y Kibana tienen seguridad deshabilitada en la plantilla de laboratorio y sus puertos se limitan a la laptop.

## 2. STRIDE por componente

| Letra | Amenaza concreta | Componente y flujo del DFD | Control requerido y comprobación posterior |
|---|---|---|---|
| S · Suplantación | Un token JWT alterado se acepta sin validar su firma y permite fingir otra identidad. | Navegador → WAF → `authenticate` de Express. | Verificar firma, expiración y algoritmo; prueba de regresión con token alterado en H4 y revisión SAST en H2. |
| T · Manipulación | Un usuario envía `role=admin` o modifica campos de un ticket que no debe controlar. | Cuerpo HTTP → rutas `/api/users` y `/api/tickets` → SQLite. | Autorizar por rol y por objeto, validar campos permitidos; pruebas de acceso en H4 y observación del WAF en H3. |
| R · Repudio | Una creación, edición o eliminación de ticket no queda atribuida en un registro de auditoría de la aplicación. | API → SQLite; WAF → logs. | Registrar actor, operación, objeto, hora y resultado sin secretos; correlacionar con eventos en Kibana en H3. |
| I · Divulgación | Un usuario `viewer` consulta tickets ajenos o recibe hashes de contraseñas en `/api/users`. | API → SQLite → respuesta al navegador. | Proyección de respuesta sin hashes y autorización por objeto; prueba HTTP en H4, alerta de acceso anómalo en H3. |
| D · Denegación de servicio | La ruta de login acepta intentos ilimitados; una ráfaga consume recursos y permite fuerza bruta. | Navegador → WAF → `/api/auth/login` → SQLite. | Limitar intentos en API y detectar ráfagas en Kibana; revisar disponibilidad y falsos positivos en H3/H4. |
| E · Elevación de privilegios | Cualquier usuario autenticado puede crear usuarios con rol administrativo o cambiar roles. | `/api/users` y `/api/users/:id/role` → SQLite. | Autorizar operaciones administrativas en la API y probar que `viewer` recibe 403 en H4; búsqueda de eventos en H3. |

## 3. PASTA, etapas 1 a 5

### Etapa 1 · Objetivos del negocio

Secure CRM gestiona solicitudes de clientes, asignaciones y estados de tickets. Los activos principales son los datos de contacto del cliente, el contenido de tickets, las cuentas y roles, y la continuidad de atención. Se busca que solo el personal autorizado vea o cambie cada registro, que las operaciones administrativas estén separadas de las de lectura, y que los eventos relevantes puedan investigarse. Una alteración de roles o tickets puede cambiar la atención al cliente; una fuga expone datos de contacto y asuntos internos.

El uso en este curso es local y con datos de prueba. La disponibilidad y trazabilidad se evalúan sobre el laboratorio; no se infiere que la aplicación esté lista para producción.

### Etapa 2 · Alcance técnico

| Elemento | Incluido | Límite o decisión |
|---|---|---|
| Web | Next.js 14, rutas de login, panel, tickets y administración | Puerto `3000` solo local; peticiones de API por `8080` |
| WAF | ModSecurity + OWASP CRS | `DetectionOnly` en H0–H2; registra sin bloquear |
| API | Express + TypeScript, JWT y rutas `/api/*` | Puerto `4000` solo en la red de Docker |
| Datos | SQLite con usuarios y tickets de prueba | Base dentro del contenedor; la semilla se restaura al arrancar |
| Observabilidad | Logs WAF → Filebeat → Elasticsearch → Kibana | Puertos `9200` y `5601` solo locales |
| Fuera de alcance | Servicios públicos, datos reales y sistemas de terceros | No se escanean ni se atacan |

### Etapa 3 · Descomposición de la aplicación

1. El navegador carga la web por `3000`. El formulario de login envía usuario y contraseña por `8080` al WAF; este los reenvía a `/api/auth/login`.
2. Express consulta SQLite y devuelve un JWT y un usuario. La web guarda el JWT en `localStorage` y lo envía en `Authorization` para el panel, tickets y usuarios.
3. Las rutas de tickets y usuarios leen y modifican SQLite. Los identificadores de ruta, la búsqueda `q`, los cuerpos JSON y el token cruzan el límite de confianza del cliente.
4. El WAF escribe logs de acceso y auditoría. Filebeat los indexa en Elasticsearch y Kibana los presenta al Equipo azul.

Las rutas y almacenes se corresponden con el [DFD](dfd.svg). No se supone que un control en el WAF valide la lógica de negocio de Express.

### Etapa 4 · Análisis de amenazas

Los actores son un visitante sin sesión, un usuario `viewer`, un agente y un administrador; para el laboratorio, el Equipo rojo simula abuso de esos niveles de acceso. Los puntos de entrada son el login, el parámetro de búsqueda, los identificadores de tickets y usuarios, los cuerpos JSON y el token de sesión. Las rutas administrativas y de tickets requieren comprobar el rol y, cuando corresponda, la pertenencia del objeto. El WAF observa patrones HTTP, pero no conoce por sí mismo quién es dueño de un ticket.

Se priorizan tres cadenas: (1) suplantación o inyección en el login → acceso a datos; (2) un usuario autenticado consulta o cambia tickets ajenos → fuga o manipulación; (3) un usuario de lectura crea una cuenta administrativa → control de usuarios. Cada cadena cruza cliente → WAF → API → SQLite y tiene controles de aplicación y de detección separados.

### Etapa 5 · Vulnerabilidades del Proyecto DAST

Estos son hallazgos confirmados contra la instancia local via WAF (`http://localhost:8080`). Ver [hallazgos-dast.md](hallazgos-dast.md) para la evidencia completa de petición y respuesta de cada uno (Davis Roldán, Equipo rojo, 2026-11-04).

| Hallazgo | Ubicación en la aplicación | Flujo del DFD y efecto |
|---|---|---|
| Inyección SQL en login | `apps/api/src/auth.ts` | Entrada HTTP → consulta SQLite; acceso indebido. |
| Inyección SQL en búsqueda | `apps/api/src/routes/tickets.ts` | `q` del cliente → consulta SQLite; lectura o error. |
| XSS reflejado y almacenado | `apps/web/app/tickets/` y respuestas de tickets | Datos de tickets → navegador; ejecución en sesión ajena. |
| IDOR en tickets | `apps/api/src/routes/tickets.ts` | ID de ruta → SQLite sin comprobar propietario. |
| JWT sin verificación de firma | `apps/api/src/middleware/auth.ts` | Token del cliente → identidad/rol aceptados. |
| Hashes expuestos | `apps/api/src/routes/users.ts` | SQLite → respuesta JSON con `passwordHash`. |
| Asignación de rol sin control | `apps/api/src/routes/users.ts` | JSON del cliente → rol persistido o modificado. |
| CORS permisivo y cabeceras ausentes | `apps/api/src/index.ts` | Respuestas de API → navegador de cualquier origen. |
| Login sin límite de intentos | `apps/api/src/auth.ts` | Ráfagas de peticiones → autenticación y recursos. |
| Errores detallados | `apps/api/src/auth.ts`, `apps/api/src/index.ts` | Fallas internas → respuesta con SQL o stack. |

## 4. Superficie de ataque · Equipo rojo

![Mapa de superficie de ataque de Secure CRM](superficie.svg)

[Fuente editable del diagrama](superficie.dot) · [Tabla detallada con entradas, salidas y vulnerabilidades](superficie.md)

El mapa fue construido a partir del código fuente de `apps/api/src/`. Las rutas, métodos, roles, entradas y salidas se derivaron de los archivos `auth.ts`, `middleware/auth.ts`, `routes/tickets.ts`, `routes/users.ts` y `routes/dashboard.ts`. Los hallazgos se corresponden con las diez vulnerabilidades del tablero DAST de la guía del curso.

**Hallazgo global crítico:** el middleware `authenticate` usa `jwt.decode()` en lugar de `jwt.verify()`, por lo que la firma del token nunca se valida. Cualquier usuario puede forjar un token con el rol que quiera. Esto compromete todas las rutas autenticadas (CVSS 9.1).

**Verificación de puertos confirmada desde el host (Mac con Docker):**

```bash
# Responde por el WAF — HTTP 200
curl -s http://localhost:8080/api/health

# Puerto 4000 no publicado — conexión rechazada
curl -s http://localhost:4000/api/health
```

El puerto `4000` no está publicado al host en la configuración actual del `docker-compose.yml` (`expose` sin `ports`). No se detectó bypass directo a la API.

**Tres candidatos para los PoC del Hito 2** (derivados del análisis del código y del CVSS):

| Prioridad | Hallazgo | Ruta | CVSS |
|---|---|---|---|
| 1 | JWT sin verificación de firma | Middleware / todas las rutas autenticadas | 9.1 Crítica |
| 2 | SQL Injection en login | `POST /api/auth/login` | 9.1 Crítica |
| 3 | IDOR en tickets | `GET /PUT /DELETE /api/tickets/:id` | 8.1 Alta |

La [lista de entrega para el Equipo rojo](PENDIENTE-RED-TEAM.md) queda cubierta con este mapa. Los PoC, escaneos ZAP/Burp, cálculo de CVSS completo y la clasificación final corresponden al Hito 2.

## 5. Requisitos de seguridad verificables

Los controles de H2–H4 son **planificados**, no entregables ya ejecutados. El Equipo azul seleccionó cómo se comprobará cada requisito.

| ID | Requisito | Amenaza | Control que lo comprueba | Criterio observable posterior |
|---|---|---|---|---|
| RS-01 | La API debe rechazar JWT con firma alterada o vencidos. | Suplantación | Prueba de regresión H4; SAST del pipeline H2 | Token adulterado → 401; token válido → 200. |
| RS-02 | Solo un administrador debe crear usuarios o cambiar roles. | Elevación | Prueba de autorización H4; búsqueda de llamadas en Kibana H3 | `viewer`/`agent` → 403; `admin` → resultado permitido. |
| RS-03 | Cada lectura o cambio de ticket debe comprobar acceso al objeto. | IDOR / manipulación | Pruebas con dos usuarios H4; detección en Kibana H3 | Ticket ajeno → 403/404; propio → 200. |
| RS-04 | Las respuestas de usuarios no deben incluir hashes. | Divulgación | Prueba de contrato H4; revisión SAST H2 | Ningún JSON de `/api/users*` contiene `passwordHash`. |
| RS-05 | Búsquedas y login deben usar parámetros SQL y codificar salida HTML. | Inyección / XSS | SAST H2, WAF y PoC repetido en H4 | El PoC no cambia la consulta ni ejecuta script. |
| RS-06 | Login debe limitar ráfagas por cuenta y origen. | Denegación / fuerza bruta | Regla de Kibana y prueba de límite H3/H4 | Exceso de intentos → 429 o bloqueo temporal, con evento investigable. |
| RS-07 | Las operaciones relevantes deben registrar actor, resultado, objeto y hora sin secretos. | Repudio | Búsqueda en Kibana H3 y revisión de logs | Se correlaciona la acción con el actor; no aparecen contraseñas ni tokens. |
| RS-08 | Las llamadas normales a la API deben pasar por el WAF. | Bypass del control | Prueba de red H0; evidencia en Kibana H3 | `8080/api/health` → 200; acceso directo a `4000` desde host → conexión rechazada. |

## 6. Casos de abuso

### CA-01 · Suplantar identidad con token alterado

- **Dado** un cliente que posee un JWT de prueba de rol `viewer`.
- **Cuando** altera los datos del token y solicita una ruta administrativa por el WAF.
- **Entonces** la API debe rechazarlo con 401, sin modificar datos, y dejar evidencia de la solicitud.

### CA-02 · Leer un ticket ajeno

- **Dado** dos agentes con tickets asignados a personas diferentes.
- **Cuando** uno consulta por el WAF el identificador del ticket del otro.
- **Entonces** la API debe negar la lectura sin revelar el contenido del ticket.

### CA-03 · Escalar privilegios mediante el cuerpo JSON

- **Dado** un usuario autenticado con rol de solo lectura.
- **Cuando** intenta crear una cuenta con `role=admin` o cambiar el rol de otra cuenta.
- **Entonces** la API debe devolver 403 y no cambiar la tabla de usuarios.

### CA-04 · Inyección en login o búsqueda

- **Dado** un visitante o un agente con acceso al formulario correspondiente.
- **Cuando** envía caracteres de control SQL en el usuario o en `q` a través del WAF.
- **Entonces** la aplicación debe tratar la entrada como dato, sin cambiar la consulta ni devolver detalles internos.

### CA-05 · Ejecutar script desde un ticket

- **Dado** un ticket con texto aportado por un usuario de prueba.
- **Cuando** otra persona abre la lista o el detalle del ticket en el navegador.
- **Entonces** el texto debe mostrarse como contenido inerte y no ejecutar JavaScript.

### CA-06 · Saturar el inicio de sesión

- **Dado** una cuenta de prueba y un origen local.
- **Cuando** se repiten intentos fallidos de login en poco tiempo por el WAF.
- **Entonces** la API debe limitar los intentos y el Equipo azul debe poder identificar la ráfaga en el SIEM.

## Trazabilidad inicial

| Amenaza | Hallazgo DAST | Requisito | Caso de abuso | Continuación prevista |
|---|---|---|---|---|
| Suplantación | JWT sin verificar | RS-01 | CA-01 | H2 PoC; H4 corrección y re-prueba |
| Divulgación | IDOR | RS-03 | CA-02 | H2 PoC; H3 detección; H4 re-prueba |
| Elevación | Cambio de rol sin control | RS-02 | CA-03 | H2 PoC; H3 detección; H4 corrección |
| Inyección | SQLi | RS-05 | CA-04 | H2 SAST/DAST y PoC; H4 corrección |
| Manipulación | XSS en tickets | RS-05 | CA-05 | H2 PoC; H4 corrección |
| Denegación | Login ilimitado | RS-06 | CA-06 | H3 regla de ráfagas; H4 límite |

Este diseño no presupone resultados de H2–H4. Los controles y criterios permiten comprobarlos cuando se ejecuten. Para cerrar el Hito 1 falta incorporar y revisar el mapa de superficie de ataque del Equipo rojo y confirmar sus hallazgos DAST de la etapa 5.
