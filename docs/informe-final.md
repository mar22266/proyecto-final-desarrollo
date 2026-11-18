# Informe final | Proyecto Integrador

**Desarrollo de Software Seguro · Secure CRM**

**Repositorio del proyecto:** [https://github.com/mar22266/proyecto-final-desarrollo](https://github.com/mar22266/proyecto-final-desarrollo)

**Video del proyecto:** [https://youtu.be/_tGgxkugSOA](https://youtu.be/_tGgxkugSOA)

**Integrantes:** Andre Marroquin, Davis Roldan, Gabriel Paz y Julio Lemus

Guatemala, 19 de noviembre de 2026

## Resumen ejecutivo

Secure CRM gestiona solicitudes de clientes, asignaciones y cuentas de usuario. El proyecto recorrió el ciclo de desarrollo seguro desde el modelado de amenazas hasta la comprobación de las correcciones. PASTA organiza el análisis alrededor de los procesos del negocio. STRIDE se aplica en la etapa 4 para clasificar las amenazas por componente.

Se documentaron tres pruebas de concepto principales en la versión vulnerable. La inyección SQL del inicio de sesión permitió el acceso administrativo, un JWT alterado fue aceptado y un usuario pudo leer un ticket ajeno. H3 registró las tres señales y el WAF bloqueó la inyección SQL. H4 corrigió las tres causas en la API y registró los rechazos al repetir las pruebas con el WAF en observación.

| Evidencia de H2 | Verificación de H4 | Defensa adicional |
|---|---|---|
| 3 PoC principales con Burp Suite y Postman | 3 casos corregidos y 5 regresiones documentadas | 4 reglas propias del WAF verificadas después de H4 |

## 1. PASTA · Objetivos del negocio

Los cuatro objetivos y los códigos de operación provienen del [modelo de H1](hito-1/README.md#etapa-1--objetivos-del-negocio).

| Objetivo | Operaciones del DFD | Activos y efecto sobre el negocio |
|---|---|---|
| Proteger el acceso al CRM | A1, inicio de sesión. A2, consulta del panel. | Las cuentas, credenciales y sesiones permiten atribuir las operaciones a una identidad válida. Suplantarla expone datos y funciones del CRM. |
| Atender solicitudes sin comprometer al cliente | T1–T5, listar, buscar, leer, crear, editar o eliminar tickets. | Los datos de contacto, el contenido y el estado de los tickets deben conservarse íntegros y limitarse al personal autorizado. |
| Separar funciones y privilegios | U1–U3, listar usuarios, crear cuentas y cambiar roles. | El directorio y los permisos separan la atención de tickets de la administración del sistema. |
| Investigar abusos y fallas | O1, consulta y correlación de actividad. | Los registros deben permitir reconstruir un incidente y vincularlo con la operación, sin divulgar información de autenticación. |

<!-- salto -->

## 2. PASTA · Alcance técnico

El análisis se realizó en la instancia local del grupo, con cuentas y datos de prueba. El entorno de H0 ejecuta en Docker una web Next.js, una API Express con TypeScript y una base SQLite. La web se abre en el puerto 3000 y envía sus solicitudes de API a ModSecurity con OWASP CRS por el puerto 8080. El puerto 4000 de la API queda dentro de la red de Docker. Filebeat envía registros a Elasticsearch y el equipo los consulta en Kibana. El alcance se limita al laboratorio. [Entorno H0](hito-0/README.md) · [Docker Compose](../waf-siem/docker-compose.yml)

| Fase | Componente evaluado | Condición documentada |
|---|---|---|
| H0–H2 | Aplicación y WAF del laboratorio | En las PoC, DetectionOnly permite observar las solicitudes durante la comprobación de la línea base. |
| H3 | WAF, registros de seguridad y Kibana | En On, el WAF puede bloquear. Las búsquedas de Kibana permiten correlacionar los eventos. |
| H4 | API corregida detrás del WAF | La re-prueba con DetectionOnly permite atribuir el rechazo al código. |
| Complemento de H3 | WAF con reglas propias y API reconstruida | La validación posterior registra bloqueos del WAF en On y comprueba por separado los rechazos de la API para JWT e IDOR. |

## 3. PASTA · Descomposición y límites de confianza

El [DFD general](hito-1/dfd.svg) muestra tres límites de confianza. La entrada del cliente llega al WAF, la API decide el acceso a los datos y los registros se trasladan al SIEM. El [DFD por operación](hito-1/dfd-casos.svg) vincula cada pantalla con las rutas y los datos.

| Flujo | Qué entra, por dónde pasa y qué sale | Decisión de confianza |
|---|---|---|
| Acceso e identidad · A1–A2 | El navegador envía credenciales por el WAF. La API consulta usuarios en SQLite y devuelve una cuenta y un JWT para acceder al panel. | La API debe validar las credenciales y comprobar el token en las solicitudes siguientes. |
| Atención de tickets · T1–T5 | La API recibe la sesión y, según la operación, una búsqueda, un identificador o datos del ticket. Lee o modifica tickets en SQLite y devuelve el resultado. | Deben comprobarse el rol, el acceso al ticket específico y el tratamiento de la entrada. |
| Administración · U1–U3 | La API recibe solicitudes de consulta o de cambio y trabaja sobre el directorio de usuarios de SQLite. | Los cambios de cuenta y roles requieren autorización administrativa. Las respuestas deben limitar los campos expuestos. |
| Investigación · O1 | Los registros de ModSecurity y los eventos de la API llegan por Filebeat a Elasticsearch. El equipo los consulta en Kibana. | La evidencia debe vincularse con la ruta, hora y resultado. Los eventos de seguridad de la API excluyen tokens y contraseñas. |

<!-- salto -->

## 4. PASTA · Análisis de amenazas con STRIDE

H1 examinó las operaciones desde las perspectivas de un visitante, un usuario de consulta, un agente y un administrador. Los requisitos RS de la tabla provienen del modelo de amenazas. Su estado se determina con la evidencia de los hitos posteriores. [STRIDE y requisitos de H1](hito-1/README.md)

| STRIDE | Componente y amenaza | Requisito y evidencia |
|---|---|---|
| S · Suplantación | Autenticación de la API. Una firma JWT sin verificar permite hacerse pasar por otra identidad. | RS-01. PoC-01, evento DET-02 y rechazo de la API en H4. |
| T · Manipulación | Rutas de tickets y usuarios. Una modificación sin autorización puede cambiar estados, cuentas o roles. | RS-02 y RS-03. El control agregado en H4 se limita a la lectura del detalle de un ticket. |
| R · Repudio | API y registros. Una modificación sin actor, objeto y resultado dificulta atribuir la acción. | RS-07. H3 correlacionó eventos concretos del WAF y la API. El modelo registra la cobertura de auditoría como riesgo. |
| I · Divulgación de información | API y SQLite. La lectura de un ticket ajeno o la exposición de hashes revela datos sensibles. | RS-03 y RS-04. PoC-03 comprueba el acceso indebido al ticket. Los hashes se observaron en la respuesta de PoC-01. |
| D · Denegación de servicio | Inicio de sesión. La ausencia de límites facilita intentos repetidos y puede afectar la disponibilidad. | RS-06. H1 documenta el riesgo. No se registró una comprobación de un límite HTTP 429. |
| E · Elevación de privilegios | Rutas de administración. Una sesión sin permisos puede solicitar altas o cambios de rol. | RS-02. H1 documenta el riesgo. La corrección de firma JWT no incorpora autorización administrativa en esas rutas. |

H1 documenta ocho requisitos verificables y siete casos de abuso en formato Dado / Cuando / Entonces. Los casos CA-01, CA-02 y CA-04 enlazan con las tres PoC de H2. El alcance de CA-04 incluye el login y la búsqueda. La corrección de H4 cubre el login. [Casos de abuso](hito-1/README.md#6-casos-de-abuso)

## 5. PASTA · Análisis de vulnerabilidades

El inventario de H1 conserva diez hallazgos DAST históricos. En acceso se identificaron SQLi de login, JWT sin verificar, riesgos de sesión y falta de límite de intentos. En tickets se documentaron XSS reflejado y lectura ajena. En administración se registraron exposición de hashes y cambios de rol sin control. CORS y los errores detallados afectan a varios flujos. [Hallazgos históricos de H1](hito-1/hallazgos-dast.md)

H2 priorizó H-01, H-04 y H-03 por su efecto sobre el acceso administrativo, la identidad y los datos de clientes. La consulta SQL de búsqueda aparece en la revisión de código y en ZAP con confianza baja. Su bloqueo posterior en el WAF se comprobó como evidencia adicional. La matriz conserva las tres PoC principales de Burp y sus clasificaciones originales. [Matriz de H2](hito-2/README.md)

<!-- salto -->

## 6. PASTA · Simulación y comprobación de controles

### 6.1 H2 · Línea base y pipeline

Burp Suite y Postman documentan tres PoC sobre la API vulnerable con el WAF en DetectionOnly. Las tres devolvieron HTTP 200. En el inicio de sesión se emitió un token administrativo. En el caso de JWT se devolvió información del directorio de usuarios, incluidos hashes. En el caso de IDOR se devolvieron datos de un ticket ajeno. [Evidencia de Burp](hito-2/poc-burp.md) · [Registro de Postman](hito-2/verificacion-postman-2026-11-10.md)

| Fecha | Hito y evidencia | Resultado registrado |
|---|---|---|
| 3–4 nov | H0–H1 · [Entorno](hito-0/README.md) y [modelo](hito-1/README.md) | Configuración local, DFD, PASTA, STRIDE y hallazgos históricos. |
| 9–10 nov | H2 · [Burp](hito-2/poc-burp.md), [ZAP activo](hito-2/zap-escaneo-2026-11-10.md) y [Postman](hito-2/verificacion-postman-2026-11-10.md) | Tres PoC principales documentadas. Las clasificaciones OWASP, CWE y CVSS se conservan con la evidencia. |
| 10 nov | H2 · [Pipeline](hito-2/evidencia-pipeline-2026-11-10.md) | SAST, SCA, SBOM y ZAP baseline ejecutados y publicados en modo reporte. |
| 17 nov | H3 · [Repetición histórica](https://github.com/mar22266/proyecto-final-desarrollo/blob/051623916261727a015da5caeba71aef7d7f539a/docs/hito-3/demo-purple-team.md) | Con WAF en On, SQLi recibió 403. JWT e IDOR generaron eventos y aún recibieron 200. El registro acredita una sesión local con rol azul simulado. |
| 17 nov | H4 · [Re-prueba de la API](hito-4/README.md#re-prueba-de-poc-con-waf-en-detectiononly) | Con WAF en DetectionOnly, los rechazos de la API fueron 401, 401 y 403. |
| 17 nov | H4 · [Regresiones](hito-4/README.md#pruebas-de-regresión) | Se registraron cinco regresiones aprobadas localmente y compilación de la API. |
| 17 nov | Complemento H3 · [Evidencia posterior a H4](hito-3/evidencia-reglas-10020-10023/WAF-RT-20261118T004102Z.json) | Cuatro reglas propias verificadas en On. La evidencia adicional usa marcas UTC del 18 nov, correspondientes al 17 nov en Guatemala. |

La cronología conserva las fechas de los registros de cada hito. La repetición histórica de H3 y la re-prueba de H4 están fechadas en UTC. La validación adicional se identifica por su fecha en Guatemala.

El workflow ejecuta Semgrep para SAST, pnpm audit para SCA, Syft para el inventario SBOM CycloneDX y ZAP baseline para DAST de la superficie pública. Incluye un job de regresiones de API. El escaneo activo por el WAF pertenece a la evidencia de H2 y tuvo un alcance distinto al baseline de CI. [Workflow DevSecOps](../.github/workflows/devsecops.yml)

El gate se mantiene en modo reporte. El grupo documentó el umbral de bloqueo con cero resultados ERROR de Semgrep, cero avisos altos o críticos en dependencias de producción y cero alertas altas del baseline de ZAP. El SBOM se exige como artefacto. Un resultado verde acredita la ejecución del workflow bajo esa configuración. [Umbral documentado](hito-2/revision-gate.md)

<!-- salto -->

### 6.2 H3 · Detección, bloqueo y reglas del WAF

ModSecurity produce registros de auditoría y la API emite eventos de seguridad. Filebeat envía ambos a Elasticsearch. En Kibana, las búsquedas guardadas permiten correlacionar ruta, marca de tiempo y regla o evento. Las DET se implementaron como consultas de Discover. El bloqueo lo ejecuta ModSecurity cuando una regla aplica en modo On. [Documentación de H3](hito-3/README.md)

| Detección | Señal registrada | Resultado |
|---|---|---|
| DET-01 · SQLi de login | Auditoría WAF, regla CRS 942100 y umbral 949110. | WAF 403 en la línea base de H3. |
| DET-02 · JWT con firma inválida | Evento de API jwt_invalid_signature. | Detectado con HTTP 200 en la línea base de H3. H4 cambió la respuesta a 401. |
| DET-03 · Lectura de ticket ajeno | Evento de API ticket_foreign_access. | Detectado con HTTP 200 en la línea base de H3. H4 cambió la respuesta a 403. |
| DET-04 · XSS | Auditoría WAF, familia CRS 941 y regla propia 10022. | Respuestas 403 corroboradas en la validación adicional. |
| DET-05 · Método HTTP no permitido | Auditoría WAF, regla CRS 911100. | Respuesta 403 corroborada en la validación adicional. |

El dashboard **H3 · Detección Blue Team** reúne las tres DET principales y cuatro visualizaciones de tiempo, reglas, rutas e IP de origen. DET-04, DET-05 y las cuatro búsquedas WAF se consultan en Discover. La exportación contiene 15 objetos y el registro de entorno acredita una importación local exitosa. [Exportación de Kibana](../waf-siem/kibana-export.ndjson) · [Registro de importación](hito-3/evidencia-det-04-05/entorno-kibana.json)

**Complemento posterior a H4.** El Equipo azul incorporó cuatro reglas propias en la configuración de ModSecurity. La validación con la API reconstruida registró HTTP 403 y eventos de auditoría para cada regla. En esa misma validación, salud, login legítimo, búsqueda normal y listado de usuarios respondieron HTTP 200. [Archivo de reglas](../waf-siem/waf/REQUEST-901-CRM-CUSTOM-RULES.conf) · [Evidencia 10020–10023](hito-3/evidencia-reglas-10020-10023/WAF-RT-20261118T004102Z.json)

| Regla | Operación protegida |
|---|---|
| 10020 | Inicio de sesión ante el patrón ensayado de inyección SQL. |
| 10021 | Búsqueda de tickets ante el patrón ensayado de inyección SQL. |
| 10022 | Búsqueda de tickets ante el patrón ensayado de XSS. |
| 10023 | Consulta del detalle de usuario por la ruta sensible. |

La exclusión existente 10001 retira únicamente el encabezado Host de la evaluación de CRS 920350 al usar 127.0.0.1, con o sin puerto. La documentación de H3 indica que los flujos legítimos ensayados no requirieron exclusiones adicionales. [Configuración de la exclusión](https://github.com/mar22266/proyecto-final-desarrollo/blob/aeb04a3d39555b9d074a40bd11e9c18bb4660994/waf-siem/waf/REQUEST-901-CRM-CUSTOM-RULES.conf)

<!-- salto -->

### 6.3 H4 · Corrección y re-prueba en la API

El Equipo rojo repitió las tres PoC contra la API corregida con el WAF en DetectionOnly. Las respuestas registradas separan el efecto de la corrección de los bloqueos observados en H3. [Evidencia de H4](hito-4/README.md)

| Caso | Cambio comprobable en el código | Re-prueba documentada |
|---|---|---|
| SQLi de login · H-01 | La API usa parámetros en la consulta de credenciales. [auth.ts](../apps/api/src/auth.ts) | 401. La regresión comprueba también la ausencia de token. |
| JWT alterado · H-04 | El middleware verifica el JWT antes de usar su identidad y su rol. [Middleware de autenticación](../apps/api/src/middleware/auth.ts) | 401. Se conserva el evento para firmas inválidas. |
| IDOR de lectura · H-03 | El detalle del ticket permite el acceso al administrador, al autor o al usuario asignado. [Rutas de tickets](../apps/api/src/routes/tickets.ts) | 403 para el usuario sin acceso. La regresión comprueba el acceso legítimo del administrador. |

El registro de H4 documenta cinco regresiones locales aprobadas y la compilación de TypeScript. La suite incluye los tres rechazos, el login válido y la lectura autorizada del ticket. Las regresiones se incorporaron posteriormente como un job del workflow. La evidencia posterior, con el WAF en On, también registra los rechazos 401 y 403 de JWT e IDOR y sus eventos de API. [Suite de regresión](../apps/api/src/tests/regression.test.ts) · [Validación posterior de JWT e IDOR](hito-3/evidencia-reglas-10020-10023/JWT-IDOR-RT-20261118T004041Z.json)

La auditoría de H4 registra Claude Code, los resúmenes de los prompts, el diff y las observaciones de revisión. El historial íntegro de respuestas no se conserva. Codex se utilizó para reforzar la regresión de SQLi, incorporarla al pipeline y revisar la trazabilidad. [Auditoría de los cambios](hito-4/README.md#auditoría-del-diff)

## 7. PASTA · Impacto y riesgo residual

| Objetivo de negocio | Riesgo que permanece según el código y la evidencia |
|---|---|
| Acceso e identidad | Persisten el secreto JWT de reserva, el hash débil de contraseñas, los atributos de sesión inseguros y la falta de límite de intentos. |
| Atención de tickets | La búsqueda conserva una consulta SQL concatenada en la API. La autorización de H4 cubre el detalle de lectura. La edición y el borrado requieren controles equivalentes. |
| Administración de usuarios | La API conserva la exposición de hashes y las altas y cambios de rol carecen de autorización por rol. El bloqueo del detalle por la regla 10023 tiene alcance de WAF. |
| Investigación | La evidencia cubre detecciones y eventos concretos. Atribuir de forma completa las modificaciones de tickets y roles sigue siendo un riesgo identificado en H1. |

La auditoría SCA posterior a H4 registró **19 avisos altos y 6 críticos** en el árbol de dependencias de producción. La aceptación temporal documentada llegaba hasta H4. La revisión del repositorio no muestra una excepción posterior por paquete y aviso. El alcance del resultado se mantiene en el laboratorio local con datos de prueba.

<!-- salto -->

## Matriz de trazabilidad por vulnerabilidad

PoC es una petición y respuesta reproducible; DET identifica una búsqueda guardada de Kibana; RS es un requisito de seguridad definido en H1. La tabla señala cuando un hallazgo no tiene una PoC individual.

| Hallazgo y efecto en el negocio | PoC y clasificación H2 | Detección y bloqueo H3 | Corrección y nueva prueba H4 |
|---|---|---|---|
| **H-01, A1: SQLi del login.** Acceso como administrador sin contraseña; compromete cuentas y tickets. RS-05, CA-04. | **PoC-02** Burp/Postman: admin'-- devolvió token admin. OWASP A05, CWE-89, CVSS 9.1. ZAP activo señaló SQLi en login con confianza baja. | Semgrep y ZAP baseline son controles generales; el baseline público no demuestra esta ruta autenticada. DET-01 vio CRS 942100; WAF On devolvió 403. | Query parametrizada en auth.ts. Reprueba 401 en DetectionOnly; regresión exige 401 y ausencia de token. |
| **H-04, A1/U1 y transversal: JWT sin firma verificada.** Suplantación de identidad y privilegios; expone usuarios y puede afectar tickets. RS-01, CA-01. | **PoC-01** Burp/Postman: JWT alterado devolvió 200 y lista de usuarios. OWASP A07, CWE-347, CVSS 9.1. | No lo demuestra ZAP baseline. DET-02 registró jwt_invalid_signature en app-security; el CRS no valida criptografía y no bloqueó la línea base. | jwt.verify() en middleware; reprueba 401 en DetectionOnly; regresión exige 401. |
| **H-03, T2: IDOR de lectura.** Un usuario ve ticket y datos de cliente ajenos. RS-03, CA-02. | **PoC-03** Burp/Postman: viewer recibió ticket ajeno con 200. OWASP A01, CWE-639, CVSS 8.1. | No lo demuestra ZAP baseline. DET-03 registró ticket_foreign_access; el WAF no conoce propiedad de objetos. | GET /api/tickets/:id devuelve 403 a quien no es dueño ni asignado; reprueba 403 en DetectionOnly; regresión confirma además acceso válido de admin. |
| **H-02, T1: XSS reflejado.** Riesgo para sesión y datos del operador que consulta tickets. RS-05, CA-05. | Hallazgo DAST H1 con evidencia; **sin PoC individual de Burp H2**. | DET-04 y 403 corresponden a una prueba local adicional de XSS, no a PoC-01/02/03. | Sin corrección específica documentada en H4. |
| **H-05, U1: hashes expuestos.** Divulgación de datos de autenticación. RS-04. | Se observó passwordHash dentro de la respuesta de PoC-01; no es una cuarta PoC independiente. | DET-02 identifica el JWT alterado, no impide que una sesión legítima lea hashes. | Sigue presente en routes/users.ts; riesgo residual. |
| **H-06/H-07, A1-A2 y transversal: cookie/cabeceras y CORS.** Mayor exposición de sesiones y navegador. | Hallazgos DAST H1; sin PoC individual de Burp H2. | ZAP baseline observó cabeceras faltantes; el WAF no sustituye la política de origen ni atributos de cookie. | Sin corrección específica; riesgo residual del laboratorio. |
| **H-08, U2-U3: rol aceptado del cliente.** Escalada de privilegios y alteración de cuentas. RS-02, CA-03. | Hallazgo H1; sin PoC individual H2. | No existe detección específica demostrada para este abuso lógico. | POST /api/users y PUT /api/users/:id/role siguen sin autorización por rol; riesgo residual. |
| **H-09, A1/O1: login sin límite.** Intentos repetidos contra cuentas y disponibilidad. RS-06, CA-06. | Hallazgo H1; sin PoC individual H2. | El SIEM recibe eventos de tráfico, pero no se documentó una regla de ráfagas ni un 429. | Sin corrección específica; riesgo residual. |
| **H-10, A1-A2: errores detallados.** Filtración de detalles internos. | Hallazgo H1; sin PoC individual H2. | Los escaneos pueden señalar exposición, sin sustituto de revisión de respuesta. | H4 retiró el detalle SQL del login, pero el manejador global aún incluye message y stack; corrección parcial. |

La búsqueda de tickets q concatena SQL y las rutas PUT/DELETE no comprueban los permisos sobre el ticket. Son riesgos visibles en el código para T1/T4/T5; no se presentan como PoC de Burp ejecutadas. La [matriz de H2](hito-2/README.md) mantiene esa distinción.

<!-- salto -->

## Conclusiones

- **El impacto de negocio orientó la priorización.** Las tres PoC de H2 afectaban la identidad de la sesión, el acceso a cuentas y la confidencialidad de tickets. Los códigos A1, U1 y T2 permiten seguir esas operaciones desde el DFD hasta la re-prueba.
- **La trazabilidad permite atribuir cada resultado.** La SQLi pasó de un acceso indebido en H2 a un bloqueo del WAF en H3 y a un rechazo de la API en H4. Para JWT e IDOR, el registro de H3 identificó el problema y la re-prueba de H4 comprobó la corrección.
- **La comprobación incluye tráfico legítimo.** En la regresión de la API se conservaron el acceso válido y la lectura autorizada. Las reglas adicionales del WAF también se verificaron junto con solicitudes legítimas que respondieron 200.
- **La evaluación residual delimita el cierre técnico.** El tratamiento documentado cubre los tres casos prioritarios. El riesgo que queda en otras rutas, en las sesiones y en las dependencias respalda mantener Secure CRM en el entorno de laboratorio.

## Evidencias de referencia

| Hito | Evidencia principal |
|---|---|
| H0 · Entorno | [Configuración y roles](hito-0/README.md) · [Docker Compose](../waf-siem/docker-compose.yml) |
| H1 · Diseño | [Modelo PASTA y STRIDE](hito-1/README.md) · [DFD por operación](hito-1/dfd-casos.svg) · [Hallazgos DAST](hito-1/hallazgos-dast.md) |
| H2 · Línea base | [PoC de Burp](hito-2/poc-burp.md) · [Postman](hito-2/verificacion-postman-2026-11-10.md) · [Pipeline y artefactos](hito-2/evidencia-pipeline-2026-11-10.md) |
| H3 · Controles | [Detección y respuesta](hito-3/README.md) · [Exportación de Kibana](../waf-siem/kibana-export.ndjson) · [Validación adicional DET-04 y DET-05](hito-3/evidencia-det-04-05/RT-20261118T002052Z.json) · [Validación de cuatro reglas propias](hito-3/evidencia-reglas-10020-10023/WAF-RT-20261118T004102Z.json) |
| H4 · Correcciones | [Re-prueba y auditoría](hito-4/README.md) · [Regresiones de la API](../apps/api/src/tests/regression.test.ts) |

---

Proyecto Final Desarrollo Seguro de Software · Universidad del Valle de Guatemala
