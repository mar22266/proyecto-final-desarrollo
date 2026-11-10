# Mapa de superficie de ataque · Secure CRM

Responsable: Davis Roldán (Equipo rojo). Derivado del código fuente en `apps/api/src/` y del DFD del Hito 1.

## Entradas globales (aplican a todas las rutas)

| Entrada global | Descripción | Riesgo |
|---|---|---|
| Cabecera `Authorization: Bearer <jwt>` | Token JWT decodificado sin verificar firma (`jwt.decode`, no `jwt.verify`) | Cualquier usuario puede forjar un token con el rol que quiera |
| Cookie `session` | Alternativa al header; sin `HttpOnly`, `Secure` ni `SameSite` | Robable desde JavaScript |
| Cabecera `Origin` | CORS refleja cualquier origen con `Allow-Credentials: true` | Habilita peticiones cross-origin autenticadas desde sitios maliciosos |

## Rutas y métodos

### Sin autenticación

| Ruta | Método | Rol requerido | Entrada | Salida | Hallazgo DAST | CWE |
|---|---|---|---|---|---|---|
| `/api/health` | GET | Ninguno | — | `{status, service}` | Fingerprinting (revela nombre del servicio) | CWE-200 |
| `/api/auth/login` | POST | Ninguno | Body: `{username, password}` | `{token, user}` + cookie `session` | SQLi en `username`; fuerza bruta sin límite; error verboso con SQL y stack; cookie insegura | CWE-89, CWE-307, CWE-209, CWE-1004 |

### Tickets — requiere JWT (cualquier rol: admin, agent, viewer)

| Ruta | Método | Rol requerido | Entrada | Salida | Hallazgo DAST | CWE |
|---|---|---|---|---|---|---|
| `/api/tickets` | GET | Cualquiera | Query: `q` (cadena de búsqueda) | `{query, tickets[]}` — incluye todos los tickets | SQLi en `q` por concatenación; XSS reflejado (`q` se devuelve sin sanitizar) | CWE-89, CWE-79 |
| `/api/tickets/:id` | GET | Cualquiera | Path: `id` | Ticket completo | IDOR: sin verificar propietario ni rol | CWE-639 |
| `/api/tickets` | POST | Cualquiera (**viewer puede crear**) | Body: campos del ticket | Ticket creado | Broken Access Control (viewer no debería crear); acepta campos extra (mass assignment) | CWE-862, CWE-915 |
| `/api/tickets/:id` | PUT | Cualquiera (**viewer puede editar cualquier ticket**) | Path: `id` + body con cambios | Ticket actualizado | IDOR + Broken Access Control | CWE-639, CWE-862 |
| `/api/tickets/:id` | DELETE | Cualquiera (**cualquier rol borra cualquier ticket**) | Path: `id` | `{ok: true}` | IDOR + Broken Access Control | CWE-639, CWE-862 |

### Usuarios — requiere JWT (cualquier rol; debería ser solo admin)

| Ruta | Método | Rol requerido | Entrada | Salida | Hallazgo DAST | CWE |
|---|---|---|---|---|---|---|
| `/api/users` | GET | Cualquiera (**debería ser admin**) | — | Lista de usuarios con `passwordHash` (MD5) | Broken Access Control; exposición de hashes MD5 sin salt | CWE-862, CWE-327, CWE-256 |
| `/api/users/:id` | GET | Cualquiera | Path: `id` | Usuario con `passwordHash` | IDOR; exposición de hash | CWE-639, CWE-327 |
| `/api/users` | POST | Cualquiera (**debería ser admin**) | Body: `{username, email, fullName, role, password}` | Usuario creado | Escalada de privilegios: `role` viene del cliente sin restricción; mass assignment | CWE-915, CWE-862 |
| `/api/users/:id/role` | PUT | Cualquiera (**debería ser admin**) | Path: `id` + body: `{role}` | `{id, username, role}` | Cambio de rol sin verificar que el solicitante sea admin | CWE-862 |

### Dashboard — requiere JWT (cualquier rol)

| Ruta | Método | Rol requerido | Entrada | Salida | Hallazgo DAST |
|---|---|---|---|---|---|
| `/api/dashboard` | GET | Cualquiera | — | Métricas: total de tickets, por estado, por prioridad, por agente, 5 recientes | Sin vulnerabilidad específica; expone conteos a cualquier rol |

## Datos en riesgo

| Dato | Almacén | Ruta de acceso | Riesgo |
|---|---|---|---|
| Credenciales (username + password) | SQLite `users.password_hash` | `/api/auth/login` | SQLi → bypass de autenticación |
| Hash MD5 de contraseñas | SQLite `users.password_hash` | `/api/users`, `/api/users/:id` | Expuesto en JSON; MD5 sin salt es trivial de romper |
| Contenido de tickets (título, descripción, cliente) | SQLite `tickets` | `/api/tickets`, `/api/tickets/:id` | Lectura y modificación sin verificar propietario (IDOR) |
| Token JWT | Respuesta JSON + cookie | `/api/auth/login` | Cookie sin `HttpOnly`; firma no verificada → forgeable |
| Roles de usuario | SQLite `users.role` | `/api/users/:id/role` | Cualquier usuario puede cambiar el rol de cualquier cuenta |

## Límites de confianza y bypass del WAF

| Límite | Descripción | Verificación local |
|---|---|---|
| Límite 1 → Límite 2 | Navegador / Postman → WAF en `localhost:8080` | `curl http://localhost:8080/api/health` → HTTP 200 ✓ |
| Acceso directo a la API | Puerto `4000` no publicado al host | `curl http://localhost:4000/api/health` → conexión rechazada ✓ |
| WAF en `DetectionOnly` | El WAF registra pero no bloquea; los ataques pasan hacia la API | Payloads SQLi y XSS llegan a Express sin modificar |

> La verificación de los puertos se realiza con el entorno Docker levantado desde `waf-siem/`. Ver sección de verificación abajo.

## Tres hallazgos candidatos para los PoC del Hito 2

| Prioridad | Hallazgo | Ruta | CVSS | Justificación |
|---|---|---|---|---|
| 1 | JWT sin verificación de firma | Middleware `auth.ts` / todas las rutas autenticadas | 9.1 Crítica | Impacto total en autenticación y autorización; explotación sin credenciales |
| 2 | SQL Injection en login | `POST /api/auth/login` | 9.1 Crítica | Permite bypass completo de autenticación sin conocer contraseña |
| 3 | IDOR en tickets | `GET /PUT /DELETE /api/tickets/:id` | 8.1 Alta | Lectura y modificación de datos de cualquier usuario con cualquier rol |

## Verificación de puertos (Equipo rojo)

```bash
# Debe devolver HTTP 200 con {"status":"ok"}
curl -s http://localhost:8080/api/health | jq .

# Debe fallar con "Connection refused" (puerto no publicado al host)
curl -s http://localhost:4000/api/health
```

Resultado esperado: el puerto `8080` responde por el WAF; el puerto `4000` no es accesible desde el host. Si `4000` responde, existe un bypass del WAF que debe documentarse.
