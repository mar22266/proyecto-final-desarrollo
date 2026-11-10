# Verificación local de la colección Postman

Fecha: 10 de noviembre de 2026. Entorno de prueba: instancia local de Secure CRM a través del WAF en `http://localhost:8080`, con `MODSEC_RULE_ENGINE=DetectionOnly`.

La colección [`poc-postman.json`](poc-postman.json) se ejecutó con Newman 6.2.3:

```bash
npx --yes newman@6.2.3 run docs/hito-2/poc-postman.json --reporters json --reporter-json-export resultado-local.json
```

La corrida comenzó a las **2026-11-10T18:00:01.965Z** y terminó a las **2026-11-10T18:00:02.141Z**. Newman registró **7 solicitudes, 8 aserciones correctas y 0 fallos**.

| Solicitud | Ruta por el WAF | HTTP observado | Comprobación |
|---|---|---:|---|
| PoC-01a | `POST /api/auth/login` | 200 | Se obtuvo un token de `viewer`. |
| PoC-01b | `GET /api/users` | 200 | El token con firma falsa obtuvo usuarios y `passwordHash`. |
| PoC-02a | `POST /api/auth/login` | 200 | El payload SQLi obtuvo un token de administrador. |
| PoC-02b | `POST /api/auth/login` | 500 | El error SQL verboso coincidió con la aserción esperada. |
| PoC-03a | `POST /api/auth/login` | 200 | Se obtuvo un token de `viewer`. |
| PoC-03b | `GET /api/tickets/1` | 200 | El `viewer` leyó un ticket ajeno. |
| PoC-03c | `GET /api/tickets/2` | 200 | El `viewer` leyó otro ticket. |

El código 500 de PoC-02b es el resultado esperado de esa prueba; no representa un fallo de ejecución de Newman. La salida JSON sin filtrar contiene tokens y respuestas de prueba, por lo que no se publica en el repositorio. Este resumen conserva los resultados necesarios para repetir y revisar la prueba sin exponer esos valores.

Esta corrida local verifica que la colección funciona en el entorno de André. El registro de horas de Davis para su propia corrida está en el [resumen de Hito 2](README.md#ejecución-en-postman-con-marca-de-tiempo); son ejecuciones distintas.
