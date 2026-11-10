import { appendFileSync } from 'fs';
import { Request } from 'express';

const logPath = process.env.SECURITY_LOG_PATH;

type SecurityEvent = 'jwt_invalid_signature' | 'ticket_foreign_access';

export function recordSecurityEvent(
  req: Request,
  event: SecurityEvent,
  details: Record<string, string | number | undefined> = {}
) {
  if (!logPath) return;

  const entry = {
    timestamp: new Date().toISOString(),
    event,
    method: req.method,
    path: req.originalUrl.split('?')[0],
    ...details,
  };

  try {
    appendFileSync(logPath, `${JSON.stringify(entry)}\n`, { encoding: 'utf8', mode: 0o600 });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`No se pudo escribir el evento de seguridad: ${message}`);
  }
}
