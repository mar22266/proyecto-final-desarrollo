#!/usr/bin/env bash
# Tráfico legítimo a través del WAF. Sirve de baseline para el Hito 3
# (lo que el WAF no debería bloquear cuando pasen a modo On).
#
# Las rutas de abajo son las de Secure CRM. Cámbienlas por las de su app.
# Uso, desde waf-siem/:  ./scripts/trafico-legitimo.sh
set -u

WAF_URL="${WAF_URL:-http://127.0.0.1:8080}"

echo "=== Tráfico legítimo por el WAF ($WAF_URL) ==="
echo "Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"

pedir() {
  local method="$1" url="$2" data="${3:-}"
  local code
  if [ -n "$data" ]; then
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 15 -X "$method" \
      -H 'Content-Type: application/json' --data "$data" "$url" || true)"
  else
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 15 -X "$method" "$url" || true)"
  fi
  printf '%s  HTTP %s  %s %s\n' "$(date -u +%H:%M:%S)" "${code:-000}" "$method" "$url"
  sleep 1
}

# Comprobación pública mínima. Las rutas de tickets requieren un JWT; para
# probarlas hay que iniciar sesión y enviar Authorization: Bearer <token>.
pedir GET "$WAF_URL/api/health"
pedir POST "$WAF_URL/api/auth/login" '{"username":"jperez","password":"Password1"}'

echo "=== Listo. En Kibana busquen fields.fuente : \"waf-access\" (Last 15 minutes) ==="
