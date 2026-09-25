#!/usr/bin/env bash
#
# APIShield LOCAL DEVELOPMENT / DEMO JWT helper - NOT for production use.
#
# Creates a throwaway RSA key pair and mints RS256 JWTs signed with it, so the Docker demo
# (docker-compose.demo.yml) can run authenticated end-to-end tests. APIShield itself only ever
# receives the PUBLIC key and validates tokens with its normal JWT resource-server support;
# the private key stays on this machine in demo/jwt/, which is git-ignored and docker-ignored.
#
# Usage:
#   scripts/demo-jwt.sh keys [--force]              generate demo/jwt/private.pem + public.pem
#   scripts/demo-jwt.sh token <subject> [ttl-sec]   print a signed JWT (default ttl 3600;
#                                                   a negative ttl yields an already-expired token)
#
# Requires: bash, openssl.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KEY_DIR="${APISHIELD_DEMO_JWT_DIR:-$SCRIPT_DIR/../demo/jwt}"
PRIVATE_KEY="$KEY_DIR/private.pem"
PUBLIC_KEY="$KEY_DIR/public.pem"

# Must match SPRING_SECURITY_OAUTH2_RESOURCESERVER_JWT_AUDIENCES in docker-compose.demo.yml.
AUDIENCE="apishield-demo"
ISSUER="apishield-local-demo"

usage() {
  sed -n '3,15p' "$0" | sed 's/^# \{0,1\}//'
  exit 1
}

base64url() {
  openssl base64 -A | tr '+/' '-_' | tr -d '='
}

json_escape() {
  local value=$1
  value=${value//\\/\\\\}
  value=${value//\"/\\\"}
  printf '%s' "$value"
}

generate_keys() {
  if [[ -f "$PRIVATE_KEY" && "${1:-}" != "--force" ]]; then
    echo "Demo keys already exist in $KEY_DIR (use --force to replace them)." >&2
    exit 1
  fi
  mkdir -p "$KEY_DIR"
  (umask 077 && openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$PRIVATE_KEY" 2>/dev/null)
  openssl pkey -in "$PRIVATE_KEY" -pubout -out "$PUBLIC_KEY"
  chmod 600 "$PRIVATE_KEY"
  chmod 644 "$PUBLIC_KEY"
  echo "DEMO keys written to $KEY_DIR (private.pem stays local; only public.pem is mounted into APIShield)." >&2
}

mint_token() {
  local subject=${1:-}
  local ttl=${2:-3600}
  [[ -n "$subject" ]] || usage
  [[ "$ttl" =~ ^-?[0-9]+$ ]] || { echo "ttl must be an integer number of seconds" >&2; exit 1; }
  [[ -f "$PRIVATE_KEY" ]] || { echo "No demo private key - run: $0 keys" >&2; exit 1; }

  local now exp header payload signature
  now=$(date +%s)
  exp=$((now + ttl))
  header=$(printf '{"alg":"RS256","typ":"JWT"}' | base64url)
  payload=$(printf '{"sub":"%s","aud":"%s","iss":"%s","iat":%d,"exp":%d}' \
    "$(json_escape "$subject")" "$AUDIENCE" "$ISSUER" "$now" "$exp" | base64url)
  signature=$(printf '%s.%s' "$header" "$payload" | openssl dgst -sha256 -sign "$PRIVATE_KEY" -binary | base64url)
  printf '%s.%s.%s\n' "$header" "$payload" "$signature"
}

case "${1:-}" in
  keys) generate_keys "${2:-}" ;;
  token) mint_token "${2:-}" "${3:-}" ;;
  *) usage ;;
esac
