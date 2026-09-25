#!/usr/bin/env bash
set -euo pipefail

if ! command -v softhsm2-util >/dev/null 2>&1; then
  echo "softhsm2-util not found; install SoftHSM v2 before running this script." >&2
  exit 1
fi

if ! command -v openssl >/dev/null 2>&1; then
  echo "openssl not found; demo key import will be skipped." >&2
  OPENSSL_AVAILABLE=0
else
  OPENSSL_AVAILABLE=1
fi

TOKEN_DIR="${SOFTHSM_TOKEN_DIR:-$PWD/.softhsm-tokens}"
SO_PIN="${SOFTHSM_SO_PIN:-1234}"
USER_PIN="${SOFTHSM_USER_PIN:-1234}"
LABEL="${SOFTHSM_LABEL:-wasm-pkcs11}"
IMPORT_DEMO="${SOFTHSM_IMPORT_DEMO:-1}"

mkdir -p "$TOKEN_DIR"

cat >"$TOKEN_DIR/softhsm2.conf" <<EOF
directories.tokendir = $TOKEN_DIR
objectstore.backend = file
EOF

export SOFTHSM2_CONF="$TOKEN_DIR/softhsm2.conf"

softhsm2-util --init-token --free --label "$LABEL" --so-pin "$SO_PIN" --pin "$USER_PIN"

if [[ "$IMPORT_DEMO" != "0" && "$OPENSSL_AVAILABLE" -eq 1 ]]; then
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  openssl genrsa -out "$tmp/demo-key.pem" 2048 >/dev/null
  openssl pkcs8 -topk8 -inform PEM -outform DER -in "$tmp/demo-key.pem" \
    -out "$tmp/demo-key.der" -nocrypt >/dev/null
  openssl rand -out "$tmp/aes-32.key" 32 >/dev/null

  softhsm2-util --import "$tmp/demo-key.der" \
    --token "$LABEL" \
    --label "demo-rsa" \
    --id A1B2C3D4 \
    --pin "$USER_PIN" \
    --so-pin "$SO_PIN" \
    --type privkey >/dev/null

  softhsm2-util --import "$tmp/aes-32.key" \
    --token "$LABEL" \
    --label "demo-aes" \
    --id D4C3B2A1 \
    --pin "$USER_PIN" \
    --so-pin "$SO_PIN" \
    --type secretkey \
    --key-type aes \
    --key-size 256 >/dev/null
fi

echo "SoftHSM token initialized:"
echo "  Label    : $LABEL"
echo "  SO PIN   : $SO_PIN"
echo "  User PIN : $USER_PIN"
echo "  Tokens   : $TOKEN_DIR"
if [[ "$IMPORT_DEMO" != "0" && "$OPENSSL_AVAILABLE" -eq 1 ]]; then
  echo "  Demo RSA private key label: demo-rsa (ID A1B2C3D4)"
  echo "  Demo AES-256 secret key label: demo-aes (ID D4C3B2A1)"
fi
