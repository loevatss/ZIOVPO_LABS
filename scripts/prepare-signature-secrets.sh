#!/usr/bin/env bash
set -euo pipefail

KEYSTORE_PATH="${1:-certs/rbpo_ticket_signing_1BIB23403.p12}"

if [[ ! -f "$KEYSTORE_PATH" ]]; then
  echo "Keystore not found: $KEYSTORE_PATH" >&2
  exit 1
fi

KEYSTORE_B64=$(base64 < "$KEYSTORE_PATH" | tr -d '\n')

echo "Set this in GitHub Secrets:"
echo "SIGNATURE_KEYSTORE_B64=$KEYSTORE_B64"
echo "SIGNATURE_KEYSTORE_PASSWORD=<your keystore password>"
echo "SIGNATURE_KEY_PASSWORD=<your key password>"
echo
echo "Set this in GitHub Variables:"
echo "SIGNATURE_ALGORITHM=SHA256withRSA"
echo "SIGNATURE_KEYSTORE_TYPE=PKCS12"
echo "SIGNATURE_KEY_ALIAS=ticket-signing"
