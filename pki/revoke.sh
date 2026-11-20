#!/usr/bin/env bash
# Irreversible within the current lab CA database. Regenerate the lab CA to reset.
set -euo pipefail
cd "$(dirname "$0")/.."
profile="${1:-srv_plain}"
case "$profile" in
  srv_plain|srv_muststaple) ;;
  *) echo "Usage: bash pki/revoke.sh [srv_plain|srv_muststaple]" >&2; exit 2;;
esac
openssl ca -config pki/openssl.cnf -revoke "pki/out/$profile.crt" -crl_reason keyCompromise
openssl ca -config pki/openssl.cnf -gencrl -out pki/out/crl.pem
echo "Revoked $profile in local database. Restart OCSP responder and Jetty to clear stale state."
