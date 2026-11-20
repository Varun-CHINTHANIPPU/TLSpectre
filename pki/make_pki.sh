#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
: "${KS_PASS:?Export KS_PASS; this password is used for lab PKCS12 keystores}"
umask 077
DIR="pki/out"
if [[ -e "$DIR/index.txt" ]]; then
  echo "PKI already exists in $DIR; remove it explicitly to generate new lab keys." >&2
  exit 2
fi
mkdir -p "$DIR/newcerts"
touch "$DIR/index.txt"
printf '1000\n' > "$DIR/serial"
printf '1000\n' > "$DIR/crlnumber"
openssl req -new -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -noenc \
  -keyout "$DIR/ca.key" -out "$DIR/ca.crt" -days 3650 \
  -config pki/openssl.cnf -extensions v3_ca
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -noenc \
  -keyout "$DIR/ocsp.key" -out "$DIR/ocsp.csr" -subj "/CN=TLS13-Lab OCSP Signer"
openssl ca -batch -notext -config pki/openssl.cnf -extensions ocsp_signer \
  -in "$DIR/ocsp.csr" -out "$DIR/ocsp.crt"
for profile in srv_plain srv_muststaple; do
  openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -noenc \
    -keyout "$DIR/$profile.key" -out "$DIR/$profile.csr" -subj "/CN=lab.test"
  openssl ca -batch -notext -config pki/openssl.cnf -extensions "$profile" \
    -in "$DIR/$profile.csr" -out "$DIR/$profile.crt"
  openssl pkcs12 -export -inkey "$DIR/$profile.key" -in "$DIR/$profile.crt" \
    -certfile "$DIR/ca.crt" -out "$DIR/$profile.p12" -passout env:KS_PASS
done
keytool -importcert -noprompt -alias lab-ca -storetype PKCS12 \
  -keystore "$DIR/truststore.p12" -storepass "$KS_PASS" -file "$DIR/ca.crt"
openssl ca -config pki/openssl.cnf -gencrl -out "$DIR/crl.pem"
openssl verify -CAfile "$DIR/ca.crt" "$DIR/srv_plain.crt" "$DIR/srv_muststaple.crt"
echo "Generated ephemeral lab PKI in $DIR. Never commit its private keys."
