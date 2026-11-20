"""Disposable private PKI for E6: four certificate profiles + signed OCSP fixtures.

Never overwrites an existing directory, never loads a system CA, never publishes
keys. All private material lives under ignored data/runtime/.
"""
import argparse
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import subprocess

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import ocsp


def openssl(*args):
    subprocess.run(["openssl", *map(str, args)], check=True, stdout=subprocess.DEVNULL)


def sign_response(cert, issuer, signer, key, *, revoked: bool, freshness: str,
                  algorithm, now: datetime | None = None) -> bytes:
    """Sign one OCSP response matching the request's CertID hash.

    Request-time signatures keep fresh OCSP evidence fresh during long runs.
    """
    if freshness not in ("fresh", "expired"):
        raise ValueError("invalid OCSP freshness")
    now = now or datetime.now(timezone.utc)
    this_update = now - timedelta(minutes=5) if freshness == "fresh" else now - timedelta(days=2)
    next_update = now + timedelta(minutes=10) if freshness == "fresh" else now - timedelta(days=1)
    builder = (ocsp.OCSPResponseBuilder()
               .add_response(
                   cert=cert, issuer=issuer, algorithm=algorithm,
                   cert_status=ocsp.OCSPCertStatus.REVOKED if revoked else ocsp.OCSPCertStatus.GOOD,
                   this_update=this_update, next_update=next_update,
                   revocation_time=max(cert.not_valid_before_utc, now - timedelta(minutes=1)) if revoked else None,
                   revocation_reason=x509.ReasonFlags.key_compromise if revoked else None)
               .responder_id(ocsp.OCSPResponderEncoding.HASH, signer)
               .certificates([signer]))
    return builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)


def generate(out: Path, *, uri: str = "http://10.77.2.2:8888") -> Path:
    if uri not in ("http://10.77.2.2:8888", "http://127.0.0.1:8888"):
        raise ValueError("OCSP URI must be a local test responder")
    if not os.environ.get("KS_PASS"):
        raise EnvironmentError("KS_PASS required")
    if out.exists():
        raise FileExistsError("E6 PKI must use a new directory (never overwrite keys)")
    out.mkdir(parents=True)
    (out/"newcerts").mkdir()
    (out/"index.txt").touch()
    (out/"serial").write_text("2000\n")
    (out/"crlnumber").write_text("2000\n")
    config = out/"openssl.cnf"
    config.write_text(f"""[ req ]
prompt = no
distinguished_name = dn
x509_extensions = v3_ca
[ dn ]
CN = E6 TLS lab Root CA
[ ca ]
default_ca = local_ca
[ local_ca ]
dir = {out.resolve()}
database = $dir/index.txt
new_certs_dir = $dir/newcerts
serial = $dir/serial
crlnumber = $dir/crlnumber
certificate = $dir/ca.crt
private_key = $dir/ca.key
default_md = sha256
default_days = 30
default_crl_days = 30
policy = allow_name
email_in_dn = no
unique_subject = no
copy_extensions = none
[ allow_name ]
commonName = supplied
[ v3_ca ]
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
[ ocsp_signer ]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = OCSPSigning
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
[ plain ]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
subjectAltName = @alt_names
authorityInfoAccess = OCSP;URI:{uri}
[ muststaple ]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
subjectAltName = @alt_names
authorityInfoAccess = OCSP;URI:{uri}
tlsfeature = status_request
[ alt_names ]
DNS.1 = lab.test
IP.1 = 127.0.0.1
IP.2 = 10.77.1.1
""")
    openssl("req", "-new", "-x509", "-newkey", "ec", "-pkeyopt",
            "ec_paramgen_curve:P-256", "-noenc", "-days", "30",
            "-keyout", out/"ca.key", "-out", out/"ca.crt",
            "-config", config, "-extensions", "v3_ca")
    openssl("req", "-new", "-newkey", "ec", "-pkeyopt",
            "ec_paramgen_curve:P-256", "-noenc",
            "-keyout", out/"ocsp.key", "-out", out/"ocsp.csr",
            "-subj", "/CN=E6 OCSP Signer")
    openssl("ca", "-batch", "-notext", "-config", config,
            "-extensions", "ocsp_signer",
            "-in", out/"ocsp.csr", "-out", out/"ocsp.crt")
    names = []
    for status in ("good", "revoked"):
        for variant in ("plain", "muststaple"):
            name = status + "_" + variant
            names.append(name)
            openssl("req", "-new", "-newkey", "ec", "-pkeyopt",
                    "ec_paramgen_curve:P-256", "-noenc",
                    "-keyout", out/f"{name}.key", "-out", out/f"{name}.csr",
                    "-subj", "/CN=lab.test")
            openssl("ca", "-batch", "-notext", "-config", config,
                    "-extensions", variant, "-in", out/f"{name}.csr",
                    "-out", out/f"{name}.crt")
            openssl("pkcs12", "-export", "-inkey", out/f"{name}.key",
                    "-in", out/f"{name}.crt", "-certfile", out/"ca.crt",
                    "-out", out/f"{name}.p12", "-passout", "env:KS_PASS")
            if status == "revoked":
                openssl("ca", "-config", config, "-revoke",
                        out/f"{name}.crt", "-crl_reason", "keyCompromise")
    openssl("ca", "-config", config, "-gencrl", "-out", out/"crl.pem")
    subprocess.run(["keytool", "-importcert", "-noprompt", "-alias", "e6-root",
                    "-storetype", "PKCS12", "-keystore", str(out/"truststore.p12"),
                    "-storepass", os.environ["KS_PASS"], "-file", str(out/"ca.crt")],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    ca = x509.load_pem_x509_certificate((out/"ca.crt").read_bytes())
    signer = x509.load_pem_x509_certificate((out/"ocsp.crt").read_bytes())
    key = serialization.load_pem_private_key((out/"ocsp.key").read_bytes(), password=None)
    mapping = {}
    for name in names:
        cert = x509.load_pem_x509_certificate((out/f"{name}.crt").read_bytes())
        mapping[str(cert.serial_number)] = name
        # Reference fixtures use SHA-1; the live responder uses the request digest.
        for freshness in ("fresh", "expired"):
            der = sign_response(cert, ca, signer, key, revoked=name.startswith("revoked"),
                                freshness=freshness, algorithm=hashes.SHA1())
            (out/f"{name}-{freshness}.der").write_bytes(der)
    (out/"serial-map.json").write_text(json.dumps(mapping, indent=2))
    return out


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--uri", default="http://10.77.2.2:8888")
    args = p.parse_args()
    print(generate(args.out, uri=args.uri))


if __name__ == "__main__":
    main()
