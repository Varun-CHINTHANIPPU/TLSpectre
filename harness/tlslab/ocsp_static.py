"""Serve signed, request-matched good/revoked OCSP responses for E6.

Responses are selected by certificate serial AND verified issuer hashes, then
signed with the request's CertID digest. Private lab only.
"""
import argparse
import base64
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
from urllib.parse import unquote

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import ocsp

from .e6_pki import sign_response


def serve(directory: Path, *, freshness: str, bind: str, port: int):
    if freshness not in ("fresh", "expired"):
        raise ValueError("invalid freshness")
    if bind not in ("127.0.0.1", "10.77.2.2"):
        raise ValueError("OCSP responder must bind to loopback or the laboratory namespace")
    # E6 uses an explicit serial map; the ordinary E1/E7 lab PKI contains
    # two non-revoked server certificates without an extra mapping file.
    map_path = directory/"serial-map.json"
    if map_path.is_file():
        mapping = json.loads(map_path.read_text())
    else:
        mapping = {}
        for name in ("srv_plain", "srv_muststaple"):
            certificate = x509.load_pem_x509_certificate(
                (directory/f"{name}.crt").read_bytes())
            mapping[str(certificate.serial_number)] = name
    issuer = x509.load_pem_x509_certificate((directory/"ca.crt").read_bytes())
    signer = x509.load_pem_x509_certificate((directory/"ocsp.crt").read_bytes())
    key = serialization.load_pem_private_key((directory/"ocsp.key").read_bytes(), password=None)
    certs = {serial: x509.load_pem_x509_certificate((directory/f"{name}.crt").read_bytes())
             for serial, name in mapping.items()}

    class Handler(BaseHTTPRequestHandler):
        def respond(self, data: bytes):
            try:
                request = ocsp.load_der_ocsp_request(data)
                serial = str(request.serial_number)
                name = mapping[serial]
                cert = certs[serial]
                expected = ocsp.OCSPRequestBuilder().add_certificate(
                    cert, issuer, request.hash_algorithm).build()
                if (request.issuer_name_hash != expected.issuer_name_hash or
                        request.issuer_key_hash != expected.issuer_key_hash):
                    raise ValueError("OCSP request issuer differs from lab CA")
                body = sign_response(cert, issuer, signer, key,
                                     revoked=name.startswith("revoked"), freshness=freshness,
                                     algorithm=request.hash_algorithm)
            except (ValueError, TypeError, KeyError, FileNotFoundError):
                self.send_error(400, "unknown OCSP request")
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/ocsp-response")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 1 <= length <= 16384:
                    raise ValueError()
                data = self.rfile.read(length)
            except ValueError:
                self.send_error(400)
                return
            self.respond(data)

        def do_GET(self):
            try:
                encoded = unquote(self.path.lstrip("/"))
                self.respond(base64.b64decode(encoded, validate=True))
            except ValueError:
                self.send_error(400)

        def log_message(self, *args):
            pass

    HTTPServer((bind, port), Handler).serve_forever()


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--dir", type=Path, required=True)
    p.add_argument("--freshness", choices=["fresh", "expired"], required=True)
    p.add_argument("--bind", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8888)
    args = p.parse_args()
    serve(args.dir, freshness=args.freshness, bind=args.bind, port=args.port)


if __name__ == "__main__":
    main()
