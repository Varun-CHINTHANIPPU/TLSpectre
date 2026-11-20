"""Limited E1 smoke probes. Never promotes a timeout to 'secure'."""
import argparse
import http.client
import json
import socket
import ssl
from pathlib import Path
import sys

import yaml

ROOT = Path(__file__).resolve().parents[2]


def tls_request(host: str, port: int, ca_file: str, protocol: ssl.TLSVersion,
                path: str = "/health") -> dict:
    ctx = ssl.create_default_context(cafile=ca_file)
    ctx.minimum_version = protocol
    ctx.maximum_version = protocol
    with socket.create_connection((host, port), timeout=5) as raw:
        with ctx.wrap_socket(raw, server_hostname="lab.test") as secure:
            secure.settimeout(5)
            negotiated = secure.version()
            secure.sendall(f"HEAD {path} HTTP/1.1\r\nHost: lab.test\r\nConnection: close\r\n\r\n".encode())
            response = http.client.HTTPResponse(secure)
            response.begin()
            return {"status": response.status, "headers": dict(response.getheaders()),
                    "protocol": negotiated, "suite": secure.cipher()[0]}


def plain_redirect(host: str, port: int) -> dict:
    client = http.client.HTTPConnection(host, port, timeout=5)
    try:
        client.request("HEAD", "/health", headers={"Host": "lab.test"})
        res = client.getresponse()
        return {"status": res.status, "headers": dict(res.getheaders())}
    finally:
        client.close()


def run(config: dict, ca_file: str) -> dict:
    host = config.get("bindHost", "127.0.0.1")
    https_port = int(config.get("httpsPort", 8443))
    http_port = int(config.get("httpPort", 8080))
    expected_12 = "TLSv1.2" in config.get("protocols", ["TLSv1.3"])
    tests = {}

    def record(name, expected, action):
        try:
            actual = action()
            tests[name] = {"result": "PASS" if expected(actual) else "FAIL", "observed": actual}
        except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
            tests[name] = {"result": "ERROR", "error_type": type(exc).__name__,
                           "detail": str(exc)[:400]}

    record("tls13", lambda r: r["protocol"] == "TLSv1.3" and r["status"] == 200,
           lambda: tls_request(host, https_port, ca_file, ssl.TLSVersion.TLSv1_3))
    try:
        r = tls_request(host, https_port, ca_file, ssl.TLSVersion.TLSv1_2)
        tests["tls12"] = {"result": "PASS" if expected_12 else "FAIL", "observed": r}
    except ssl.SSLError as exc:
        tests["tls12"] = {"result": "FAIL" if expected_12 else "PASS",
                          "observed": "TLS1.2 handshake rejected", "detail": str(exc)[:200]}
    except OSError as exc:
        tests["tls12"] = {"result": "ERROR", "detail": str(exc)[:200]}
    record("hsts_200",
           lambda r: bool(r["headers"].get("Strict-Transport-Security")) == bool(config.get("hsts", True)),
           lambda: tls_request(host, https_port, ca_file, ssl.TLSVersion.TLSv1_3))
    record("hsts_404",
           lambda r: r["status"] == 404 and bool(r["headers"].get("Strict-Transport-Security")) == bool(config.get("hsts", True)),
           lambda: tls_request(host, https_port, ca_file, ssl.TLSVersion.TLSv1_3, "/not-found"))
    record("redirect",
           lambda r: (r["status"] == 308 and r["headers"].get("Location", "").startswith("https://"))
                     if config.get("httpRedirect", True) else r["status"] != 308,
           lambda: plain_redirect(host, http_port))
    record("banner", lambda r: not any(k.lower() == "server" for k in r["headers"]),
           lambda: tls_request(host, https_port, ca_file, ssl.TLSVersion.TLSv1_3))
    return {"description": "partial E1 smoke test; NOT a full E1 security assessment",
            "tests": tests,
            "complete": all(v["result"] == "PASS" for v in tests.values())}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", type=Path, default=Path("configs/server/P1.yaml"))
    ap.add_argument("--ca-file", default="pki/out/ca.crt")
    ap.add_argument("--output", type=Path)
    ns = ap.parse_args()
    config = yaml.safe_load(ns.config.read_text())
    output = run(config, ns.ca_file)
    data = json.dumps(output, indent=2)
    print(data)
    if ns.output:
        ns.output.parent.mkdir(parents=True, exist_ok=True)
        ns.output.write_text(data + "\n")
    return 0 if output["complete"] else 1


if __name__ == "__main__":
    sys.exit(main())
