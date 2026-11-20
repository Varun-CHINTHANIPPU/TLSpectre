"""Prepare or run nginx B3 reference without touching global nginx configuration."""
import argparse
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / "data/runtime"
NGINX_TEMP_SUBDIRS = ("client-body", "proxy", "fastcgi", "uwsgi", "scgi")
PATTERN = bytes((i * 31 + 17) & 255 for i in range(16384))


def fuzz_cert_lines(fuzz_dir: Path | None) -> str:
    """Provide a separate E1-only RSA certificate for RSA-only TLS fuzz clients.

    The original ECDSA lab certificate stays configured, so ECDSA clients can
    still exercise the original certificate and its OCSP staple. This does
    not modify the project's default nginx reference configuration.
    """
    if fuzz_dir is None:
        return ""
    directory = fuzz_dir.resolve()
    crt, key = directory / "rsa.crt", directory / "rsa.key"
    if not (crt.is_file() and key.is_file()):
        raise FileNotFoundError(f"RSA fuzz credential missing in {directory}")
    return ("        # E1-only secondary RSA certificate for tlsfuzzer.\n"
            f"        ssl_certificate {crt};\n"
            f"        ssl_certificate_key {key};")


def prepare(payload: bool, fuzz_dir: Path | None = None) -> Path:
    RUNTIME.mkdir(parents=True, exist_ok=True)
    # Arch's nginx defaults to root-owned /var/lib/nginx temp directories.
    # The generated config explicitly points to these private writable paths.
    for name in NGINX_TEMP_SUBDIRS:
        (RUNTIME / "nginx-temp" / name).mkdir(parents=True, exist_ok=True)
    dst = RUNTIME / "nginx-b3.conf"
    src = ROOT / "conf/nginx-b3.conf.template"
    template = src.read_text().replace("@@ROOT@@", str(ROOT))
    marker = "        @@FUZZ_CERT@@"
    if template.count(marker) != 1:
        raise ValueError("nginx B3 template missing unique fuzz credential slot")
    dst.write_text(template.replace(marker, fuzz_cert_lines(fuzz_dir)))
    if payload:
        path = RUNTIME / "b3-512m.bin"
        if not path.exists() or path.stat().st_size != 536870912:
            with path.open("wb") as out:
                for _ in range(536870912 // len(PATTERN)):
                    out.write(PATTERN)
    return dst


def main():
    p = argparse.ArgumentParser()
    p.add_argument("command", choices=["prepare", "check", "run"])
    p.add_argument("--payload", action="store_true", help="create 512MiB file for E4 reference")
    p.add_argument("--fuzz-cert-dir", type=Path,
                   help="E1-only directory with generated rsa.crt and rsa.key")
    args = p.parse_args()
    conf = prepare(args.payload, args.fuzz_cert_dir)
    if args.command != "prepare":
        cmd = ["nginx", "-p", str(ROOT) + "/", "-c", str(conf)]
        if args.command == "check":
            cmd += ["-t"]
        else:
            cmd += ["-g", "daemon off;"]
        return subprocess.call(cmd, cwd=ROOT)
    print(conf)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
