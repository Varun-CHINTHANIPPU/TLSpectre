#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
[[ -f pki/out/index.txt && -f pki/out/ocsp.key ]] || {
  echo "Run make pki first" >&2
  exit 2
}
# Loopback by default; the only non-loopback option is the isolated lab's
# dedicated OCSP address, validated again by ocsp_static.
BIND="${TLSLAB_OCSP_BIND:-127.0.0.1}"
[[ "$BIND" == "127.0.0.1" || "$BIND" == "10.77.2.2" ]] || {
  echo "Refusing to expose private lab OCSP responder on $BIND" >&2
  exit 2
}
export PYTHONPATH="$PWD/harness${PYTHONPATH:+:$PYTHONPATH}"
exec "${TLSLAB_PYTHON:-python3}" -m tlslab.ocsp_static \
  --dir pki/out --freshness fresh --bind "$BIND" --port 8888
