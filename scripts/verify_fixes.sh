#!/usr/bin/env bash
# One-shot check of the E1-E7 validation fixes on this machine (~15-25 min).
#
#   export KS_PASS='your-lab-password'
#   bash scripts/verify_fixes.sh
#
# Needs: JDK 27 on PATH, the project venv active, sudo (netns, capture, CPU
# tuning), make pki already done. Every experiment's output directory is
# listed in data/verify/<time>/runs.jsonl and checked by tlslab.check_fixes.
set -uo pipefail
cd "$(dirname "$0")/.."

: "${KS_PASS:?export KS_PASS first}"
PY="$(command -v python)"
SUDO_PY=(sudo -E env "PATH=$PATH" "PYTHONPATH=$PWD/harness" "$PY")
OUT="data/verify/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$OUT"
RUNS="$OUT/runs.jsonl"
: > "$RUNS"

step() { printf '\n========== %s ==========\n' "$*"; }

# run LABEL [sudo] ARGS... -> append {"label","out"} using the runner's JSON line
run() {
  local label=$1; shift
  local cmd=(env "PYTHONPATH=$PWD/harness" "$PY")
  if [[ $1 == sudo ]]; then cmd=("${SUDO_PY[@]}"); shift; fi
  step "$label: $*"
  local log="$OUT/$label.log"
  "${cmd[@]}" -m tlslab.run_experiment "$@" --run 2>&1 | tee "$log" | grep -v \
    -e '^Using configuration' -e '^Check that' -e '^Signature ok' -e '^The Subject' \
    -e '^commonName' -e '^Certificate is to be' -e '^Write out' -e '^Database updated' \
    -e '^Revoking' -e '^-----$' -e '^net.ipv4' -e '^$'
  local out
  out=$("$PY" -c 'import json,sys
for line in reversed(open(sys.argv[1]).read().splitlines()):
    if line.startswith("{") and "\"out\"" in line:
        print(json.loads(line)["out"]); break' "$log")
  "$PY" -c 'import json,sys
err = [l for l in open(sys.argv[3]).read().splitlines() if l.strip()][-1:] if not sys.argv[2] else []
print(json.dumps({"label":sys.argv[1],"out":sys.argv[2] or None,"error":" ".join(err)[:400]}))' \
    "$label" "$out" "$log" >> "$RUNS"
}

step "build"
java -version 2>&1 | head -1
make test || exit 1
# Clean builds prevent the shade plugin from re-shading existing fat JARs.
mvn -f java/pom.xml -B -ntp clean package && \
  mvn -f java/bench/pom.xml -B -ntp clean package && \
  make tools && make e2-agent || exit 1

step "lab ports"
"$PY" - <<'PY' || exit 1
import socket
busy = [p for p in (8080, 8081, 8443, 8444, 8888, 9443)
        if socket.socket().connect_ex(("127.0.0.1", p)) == 0]
raise SystemExit(f"stop services on {busy} first" if busy else 0)
PY
sudo -v || exit 1

run E1          E1 --pilot
run E2          sudo E2                                    # full 24-cell matrix
run E3          sudo E3 --pilot --tune-cpu                 # checks CPU tuning path
run E4          E4 --pilot
run E5-SunJSSE  sudo E5 --pilot --isolated
run E5-BCJSSE   sudo E5 --pilot --bc-pilot --isolated
run E6          sudo E6 --isolated --blocks 1              # all 24 scenarios once
run E7          sudo E7 --pilot --isolated

sudo chown -R "$(id -u):$(id -g)" data
step "CHECK"
PYTHONPATH=harness "$PY" -m tlslab.check_fixes "$RUNS"
