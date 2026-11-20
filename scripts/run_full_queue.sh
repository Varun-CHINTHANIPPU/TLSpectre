#!/usr/bin/env bash
# Unattended full TLS campaign, starting only after the specified full E3 run
# has finished with all 360 rows validated. Run under a root tmux session.
set -Eeuo pipefail
cd "$(dirname "$0")/.."

if (( EUID != 0 )); then
  echo "Start this queue under sudo; E5-E7 require network namespaces." >&2
  exit 1
fi
if [[ ! -v KS_PASS || -z "$KS_PASS" ]]; then
  echo "KS_PASS must be exported before starting tmux (sudo -E)." >&2
  exit 1
fi

PY="$PWD/.venv/bin/python"
if [[ ! -x "$PY" ]]; then
  echo "Missing project virtualenv: $PY" >&2
  exit 1
fi
export PYTHONPATH="$PWD/harness"
E3_RUN="$PWD/data/raw/E3/20261118T010442Z_61e1f7580b51"
OUT="$PWD/data/full-logs/overnight_$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$OUT"
exec > >(tee -a "$OUT/queue.log") 2>&1

log() { printf '[%s] %s\n' "$(date -Is)" "$*"; }
log "Queue started; logs: $OUT"
log "Waiting for E3: $E3_RUN"

e3_complete() {
  "$PY" - "$E3_RUN" <<'PY'
import json
import sys
from pathlib import Path
run = Path(sys.argv[1])
if not (run / "results.parquet").is_file():
    raise SystemExit(1)
try:
    manifest = json.loads((run / "manifest.json").read_text())
except (OSError, ValueError):
    raise SystemExit(1)
details = manifest.get("details", {})
ok = (manifest.get("disposition") == "COMPLETE"
      and details.get("measured_forks") == 360
      and details.get("failures") == 0
      and details.get("validated") == 360)
raise SystemExit(0 if ok else 1)
PY
}

while ! e3_complete; do
  if ! pgrep -f '[t]lslab.run_experiment E3 --run --tune-cpu' >/dev/null; then
    log "HALTED: E3 process ended without COMPLETE and 360 validated measurements."
    log "Inspect the E3 manifest; remaining experiments were NOT started."
    exit 2
  fi
  sleep 60
done
log "E3 completed: 360 measured and validated. Auditing raw JMH provenance."
if ! "$PY" -m tlslab.analysis.audit_e3 "$E3_RUN" \
        --out "$OUT/E3_audit.json" > "$OUT/E3_audit.log" 2>&1; then
  log "HALTED: E3 structural audit failed; see $OUT/E3_audit.log"
  tail -n 25 "$OUT/E3_audit.log"
  exit 2
fi
log "E3 structural audit passed; beginning remaining full experiments."

run_stage() {
  local name="$1"
  shift
  local rc=0
  local logfile="$OUT/$name.log"
  log "START $name: $*"
  "$PY" -m tlslab.run_experiment "$name" --run "$@" > "$logfile" 2>&1 || rc=$?
  "$PY" - "$name" "$rc" "$logfile" "$OUT/summary.jsonl" <<'PY'
import json
import sys
from pathlib import Path

name, rc, logfile, summary = sys.argv[1], int(sys.argv[2]), Path(sys.argv[3]), Path(sys.argv[4])
out = None
for line in reversed(logfile.read_text(errors="replace").splitlines()):
    try:
        obj = json.loads(line)
    except ValueError:
        continue
    if isinstance(obj, dict) and obj.get("out"):
        out = obj["out"]
        break
disposition = "NO_OUTPUT"
if out:
    try:
        disposition = json.loads((Path(out) / "manifest.json").read_text()).get("disposition", "UNKNOWN")
    except (OSError, ValueError):
        disposition = "NO_MANIFEST"
item = {"experiment": name, "exit_code": rc, "disposition": disposition,
        "run": out, "log": str(logfile)}
with summary.open("a") as f:
    f.write(json.dumps(item) + "\n")
print("RESULT:", json.dumps(item), flush=True)
PY
  # Continue other experiments even if a stage produces PARTIAL/FAILED data:
  # preserve each outcome, never silently label it COMPLETE.
  sleep 10
}

run_stage E4 --tune-cpu
run_stage E6 --isolated
run_stage E5 --isolated --tune-cpu
run_stage E7 --isolated --tune-cpu

log "All queued attempts finished. Review $OUT/summary.jsonl and individual logs."
log "E7 remains PARTIAL by design until its missing B3 reference is implemented."
