"""Unified entrypoint for E1-E7; defaults to inspecting the plan, not executing."""
import argparse
import json
import sys
from pathlib import Path
from .experiment_matrix import plan


def run_summary(output: Path, *, pilot: bool) -> dict:
    """Report the completed manifest's disposition, not a hard-coded label.

    COMPLETE is scoped to what an experiment actually validated; for E2 it
    means capture/keylog-to-TLS-record and Finished verification, not proof of
    upstream classical or hybrid key agreement.
    """
    manifest = json.loads((output / "manifest.json").read_text())
    disposition = manifest["disposition"]
    if disposition not in ("COMPLETE", "PARTIAL", "FAILED"):
        raise ValueError("experiment did not finalize its manifest")
    result = {
        "out": str(output),
        "classification": "PILOT" if pilot else disposition,
        "manifest_disposition": disposition,
    }
    scope = manifest.get("details", {}).get("scope")
    if scope:
        result["verification_scope"] = scope
    return result


def main():
    p=argparse.ArgumentParser()
    p.add_argument("experiment", choices=[f"E{i}" for i in range(1,8)])
    p.add_argument("--run", action="store_true")
    p.add_argument("--pilot", action="store_true")
    p.add_argument("--bc-pilot", action="store_true", help="E5 only: test three BCJSSE hybrid groups")
    p.add_argument("--reference-b3", action="store_true",
                   help="E7 only: independent nginx/OpenSSL reference, kept outside main E7 matrix")
    p.add_argument("--probe-ids", help="E1 only: comma-separated PR identifiers")
    p.add_argument("--configurations", help="E1 only: comma-separated profile names (e.g. B3)")
    p.add_argument("--isolated", action="store_true")
    p.add_argument("--tune-cpu", action="store_true")
    p.add_argument("--blocks", type=int)
    args=p.parse_args()
    if args.probe_ids and args.experiment != "E1":
        p.error("--probe-ids is valid only for E1")
    if args.configurations and args.experiment != "E1":
        p.error("--configurations is valid only for E1")
    if args.reference_b3 and args.experiment != "E7":
        p.error("--reference-b3 only applies to E7")
    if args.bc_pilot and (args.experiment != "E5" or not args.pilot):
        p.error("--bc-pilot is only valid for E5 --run --pilot")
    if not args.run:
        rows=plan(args.experiment, blocks=args.blocks)
        print(json.dumps({"experiment":args.experiment,"cells":len(rows),
                          "plan":rows if len(rows)<=24 else rows[:5],
                          "truncated":len(rows)>24},indent=2))
        return 0
    if args.experiment=="E1":
        from .run_e1 import execute
        output=execute(pilot=args.pilot, probe_ids=args.probe_ids,
                       configurations=args.configurations)
    elif args.experiment=="E2":
        from .run_e2 import execute
        output=execute(pilot=args.pilot)
    elif args.experiment=="E3":
        from .run_e3 import execute
        output=execute(pilot=args.pilot,tune_cpu=args.tune_cpu)
    elif args.experiment=="E4":
        from .run_e4 import execute
        output=execute(pilot=args.pilot,blocks=args.blocks,tune_cpu=args.tune_cpu)
    elif args.experiment=="E5":
        from .run_e5 import execute
        output=execute(pilot=args.pilot,isolated=args.isolated,tune_cpu=args.tune_cpu,
                       bc_pilot=args.bc_pilot)
    elif args.experiment=="E6":
        from .run_e6 import execute
        output=execute(pilot=args.pilot,isolated=args.isolated,blocks=args.blocks)
    elif args.experiment=="E7":
        if args.reference_b3:
            from .run_e7_reference import execute
        else:
            from .run_e7 import execute
        output=execute(pilot=args.pilot,isolated=args.isolated,
                       allow_host_tuning=args.tune_cpu)
    print(json.dumps(run_summary(Path(output), pilot=args.pilot)))
    if args.experiment == "E3":
        details = json.loads((Path(output) / "manifest.json").read_text()).get("details", {})
        if details.get("failures", 0):
            print(f"E3: {details['failures']} JMH cell(s) failed. "
                  f"Inspect {Path(output) / 'results.parquet'} and {Path(output) / 'logs'}.",
                  file=sys.stderr)
            return 2
    return 0


if __name__=="__main__":
    raise SystemExit(main())
