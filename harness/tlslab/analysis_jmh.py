"""Turn raw JMH 1.37 results into an auditable E3 CSV without inventing confidence."""
import argparse
import csv
import json
from pathlib import Path


def summarize(results: list[dict]) -> list[dict]:
    output = []
    for item in results:
        metric = item["primaryMetric"]
        params = item["params"]
        output.append({
            "benchmark": item["benchmark"], "provider": params["provider"],
            "aead": params["aead"], "size": int(params["size"]),
            "score": metric["score"], "score_error": metric.get("scoreError"),
            "score_unit": metric["scoreUnit"],
            "forks": item.get("forks"), "jvm": item.get("jvm"),
            "jmh_version": item.get("jmhVersion"),
        })
    return output


def main():
    p = argparse.ArgumentParser()
    p.add_argument("jmh_json", type=Path)
    p.add_argument("--out", type=Path, required=True)
    args = p.parse_args()
    data = json.loads(args.jmh_json.read_text())
    rows = summarize(data)
    if not rows:
        raise SystemExit("No JMH results")
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    print(f"Wrote {len(rows)} JMH condition summaries; no statistical conclusions computed")


if __name__ == "__main__":
    main()
