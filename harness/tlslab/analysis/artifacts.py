"""Publication-gated figures F1-F6 and tables T1-T7.

Input must be a *complete* validated experimental dataset with declared
factor coverage; no pilot or partial observation can generate research figures.
Reports explain which evidence is missing rather than substituting fake values.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import re

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from .stats import summarize_grouped
from ..evidence import ROOT
from ..experiment_matrix import plan

EXPECTED = {"E1":528,"E2":24,"E3":360,"E4":240,
            "E5":160,"E6":600,"E7":180}
FIGURE_SOURCE = {"F1":"E1","F2":"E3","F3":"E4","F4":"E5",
                 "F5":"E5","F6":"E7"}
TABLE_SOURCE = {"T1":"ENV","T2":"CONFIG","T3":"E1",
                "T4":"E2","T5":"E3+E4","T6":"E5","T7":"E6"}


class InsufficientEvidence(ValueError):
    pass


def _output(root: Path, kind: str, name: str, extension: str):
    folder = root / "results" / kind
    folder.mkdir(parents=True, exist_ok=True)
    return folder / (name + extension)


def _measured(experiment: str, root: Path) -> pd.DataFrame:
    if experiment == "E7":
        # The primary E7 runner intentionally retains PARTIAL until an
        # independently measured full B3 reference is available. A paired
        # factor-matrix evidence audit (NOT paired statistical inference)
        # must pass before F6 can use the original 180 measured observations.
        from .audit_e7_reference import (
            ReferenceEvidenceError, audit, find_unique, _load)
        try:
            main = find_unique(root, reference=False)
            reference = find_unique(root, reference=True)
            audit(main, reference)
            return _load(main, reference=False)[1]
        except ReferenceEvidenceError as exc:
            raise InsufficientEvidence("E7 independent reference validation missing: " +
                                       str(exc)) from exc
    folder = root / "data" / "raw" / experiment
    files = sorted(folder.glob("*/results.parquet"))
    if not files:
        raise InsufficientEvidence(f"{experiment}: no results.parquet files")
    frames = []
    for path in files:
        manifest = path.parent / "manifest.json"
        if not manifest.is_file():
            raise InsufficientEvidence(f"{path}: manifest missing")
        info = json.loads(manifest.read_text())
        if info.get("experiment") != experiment:
            raise InsufficientEvidence(f"{path}: experiment mismatch")
        if info.get("metadata", {}).get("pilot"):
            continue
        if experiment == "E1":
            # Legacy full campaigns and targeted reruns remain append-only.
            # Only a SINGLE fresh 528-cell, non-pilot COMPLETE campaign is
            # publication-qualified. Neither partial nor scoped data may be
            # silently concatenated to fabricate one full campaign.
            if info.get("disposition") != "COMPLETE":
                continue
            data = pd.read_parquet(path)
            if len(data) != EXPECTED["E1"]:
                continue
        else:
            if info.get("disposition") != "COMPLETE":
                raise InsufficientEvidence(f"{path}: manifest not COMPLETE")
            data = pd.read_parquet(path)
        if "validated" not in data.columns or not data["validated"].eq(True).all():
            raise InsufficientEvidence(f"{path}: unvalidated observations")
        frames.append(data)
    if not frames:
        raise InsufficientEvidence(f"{experiment}: no non-pilot, validated complete results")
    if experiment == "E1" and len(frames) != 1:
        raise InsufficientEvidence(
            "E1 requires exactly one independent, full, COMPLETE 528-cell "
            "campaign; targeted reruns cannot be merged for publication")
    result = pd.concat(frames, ignore_index=True)
    if experiment == "E1":
        expected_keys = {(c["configuration"], c["repetition"], f"PR{n:02d}")
                         for c in plan("E1") for n in range(1, 23)}
        observed = list(zip(result["configuration"], result["repetition"],
                            result["probe_id"]))
        if len(set(observed)) != 528 or set(observed) != expected_keys:
            raise InsufficientEvidence("E1 coverage has duplicate/missing probe-factor keys")
    if len(result) != EXPECTED[experiment]:
        raise InsufficientEvidence(
            f"{experiment}: expected {EXPECTED[experiment]} independent condition rows; found {len(result)}")
    if experiment != "E6" and "status" in result and not result["status"].isin(("MEASURED","PASS")).all():
        raise InsufficientEvidence(f"{experiment}: non-measured result status")
    if "outcome" in result and not result["outcome"].isin(("PASS","FAIL","N/A","ACCEPT","REJECT")).all():
        raise InsufficientEvidence(f"{experiment}: unresolved test outcomes")
    return result


def load_data(experiment: str, *, root: Path = ROOT):
    return _measured(experiment, root)


def _required(df: pd.DataFrame, names: list[str], label: str):
    missing = set(names) - set(df.columns)
    if missing:
        raise InsufficientEvidence(f"{label}: missing columns {sorted(missing)}")
    if df[names].isnull().any().any():
        raise InsufficientEvidence(f"{label}: required metrics include missing values")


def _plot_category(ax, series, title, ylabel):
    ax.bar(np.arange(len(series)), series.to_numpy())
    ax.set_xticks(np.arange(len(series)))
    ax.set_xticklabels([str(x) for x in series.index], rotation=35, ha="right")
    ax.set_ylabel(ylabel)
    ax.set_title(title)


def artifact_figure(name: str, *, root: Path = ROOT) -> Path:
    if name not in FIGURE_SOURCE:
        raise KeyError(name)
    exp = FIGURE_SOURCE[name]
    df = _measured(exp, root)
    if name == "F1":
        _required(df, ["configuration","probe_id","outcome","repetition"],name)
        order = ["P1","P2","B1","B2","B3","A1","A2","A3"]
        probes = [f"PR{i:02d}" for i in range(1,23)]
        scores = df.copy()
        # N/A is a third categorical state, not insecure and not a zero.
        scores["plot_value"] = np.where(scores["outcome"]=="N/A",0.5,scores["secure_outcome"])
        mean = scores.pivot_table(index="configuration",columns="probe_id",
                                  values="plot_value",aggfunc="mean").reindex(index=order,columns=probes)
        if mean.isnull().any().any():
            raise InsufficientEvidence("F1 missing probe outcomes")
        fig, ax = plt.subplots(figsize=(14,5))
        plot = ax.imshow(mean.to_numpy(), aspect="auto", cmap="RdYlGn", vmin=0, vmax=1)
        ax.set_xticks(range(len(probes)),labels=probes,rotation=90)
        ax.set_yticks(range(len(order)),labels=order)
        ax.set_title("F1. TLS configuration security-probe outcome matrix")
        fig.colorbar(plot,ax=ax,label="0 insecure; 0.5 N/A; 1 secure")
    elif name == "F2":
        _required(df, ["platform","suite","size","mib_per_second"],name)
        fig, axes = plt.subplots(1,4,figsize=(16,4),sharey=True)
        for ax, platform in zip(axes,("SunJCE","A4","A5","BC")):
            selection=df[df["platform"]==platform]
            if selection.empty:
                raise InsufficientEvidence("F2 missing provider "+platform)
            for suite, sub in selection.groupby("suite"):
                med = sub.groupby("size")["mib_per_second"].median().sort_index()
                ax.plot(med.index.to_numpy(),med.to_numpy(),marker="o",label=suite)
            ax.set_xscale("log",base=2)
            ax.set_title(platform)
            ax.set_xlabel("Payload size (bytes)")
        axes[0].set_ylabel("MiB/s")
        axes[-1].legend(fontsize=7)
        fig.suptitle("F2. AEAD primitive throughput by size and provider")
    elif name == "F3":
        _required(df, ["condition","suite","mib_per_second","server_cpu_ns_per_byte"],name)
        summary=df.pivot_table(index="suite",columns="condition",
                               values="mib_per_second",aggfunc="median")
        cpu=df.pivot_table(index="suite",columns="condition",
                           values="server_cpu_ns_per_byte",aggfunc="median")
        wanted=["P1","A4","A5","P2"]
        if set(wanted)-set(summary.columns):
            raise InsufficientEvidence("F3 missing some TLS stack/flags conditions")
        fig,(a,b)=plt.subplots(2,1,figsize=(12,8),sharex=True)
        x=np.arange(len(summary))
        for i,p in enumerate(wanted):
            dx=(i-1.5)*.18
            a.bar(x+dx,summary[p].to_numpy(),.18,label=p)
            b.bar(x+dx,cpu[p].to_numpy(),.18,label=p)
        a.set_ylabel("TLS goodput (MiB/s)")
        b.set_ylabel("Server process CPU (ns/B)")
        b.set_xticks(x,summary.index,rotation=20)
        a.legend(ncol=4)
        fig.suptitle("F3. TLS transfer performance by cipher suite")
    elif name == "F4":
        _required(df, ["provider","group","rtt_ms","handshake_ms"],name)
        fig,axes=plt.subplots(2,2,figsize=(12,8))
        for i,p in enumerate(("SunJSSE","BCJSSE")):
            for j,rtt in enumerate((0,50)):
                ax=axes[i,j]
                selection=df[(df["provider"]==p)&(df["rtt_ms"]==rtt)]
                for group,sub in selection.groupby("group"):
                    arr=np.sort(sub["handshake_ms"].to_numpy(dtype=float))
                    if (arr<=0).any():
                        raise InsufficientEvidence("F4 nonpositive handshake latency")
                    ax.step(arr,np.arange(1,len(arr)+1)/len(arr),where="post",label=group)
                if not selection["group"].nunique()==4:
                    raise InsufficientEvidence("F4 missing groups")
                ax.set_xscale("log")
                ax.set_title(f"{p} / {rtt} ms RTT")
                ax.set_xlabel("Handshake latency (ms)")
                ax.set_ylabel("ECDF")
                ax.legend(fontsize=7)
        fig.suptitle("F4. Block-level handshake latency distributions")
    elif name == "F5":
        names=["group","client_hello_bytes","server_hello_bytes",
               "encrypted_server_bytes","client_flight_bytes","server_flight_records"]
        _required(df,names,name)
        summary=df.groupby("group")[names[1:]].median().sort_index()
        fig,ax=plt.subplots(figsize=(11,5))
        x=np.arange(len(summary))
        bottom=np.zeros(len(summary))
        for col in names[1:5]:
            data=summary[col].to_numpy()
            ax.bar(x,data,bottom=bottom,label=col)
            bottom+=data
        ax.set_xticks(x,summary.index,rotation=20)
        ax.set_ylabel("Captured bytes per flight")
        ax.legend(fontsize=7)
        ax.set_title("F5. Handshake bytes on the wire (capture required)")
    elif name == "F6":
        _required(df, ["stapling","rtt_ms","handshake_ms"],name)
        fig,axes=plt.subplots(1,2,figsize=(11,5),sharey=True)
        for ax,rtt in zip(axes,(0,50)):
            data=[df[(df["rtt_ms"]==rtt)&(df["stapling"]==s)]["handshake_ms"].to_numpy()
                  for s in ("off","warm","cold")]
            if any(len(a)==0 for a in data):
                raise InsufficientEvidence("F6 missing stapling mode")
            ax.boxplot(data,tick_labels=["off","warm","cold"])
            ax.set_xlabel("Stapling")
            ax.set_title(f"{rtt} ms responder RTT")
        axes[0].set_ylabel("Handshake latency (ms)")
        fig.suptitle("F6. OCSP stapling latency distributions")
    fig.tight_layout()
    result=_output(root,"figures",name,".pdf")
    fig.savefig(result)
    plt.close(fig)
    return result


def artifact_table(name: str, *, root: Path = ROOT) -> Path:
    if name not in TABLE_SOURCE:
        raise KeyError(name)
    if name=="T1":
        # A recorded environment inventory is not the same as an externally
        # audited environment lock. The old code required a
        # metadata.environment_validated flag that no runner ever sets, making
        # T1 impossible even with five full datasets. Report facts with an
        # explicit provenance/validation flag instead of inventing proof.
        manifest_files=sorted((root/"data"/"raw").glob("E*/*/manifest.json"))
        rows=[]
        for file in manifest_files:
            data=json.loads(file.read_text())
            experiment=data.get("experiment")
            metadata=data.get("metadata",{})
            if (experiment in ("E2","E3","E4","E5","E6")
                and data.get("disposition")=="COMPLETE"
                and not metadata.get("pilot")):
                rows.append({
                    "experiment":experiment,
                    "run_id":file.parent.name,
                    "git_sha":data.get("git_sha"),
                    "java":data.get("java"),
                    "openssl":data.get("openssl"),
                    "nginx":data.get("nginx"),
                    "tshark":data.get("tshark"),
                    "hardware":json.dumps(data.get("hardware",{}),sort_keys=True),
                    "environment_independently_validated":
                        bool(metadata.get("environment_validated",False)),
                    "source":"manifest inventory; independently verify hardware and versions",
                })
        if not rows:
            raise InsufficientEvidence("T1 needs at least one COMPLETE non-pilot E2–E6 environment manifest")
        output=pd.DataFrame(rows)
    elif name=="T2":
        # This is an inspectable DESIGN matrix; it has no security outcomes.
        import yaml
        profiles=("P1","P2","B1","B2","B3","A1","A2","A3","A4","A5","A6")
        rows=[]
        for n in profiles:
            if n=="B3":
                config={"provider":"nginx/OpenSSL","protocols":["TLSv1.3"],"namedGroups":[],"cipherSuites":[]}
            else:
                path=root/"configs/server"/(n+".yaml")
                if not path.is_file():
                    raise InsufficientEvidence("T2 missing configuration "+n)
                config=yaml.safe_load(path.read_text())
            # Values are explicitly inferred from configuration (not runtime
            # security evidence). Unknown controls must not appear as enabled.
            tls13_only = config.get("protocols")==["TLSv1.3"]
            no_hsts = not bool(config.get("hsts", False))
            is_hardened = n not in ("B1","B2","B3")
            baseline_note = "design inference; verify each HC independently"
            rows.append({
                "configuration":n,"stack":config.get("provider"),
                "protocols":",".join(config.get("protocols",[])),
                "suites":",".join(config.get("cipherSuites",[])),
                "groups":",".join(config.get("namedGroups",[])),
                "HC1_TLS13_only": tls13_only,
                "HC2_suite_allowlist":bool(config.get("cipherSuites")),
                "HC3_group_allowlist":bool(config.get("namedGroups")),
                "HC4_0RTT_disabled":"UNVERIFIED",
                "HC5_record_integrity":"PROTOCOL_AEAD",
                "HC6_stapling":config.get("ocspStapling","UNVERIFIED"),
                "HC7_must_staple":"UNVERIFIED",
                "HC8_HSTS":config.get("hsts","UNVERIFIED"),
                "HC9_redirect":config.get("httpRedirect","UNVERIFIED"),
                "HC10_certpath_limits":"CONFIG_POLICY" if is_hardened else "UNVERIFIED",
                "HC11_banner_suppression":"UNVERIFIED",
                "HC12_SNI_host_check":config.get("sniHostCheck","UNVERIFIED"),
                "jvm_intrinsics_flags":",".join(config.get("jvmFlags",[])),
                "evidence_note":baseline_note,
            })
        output=pd.DataFrame(rows)
    elif name=="T3":
        df=_measured("E1",root)
        _required(df,["configuration","probe_id","category","outcome"],name)
        # Keep N/A cells visible as categories, not silently dropped.
        output=(df.groupby(["configuration","probe_id","category","outcome"],
                           dropna=False).size().rename("n").reset_index())
    elif name=="T4":
        df=_measured("E2",root)
        _required(df,["provider","suite","group","verification_pass","n_verified"],name)
        output=summarize_grouped(df,["provider","suite","group"],"verification_pass")
    elif name=="T5":
        a=_measured("E3",root)
        b=_measured("E4",root)
        _required(a,["platform","suite","size","mib_per_second","cpu_ns_per_byte"],name)
        _required(b,["condition","suite","mib_per_second",
                     "client_cpu_ns_per_byte","server_cpu_ns_per_byte"],name)
        prim=summarize_grouped(a,["platform","suite","size"],"mib_per_second")
        prim.insert(0,"level","primitive")
        tls=summarize_grouped(b,["condition","suite"],"mib_per_second")
        tls.insert(0,"level","TLS")
        output=pd.concat([prim,tls],ignore_index=True)
    elif name=="T6":
        df=_measured("E5",root)
        _required(df,["provider","rtt_ms","group","handshake_ms",
                      "handshake_bytes","hrr_rate","server_cpu_ns"],name)
        output=summarize_grouped(df,["provider","rtt_ms","group"],"handshake_ms")
        for field in ("handshake_bytes","hrr_rate","server_cpu_ns"):
            summary=df.groupby(["provider","rtt_ms","group"])[field].median()
            output[field]=[summary.get((r["provider"],r["rtt_ms"],r["group"]))
                           for _,r in output.iterrows()]
    elif name=="T7":
        df=_measured("E6",root)
        _required(df,["status","stapling","must_staple","responder_reachable",
                      "freshness","policy","accept","staple_observed"],name)
        wide=df.pivot_table(index=["status","stapling","must_staple",
                                   "responder_reachable","freshness"],
                            columns="policy",values="accept",aggfunc="mean")
        if wide.shape!=(24,5):
            raise InsufficientEvidence(f"T7 expected 24 scenarios x 5 policies; found {wide.shape}")
        output=wide.reset_index()
    else:
        raise KeyError(name)
    if output.empty:
        raise InsufficientEvidence(f"{name}: no complete report records")
    result=_output(root,"tables",name,".csv")
    output.to_csv(result,index=False)
    return result


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--figures",action="store_true")
    p.add_argument("--tables",action="store_true")
    p.add_argument("--strict",action="store_true")
    p.add_argument("--root",type=Path,default=ROOT)
    args=p.parse_args()
    if not args.figures and not args.tables:
        p.error("choose --figures and/or --tables")
    created=[]
    blocked={}
    for entries,enabled,fn in (
        (FIGURE_SOURCE,args.figures,artifact_figure),
        (TABLE_SOURCE,args.tables,artifact_table)
    ):
        if not enabled:
            continue
        for name in entries:
            try:
                created.append(str(fn(name,root=args.root)))
            except (InsufficientEvidence,FileNotFoundError,KeyError,ValueError) as exc:
                blocked[name]=str(exc)
    print(json.dumps({"created":created,"blocked":blocked},indent=2))
    return 2 if args.strict and blocked else 0


if __name__=="__main__":
    raise SystemExit(main())
