"""Portable benchmark controls: optional P-core pinning and reversible host tuning.

Host governor/turbo changes are NEVER automatic; opt in with --tune-cpu. Any
state modified by this module is restored in a finally block.
"""
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
import json
import os
import re
import subprocess
import time

CPU_ROOT = Path("/sys/devices/system/cpu")
NO_TURBO = Path("/sys/devices/system/cpu/intel_pstate/no_turbo")


PCORE_PMU = Path("/sys/devices/cpu_core/cpus")


def parse_cpu_list(text: str) -> set[int]:
    cpus: set[int] = set()
    for part in text.strip().split(","):
        if not part:
            continue
        low, _, high = part.partition("-")
        cpus.update(range(int(low), int(high or low) + 1))
    return cpus


def performance_cpus() -> set[int] | None:
    """Logical CPUs that are Intel P-cores, or None when the kernel does not say.

    Mainline Linux has no cpuN/topology/core_type file. On hybrid Intel parts
    (Alder/Raptor Lake, e.g. i7-1360P) the kernel publishes the P-core set as
    the cpu_core PMU's cpumask; cpu_atom holds the E-cores.
    """
    try:
        return parse_cpu_list(PCORE_PMU.read_text()) or None
    except (OSError, ValueError):
        return None


def physical_cores() -> dict[int, list[int]]:
    cores = {}
    hybrid = performance_cpus()
    for cpu in sorted(CPU_ROOT.glob("cpu[0-9]*"), key=lambda x: int(x.name[3:])):
        try:
            thread = int(cpu.name[3:])
            core = int((cpu / "topology/core_id").read_text())
            package = int((cpu / "topology/physical_package_id").read_text())
            if (cpu / "topology/core_type").exists():
                typ = int((cpu / "topology/core_type").read_text())
            else:
                typ = 2 if hybrid is not None and thread in hybrid else 0
        except (ValueError, OSError):
            continue
        cores.setdefault((package, core, typ), []).append(thread)
    # Type 2 is a performance core; do not infer from CPU ID.
    selected = {v[0]: sorted(v) for (package, core, typ), v in cores.items() if typ == 2}
    if len(selected) < 2:
        raise RuntimeError("Unable to identify at least two distinct P cores; do not guess CPU IDs")
    return selected


def thread_affinities(pid: int) -> dict[str, list[int]]:
    """Allowed CPUs of every thread of a process, read back from the kernel."""
    result = {}
    for task in Path(f"/proc/{pid}/task").glob("[0-9]*"):
        try:
            for line in (task / "status").read_text().splitlines():
                if line.startswith("Cpus_allowed_list:"):
                    result[task.name] = sorted(parse_cpu_list(line.split(":", 1)[1]))
        except OSError:
            continue  # thread exited while being inspected
    return result


def verify_affinity(pid: int, expected: list[int]) -> dict:
    """Evidence that a whole JVM (all threads) is confined to the expected CPUs.

    With no pinning requested this only records what the scheduler allowed.
    """
    threads = thread_affinities(pid)
    masks = sorted({tuple(v) for v in threads.values()})
    report = {"pid": pid, "threads": len(threads), "requested": sorted(expected),
              "distinct_masks": [list(m) for m in masks]}
    if expected:
        report["all_threads_confined"] = bool(threads) and all(
            set(v) <= set(expected) for v in threads.values())
        if not report["all_threads_confined"]:
            raise RuntimeError(f"server affinity not effective: {report}")
    return report


def recommended_affinity() -> dict[str, list[int]]:
    cores = list(physical_cores().values())
    return {"server": cores[0], "client": cores[1]}


def experiment_affinity() -> dict[str, list[int]]:
    """Default to portable OS scheduling; opt into verified P-core pinning.

    TLSLAB_PIN_CPU=1 is an explicit request for P-core affinity. When requested,
    unsupported hardware or topology raises an actionable error rather than
    silently pretending the process is pinned.
    """
    if os.environ.get("TLSLAB_PIN_CPU", "").strip().lower() not in ("1", "true", "yes"):
        return {"server": [], "client": []}
    try:
        return recommended_affinity()
    except RuntimeError as exc:
        raise RuntimeError(
            "TLSLAB_PIN_CPU requested, but verified Intel P-cores are unavailable; "
            "unset TLSLAB_PIN_CPU to use portable OS scheduling"
        ) from exc


def pinned(command: list[str], cores: list[int]) -> list[str]:
    if not cores or any(c < 0 for c in cores):
        raise ValueError("invalid CPU affinity")
    return ["taskset", "-c", ",".join(map(str, cores)), *command]


def cpu_manifest() -> dict:
    flags = {}
    for key, path in (
        ("intel_no_turbo", NO_TURBO),
        ("kernel_release", Path("/proc/sys/kernel/osrelease"))
    ):
        try:
            flags[key] = path.read_text().strip()
        except OSError:
            flags[key] = None
    for cpu in sorted(CPU_ROOT.glob("cpu[0-9]*"), key=lambda p: int(p.name[3:])):
        p = cpu / "cpufreq/scaling_governor"
        if p.exists():
            flags.setdefault("governors", {})[cpu.name] = p.read_text().strip()
    return flags


def performance_snapshot() -> dict:
    """Read-only approximate CPU frequency and thermal sensor observations.

    Sensors may not be present or comparable across machines. These are
    environment annotations, not automatically accepted thermal validation.
    """
    snapshot = {"cpu_controls": cpu_manifest(), "freq_mhz": {}, "thermal_c": {}}
    for cpu in sorted(CPU_ROOT.glob("cpu[0-9]*"), key=lambda p: int(p.name[3:])):
        current = cpu/"cpufreq/scaling_cur_freq"
        try:
            snapshot["freq_mhz"][cpu.name] = round(int(current.read_text().strip()) / 1000, 2)
        except (OSError, ValueError):
            continue
    for dev in sorted(Path("/sys/class/hwmon").glob("hwmon*")):
        try:
            kind = (dev/"name").read_text().strip()
        except OSError:
            continue
        for sensor in sorted(dev.glob("temp[0-9]*_input")):
            try:
                temp = float(sensor.read_text().strip()) / 1000
                if -40 <= temp <= 150:
                    snapshot["thermal_c"][f"{kind}:{sensor.name}"] = round(temp, 2)
            except (OSError, ValueError):
                continue
    return snapshot


@contextmanager
def managed_host_tuning(allow_host_changes: bool = False):
    """Only modify if explicitly enabled; write back EXACT prior states."""
    if not allow_host_changes:
        yield {"tuned": False, "pre": cpu_manifest()}
        return
    if os.geteuid() != 0:
        raise PermissionError("host CPU tuning requires root and explicit opt-in")
    targets = [NO_TURBO] if NO_TURBO.exists() else []
    targets += sorted(CPU_ROOT.glob("cpu[0-9]*/cpufreq/scaling_governor"))
    saved = []
    try:
        for path in targets:
            old = path.read_text().strip()
            new = "1" if path == NO_TURBO else "performance"
            saved.append((path, old))
            if old != new:
                path.write_text(new)
        post = cpu_manifest()
        if not controls_established(post):
            # Writes can be silently ignored (e.g. intel_pstate passive mode,
            # firmware turbo lock). Never record a "tuned" run that is not.
            raise RuntimeError("CPU tuning did not take effect: " + json.dumps(post)[:600])
        yield {"tuned": True, "pre": {str(k): v for k, v in saved},
               "post": post, "controls_established": True}
    finally:
        failures = []
        for path, old in reversed(saved):
            try:
                path.write_text(old)
            except OSError as exc:
                failures.append(f"{path}: {exc}")
        if failures:
            raise RuntimeError("CPU configuration restore failed: " + "; ".join(failures))


# ---------------------------------------------------------------------------
# Measurement-condition evidence shared by E3/E4/E5/E7.


def tuning_preflight() -> None:
    """Fail before an experiment starts if CPU tuning cannot possibly work."""
    if os.geteuid() != 0:
        raise PermissionError("--tune-cpu needs root (run through sudo)")
    missing = []
    if not NO_TURBO.exists():
        missing.append(str(NO_TURBO) + " (intel_pstate driver)")
    if not list(CPU_ROOT.glob("cpu[0-9]*/cpufreq/scaling_governor")):
        missing.append("cpu*/cpufreq/scaling_governor")
    if missing:
        raise RuntimeError("--tune-cpu unsupported on this host; missing " + ", ".join(missing))


def controls_established(controls: dict) -> bool:
    """Performance governor on every CPU and Intel turbo disabled."""
    governors = controls.get("governors") or {}
    return (bool(governors) and all(v == "performance" for v in governors.values())
            and controls.get("intel_no_turbo") == "1")


def java_feature_version(java: str = "java") -> int | None:
    """Feature release of the JVM that experiments will launch (27 for JDK 27)."""
    try:
        done = subprocess.run([java, "-version"], capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        return None
    match = re.search(r'version "(?:1\.)?(\d+)', done.stderr + done.stdout)
    return int(match.group(1)) if match else None


def require_jdk(minimum: int = 27, label: str = "experiment") -> int:
    found = java_feature_version()
    if found is None or found < minimum:
        raise RuntimeError(f"{label} requires JDK {minimum}+; 'java' on PATH reports {found}")
    return found


THROTTLE = ("core_throttle_count", "package_throttle_count")


def throttle_counters() -> dict[str, int]:
    """Kernel thermal-throttle event counters (Intel therm_throt).

    Each counter increments whenever the CPU crossed its thermal limit and was
    throttled. Unlike temperature snapshots, an unchanged counter is direct
    evidence that no throttling event occurred in between.
    """
    counters = {}
    for cpu in sorted(CPU_ROOT.glob("cpu[0-9]*"), key=lambda p: int(p.name[3:])):
        for name in THROTTLE:
            try:
                counters[f"{cpu.name}/{name}"] = int((cpu/"thermal_throttle"/name).read_text())
            except (OSError, ValueError):
                continue
    return counters


def package_temperature() -> float | None:
    """Hottest CPU package/die sensor in degrees C, or None without sensors."""
    readings = []
    for dev in Path("/sys/class/hwmon").glob("hwmon*"):
        try:
            kind = (dev/"name").read_text().strip()
        except OSError:
            continue
        if kind not in ("coretemp", "k10temp", "zenpower", "cpu_thermal"):
            continue
        for sensor in dev.glob("temp[0-9]*_input"):
            try:
                value = float(sensor.read_text()) / 1000
            except (OSError, ValueError):
                continue
            if -40 <= value <= 150:
                readings.append(value)
    for zone in Path("/sys/class/thermal").glob("thermal_zone*"):
        try:
            if (zone/"type").read_text().strip() == "x86_pkg_temp":
                readings.append(float((zone/"temp").read_text()) / 1000)
        except (OSError, ValueError):
            continue
    return max(readings) if readings else None


def thermal_limits() -> tuple[float, float]:
    return (float(os.environ.get("TLSLAB_THERMAL_MAX_C", "70")),
            float(os.environ.get("TLSLAB_THERMAL_WAIT_S", "300")))


def thermal_gate(max_c: float | None = None, wait_s: float | None = None) -> dict:
    """Wait (bounded) until the CPU package is at or below max_c before a cell."""
    default_max, default_wait = thermal_limits()
    max_c = default_max if max_c is None else max_c
    wait_s = default_wait if wait_s is None else wait_s
    started = time.monotonic()
    first = current = package_temperature()
    while current is not None and current > max_c and time.monotonic() - started < wait_s:
        time.sleep(2)
        current = package_temperature()
    return {"max_c": max_c, "temp_before_wait_c": first, "temp_c": current,
            "waited_s": round(time.monotonic() - started, 1),
            "ok": current is not None and current <= max_c}


class ThermalWindow:
    """Throttle counters and temperature around one measurement.

    ok is True only when the pre-measurement gate passed, throttle counters
    exist, and none of them changed during the measurement.
    """

    def __init__(self):
        self.gate = thermal_gate()
        self.before = throttle_counters()

    def close(self) -> dict:
        after = throttle_counters()
        common = set(self.before) & set(after)
        delta = sum(after[k] - self.before[k] for k in common) if common else None
        reasons = []
        if not self.gate["ok"]:
            reasons.append("cool-down gate not met or no CPU temperature sensor")
        if delta is None:
            reasons.append("thermal_throttle counters unavailable")
        elif delta:
            reasons.append(f"{delta} thermal throttle event(s) during measurement")
        return {"gate": self.gate, "temp_after_c": package_temperature(),
                "throttle_counters": len(common), "throttle_events": delta,
                "ok": not reasons, "reasons": reasons}
