"""Frozen E1-E7 factor plans, with no claims of observed outcomes."""
from __future__ import annotations
from dataclasses import dataclass
from itertools import product
import random

SUITES = (
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
)
GROUPS = ("x25519", "secp256r1", "X25519MLKEM768", "SecP256r1MLKEM768")
E1_CONFIGS = ("P1", "P2", "B1", "B2", "B3", "A1", "A2", "A3")
E4_STACKS = ("P1", "A4", "A5", "P2")
E7_STAPLING = ("off", "warm", "cold")


def e1_conditions():
    return [{"configuration": c, "repetition": i} for c in E1_CONFIGS for i in range(1, 4)]


def e2_conditions():
    return [{"provider": p, "suite": s, "group": g}
            for p, s, g in product(("SunJSSE", "BCJSSE"), SUITES, GROUPS)]


def e3_conditions():
    for s, size, platform in product(SUITES, (64, 1024, 16384),
                                      ("SunJCE", "A4", "A5", "BC")):
        yield {"suite": s, "size": size, "platform": platform}


def e4_conditions():
    return [{"configuration": c, "suite": s} for c, s in product(E4_STACKS, SUITES)]


def e5_conditions():
    groups = ("x25519", "X25519MLKEM768",
              "SecP256r1MLKEM768", "SecP384r1MLKEM1024")
    return [{"provider": p, "group": g, "rtt_ms": rtt}
            for p, g, rtt in product(("SunJSSE", "BCJSSE"), groups, (0, 50))]


def e6_conditions():
    """24 valid scenarios: off=>freshness N/A; on=>fresh/expired."""
    result = []
    for status, must_staple, reachable in product(
            ("good", "revoked"), (False, True), (False, True)):
        for stapling, freshness in (("off", "none"), ("on", "fresh"), ("on", "expired")):
            result.append(dict(status=status, must_staple=must_staple,
                               responder_reachable=reachable,
                               stapling=stapling, freshness=freshness))
    assert len(result) == 24
    return result


def e7_conditions():
    return [{"stapling": a, "rtt_ms": rtt}
            for a, rtt in product(E7_STAPLING, (0, 50))]


def block_order(conditions, block_id: int):
    if block_id < 0:
        raise ValueError("block must be nonnegative")
    result = list(conditions)
    random.Random(block_id).shuffle(result)
    return result


def plan(name: str, blocks: int | None = None):
    fn = {
        "E1": e1_conditions, "E2": e2_conditions, "E3": e3_conditions,
        "E4": e4_conditions, "E5": e5_conditions,
        "E6": e6_conditions, "E7": e7_conditions,
    }.get(name)
    if fn is None:
        raise ValueError(f"unknown experiment {name}")
    conditions = list(fn())
    if name == "E1":
        return [{"experiment": name, **c} for c in conditions]
    if name == "E2":
        return [{"experiment": name, **c} for c in conditions]
    defaults = {"E3": 10, "E4": 20, "E5": 10, "E6": 5, "E7": 30}
    count = defaults[name] if blocks is None else blocks
    if not 1 <= count <= 1000:
        raise ValueError("blocks outside supported range")
    return [{"experiment": name, "block": i, "position": n, **c}
            for i in range(1, count + 1)
            for n, c in enumerate(block_order(conditions, i))]
