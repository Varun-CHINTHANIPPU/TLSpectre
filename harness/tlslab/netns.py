"""Isolated three-namespace Linux lab with a dedicated OCSP namespace.

No implicit sudo. Must run as root, and only namespaces/veth interfaces with
the tlslab- prefix are touched; cleanup runs even if experiments raise.
"""
from contextlib import contextmanager
import os
import subprocess

NAMES = ("tlslab-cli", "tlslab-srv", "tlslab-ocsp")


def call(*args):
    subprocess.run(args, check=True)


def create():
    if os.geteuid() != 0:
        raise PermissionError("netns setup requires root; rerun explicitly with sudo")
    # Fail before creating or deleting anything if a lab namespace exists.
    # Otherwise a collision could cause cleanup to delete another user's namespace.
    already = subprocess.run(["ip", "netns", "list"], capture_output=True, text=True, check=True)
    existing = {line.split()[0] for line in already.stdout.splitlines() if line.strip()}
    conflicts = existing.intersection(NAMES)
    if conflicts:
        raise RuntimeError("Refusing to alter pre-existing namespaces: " + ",".join(sorted(conflicts)))
    for interface in ("tlslab-vcs","tlslab-vsc","tlslab-vso","tlslab-vos"):
        check = subprocess.run(["ip", "link", "show", interface],
                               capture_output=True, text=True)
        if check.returncode == 0:
            raise RuntimeError("Refusing to replace existing interface " + interface)
    try:
        for name in NAMES:
            call("ip", "netns", "add", name)
            call("ip", "-n", name, "link", "set", "lo", "up")
        call("ip", "link", "add", "tlslab-vcs", "type", "veth", "peer", "name", "tlslab-vsc")
        call("ip", "link", "add", "tlslab-vso", "type", "veth", "peer", "name", "tlslab-vos")
        for interface, name in (
            ("tlslab-vcs", "tlslab-cli"), ("tlslab-vsc", "tlslab-srv"),
            ("tlslab-vso", "tlslab-ocsp"), ("tlslab-vso", "tlslab-ocsp")
        ):
            if interface == "tlslab-vso":
                continue
            call("ip", "link", "set", interface, "netns", name)
        call("ip", "link", "set", "tlslab-vso", "netns", "tlslab-srv")
        call("ip", "link", "set", "tlslab-vos", "netns", "tlslab-ocsp")
        for name, interface, address in (
            ("tlslab-cli", "tlslab-vcs", "10.77.1.2/24"),
            ("tlslab-srv", "tlslab-vsc", "10.77.1.1/24"),
            ("tlslab-srv", "tlslab-vso", "10.77.2.1/24"),
            ("tlslab-ocsp", "tlslab-vos", "10.77.2.2/24"),
        ):
            call("ip", "-n", name, "addr", "add", address, "dev", interface)
            call("ip", "-n", name, "link", "set", interface, "up")
    except BaseException:
        destroy()
        raise


def destroy():
    if os.geteuid() != 0:
        raise PermissionError("netns teardown requires root")
    # A failed create() can leave one end of a veth on the host, and a named
    # namespace can outlive its name while processes keep its network open.
    # Delete known lab interfaces before removing namespace names.
    for ns, interface in (
        ("tlslab-cli", "tlslab-vcs"),
        ("tlslab-srv", "tlslab-vsc"),
        ("tlslab-srv", "tlslab-vso"),
        ("tlslab-ocsp", "tlslab-vos"),
    ):
        subprocess.run(["ip", "-n", ns, "link", "del", interface],
                       capture_output=True, check=False)
    for name in NAMES:
        subprocess.run(["ip", "netns", "del", name], capture_output=True, check=False)
    # Partial setup may have failed before moving the interfaces into a netns.
    for interface in ("tlslab-vcs", "tlslab-vsc", "tlslab-vso", "tlslab-vos"):
        subprocess.run(["ip", "link", "del", interface],
                       capture_output=True, check=False)


def delay(rtt_ms: int, *, ocsp: bool = False):
    if rtt_ms not in (0, 50):
        raise ValueError("Only 0 and 50ms RTT were frozen in the design")
    interfaces = (("tlslab-srv", "tlslab-vso"), ("tlslab-ocsp", "tlslab-vos")) if ocsp else (
        ("tlslab-cli", "tlslab-vcs"), ("tlslab-srv", "tlslab-vsc"))
    for name, iface in interfaces:
        cmd = ["ip", "netns", "exec", name, "tc", "qdisc", "replace",
               "dev", iface, "root", "netem", "delay", f"{rtt_ms / 2:.1f}ms"]
        call(*cmd)


def exec_in(namespace: str, argv: list[str]) -> list[str]:
    if namespace not in NAMES:
        raise ValueError("invalid namespace")
    return ["ip", "netns", "exec", namespace, *argv]


@contextmanager
def isolated_network():
    create()
    try:
        yield
    finally:
        destroy()


def client_ocsp_access(enabled: bool):
    """Toggle ONLY the laboratory client's path to OCSP, preserve server access.

    Forwarding is a per-network-namespace sysctl. The ephemeral namespaces and
    routes are destroyed by isolated_network() on exit.
    """
    if os.geteuid() != 0:
        raise PermissionError("route control requires root")
    call("ip", "netns", "exec", "tlslab-srv", "sysctl", "-w", "net.ipv4.ip_forward=1")
    for name, network in (("tlslab-cli","10.77.2.2/32"),
                          ("tlslab-ocsp","10.77.1.2/32")):
        subprocess.run(["ip", "-n", name, "route", "del", network],
                       check=False, capture_output=True)
    if enabled:
        call("ip", "-n", "tlslab-cli", "route", "add", "10.77.2.2/32",
             "via", "10.77.1.1")
        call("ip", "-n", "tlslab-ocsp", "route", "add", "10.77.1.2/32",
             "via", "10.77.2.1")
