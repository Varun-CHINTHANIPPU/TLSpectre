"""TLS 1.3 negative probes built on the tlsfuzzer library (not its stock scripts).

The stock tlsfuzzer scripts for named groups and compression cannot be scored
against this lab's servers: the named-group script requires the exact
HelloRetryRequest/ChangeCipherSpec sequence and alert of its reference server,
and the compression script only speaks TLS 1.2. These two probes ask the
narrower questions PR08 and PR22 are actually about:

* groups       - which named groups does the endpoint accept when the client
                 offers exactly one group and a matching key share?
* compression  - does a TLS 1.3 ClientHello whose legacy_compression_methods is
                 not exactly [null] get refused (RFC 8446 section 4.1.2)?

Run as a subprocess with third_party/tlsfuzzer on PYTHONPATH; prints one JSON
object. Local lab targets only.
"""
import argparse
import contextlib
import io
import json
import sys

LOCAL = ("127.0.0.1", "localhost", "10.77.1.1")
GROUP_CANDIDATES = (
    "x25519", "secp256r1", "secp384r1", "secp521r1", "x448",
    "ffdhe2048", "ffdhe3072",
    "x25519mlkem768", "secp256r1mlkem768", "secp384r1mlkem1024",
)
SUITES = {"TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384",
          "TLS_CHACHA20_POLY1305_SHA256"}


def _hello(host, port, suite, group, compression=None):
    from tlsfuzzer.messages import Connect, ClientHelloGenerator
    from tlsfuzzer.helpers import key_share_gen, SIG_ALL
    from tlslite.constants import (CipherSuite, ExtensionType, GroupName,
                                   SignatureScheme)
    from tlslite.extensions import (ClientKeyShareExtension,
                                    SignatureAlgorithmsCertExtension,
                                    SignatureAlgorithmsExtension,
                                    SupportedGroupsExtension,
                                    SupportedVersionsExtension)
    number = getattr(GroupName, group)
    ext = {
        ExtensionType.supported_versions:
            SupportedVersionsExtension().create([(3, 4)]),
        ExtensionType.supported_groups:
            SupportedGroupsExtension().create([number]),
        ExtensionType.key_share:
            ClientKeyShareExtension().create([key_share_gen(number)]),
        ExtensionType.signature_algorithms:
            SignatureAlgorithmsExtension().create([
                SignatureScheme.ecdsa_secp256r1_sha256,
                SignatureScheme.rsa_pss_rsae_sha256,
                SignatureScheme.rsa_pss_pss_sha256]),
        ExtensionType.signature_algorithms_cert:
            SignatureAlgorithmsCertExtension().create(SIG_ALL),
    }
    conversation = Connect(host, port)
    kwargs = {} if compression is None else {"compression": compression}
    node = conversation.add_child(ClientHelloGenerator(
        [getattr(CipherSuite, suite)], extensions=ext, **kwargs))
    return conversation, node


def _run(conversation):
    from tlsfuzzer.runner import Runner
    sink = io.StringIO()
    try:
        with contextlib.redirect_stdout(sink):
            Runner(conversation).run()
        return None
    except Exception as exc:  # tlsfuzzer signals every mismatch by exception
        return f"{type(exc).__name__}: {str(exc)[:200]}"


def first_response(host, port, suite, group, compression=None):
    """accepted | alert:<description> | closed | error:<text> for one ClientHello."""
    from tlsfuzzer.expect import ExpectAlert, ExpectClose, ExpectServerHello
    from tlslite.constants import AlertDescription, AlertLevel

    try:
        conversation, node = _hello(host, port, suite, group, compression)
    except Exception as exc:
        return f"untestable:{type(exc).__name__}: {str(exc)[:120]}"
    node.add_child(ExpectServerHello())
    if _run(conversation) is None:
        return "accepted"

    seen = {}

    class RecordingAlert(ExpectAlert):
        def process(self, state, msg):
            # msg.write() is level byte, description byte
            data = bytes(msg.write())
            if len(data) >= 2:
                seen["level"], seen["description"] = data[0], data[1]
            return super().process(state, msg)

    conversation, node = _hello(host, port, suite, group, compression)
    node.add_child(RecordingAlert(AlertLevel.fatal))
    if _run(conversation) is None:
        return "alert:" + AlertDescription.toStr(seen.get("description"))
    if "description" in seen:
        return "alert:" + AlertDescription.toStr(seen["description"]) + "(non-fatal)"

    conversation, node = _hello(host, port, suite, group, compression)
    node.add_child(ExpectClose())
    why = _run(conversation)
    return "closed" if why is None else "error:" + why


def probe_groups(host, port, suite):
    observed = {g: first_response(host, port, suite, g) for g in GROUP_CANDIDATES}
    return {"probe": "groups", "suite": suite, "observed": observed,
            "accepted": sorted(g for g, v in observed.items() if v == "accepted")}


def probe_compression(host, port, suite, group):
    baseline = first_response(host, port, suite, group)
    # deflate offered ahead of null: forbidden in a TLS 1.3 ClientHello.
    mutated = first_response(host, port, suite, group, compression=[1, 0])
    return {"probe": "compression", "suite": suite, "group": group,
            "baseline": baseline, "with_deflate": mutated}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("probe", choices=("groups", "compression"))
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--suite", default="TLS_AES_128_GCM_SHA256")
    parser.add_argument("--group", default="x25519")
    args = parser.parse_args()
    if args.host not in LOCAL:
        parser.error("local laboratory targets only")
    if args.suite not in SUITES:
        parser.error("unsupported TLS 1.3 suite")
    try:
        import tlsfuzzer  # noqa: F401
    except ImportError as exc:
        print(json.dumps({"error": f"tlsfuzzer unavailable: {exc}"}))
        return 3
    result = (probe_groups(args.host, args.port, args.suite) if args.probe == "groups"
              else probe_compression(args.host, args.port, args.suite, args.group))
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
