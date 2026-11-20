from pathlib import Path
import yaml
from tlslab.launch import ROOT, build_command


def test_p1_uses_hardened_tls_only_policy():
    cmd, manifest = build_command(Path("configs/server/P1.yaml"))
    assert any("conf/hardened.security" in arg for arg in cmd)
    assert "X25519MLKEM768" in " ".join(cmd)
    assert manifest["policy"] == "hardened"


def test_a3_and_b2_allow_tls12_for_experiment():
    for variant in ("A3", "B2"):
        cmd, manifest = build_command(Path(f"configs/server/{variant}.yaml"))
        assert any("conf/dual_stack.security" in arg for arg in cmd)
        assert manifest["policy"] == "dual_stack"


def test_vendor_baseline_has_no_security_override():
    cmd, manifest = build_command(Path("configs/server/B1.yaml"))
    assert not any("java.security.properties" in arg for arg in cmd)
    assert manifest["policy"] == "vendor"


def test_all_configs_have_unique_ports_and_nonempty_protocols():
    for file in (ROOT / "configs/server").glob("*.yaml"):
        data = yaml.safe_load(file.read_text())
        assert data["httpsPort"] != data["httpPort"]
        assert data["protocols"]
        if data["provider"] == "SunJSSE" and "SecP256r1MLKEM768" in data.get("namedGroups", []):
            assert file.name.startswith("E2")
