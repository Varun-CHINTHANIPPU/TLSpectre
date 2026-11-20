from pathlib import Path
import os
import shutil
import pytest
from cryptography import x509
from cryptography.x509 import ocsp

from tlslab.e6_pki import generate


@pytest.mark.skipif(not shutil.which("openssl") or not shutil.which("keytool"),
                    reason="OpenSSL/keytool required")
def test_generated_e6_good_revoked_and_expired_fixtures(tmp_path, monkeypatch):
    monkeypatch.setenv("KS_PASS", "ci-e6-only-local-password")
    out = generate(tmp_path/"e6", uri="http://127.0.0.1:8888")
    assert len(list(out.glob("*_*.crt"))) == 4
    plain = x509.load_pem_x509_certificate((out/"good_plain.crt").read_bytes())
    stale = ocsp.load_der_ocsp_response((out/"good_plain-expired.der").read_bytes())
    revoked = ocsp.load_der_ocsp_response((out/"revoked_plain-fresh.der").read_bytes())
    assert stale.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL
    assert stale.next_update_utc < stale.this_update_utc + __import__("datetime").timedelta(days=2)
    assert revoked.certificate_status == ocsp.OCSPCertStatus.REVOKED
    with pytest.raises(FileExistsError):
        generate(out)
