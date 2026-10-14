"""Neutral-transport tests: the plugin uses a plain stdlib TLS handshake.

History: the plugin used to narrow its TLS ClientHello toward the official
Go client's fingerprint (``tls_profile.py``). Probed 2026-10-14, the relay
answers 200 over a default stdlib handshake, so the tuning was removed
(catalog rule 11 refuses fingerprint mimicry without a measured need).
These tests pin the neutral transport:

- No tuning knob may creep back (``TUNED_OPENER`` / ``tls_profile`` gone).
- A real HTTPS request completes over a default-context transport
  (loopback echo server; trust relaxation is loopback-only).
- The transport checker still reports the stdlib-vs-Go gap honestly.
"""
import socket
import ssl
import threading


def test_no_tls_tuning_knob_exists():
    """TUNED_OPENER and the tls_profile module must stay gone.

    This is the regression guard for the catalog resubmission requirement:
    TLS fingerprint tuning must not be reintroduced without a live probe
    proving the relay needs it.
    """
    import importlib.util
    import sys

    sys.path.insert(0, ".")
    try:
        import models as models_mod
    finally:
        if "." in sys.path:
            sys.path.remove(".")

    assert not hasattr(models_mod, "TUNED_OPENER"), (
        "TLS tuning crept back; prove the relay needs it first")
    assert importlib.util.find_spec("tls_profile") is None, (
        "tls_profile.py crept back; prove the relay needs it first")
    assert hasattr(models_mod, "DEFAULT_OPENER")


def _self_signed_cert(tmpdir):
    """Generate a self-signed cert+key via openssl CLI (present on CI).

    Returns (cert_path, key_path). No Python crypto dependency.
    """
    import subprocess

    key = f"{tmpdir}/key.pem"
    cert = f"{tmpdir}/cert.pem"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", key, "-out", cert, "-days", "1",
         "-subj", "/CN=127.0.0.1"],
        check=True, capture_output=True,
    )
    return cert, key


def _tls_echo_server(port, cert, key):
    """A minimal TLS server that speaks HTTP/1.1 and echoes a fixed body."""
    import http.server

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body = b'{"ok":true}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format, *args):  # noqa: A002 - stdlib signature
            pass

    srv = http.server.HTTPServer(("127.0.0.1", port), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv


def test_neutral_transport_completes_a_real_https_request():
    """A default-context transport must complete a real HTTPS request.

    The client context below derives from the stdlib default (same profile
    the production DEFAULT_OPENER handshakes with); only trust is relaxed
    for the loopback self-signed cert (hostname check off, loopback-only).
    """
    import sys
    import tempfile
    import urllib.request

    sys.path.insert(0, ".")
    try:
        from models import DEFAULT_OPENER
    finally:
        if "." in sys.path:
            sys.path.remove(".")

    assert any(
        isinstance(h, urllib.request.HTTPSHandler)
        for h in getattr(DEFAULT_OPENER, "handlers", [])
    ), "DEFAULT_OPENER must be a plain stdlib opener with HTTPS support"

    with tempfile.TemporaryDirectory() as tmpdir:
        cert, key = _self_signed_cert(tmpdir)
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        port = srv.getsockname()[1]
        srv.close()

        server = _tls_echo_server(port, cert, key)
        try:
            client_ctx = ssl.create_default_context()
            client_ctx.load_verify_locations(cafile=cert)
            client_ctx.check_hostname = False  # loopback-only relaxation
            opener = urllib.request.build_opener(
                urllib.request.HTTPSHandler(context=client_ctx))
            req = urllib.request.Request(f"https://127.0.0.1:{port}/test")
            with opener.open(req, timeout=10) as resp:
                assert resp.status == 200
                assert resp.read() == b'{"ok":true}'
        finally:
            server.shutdown()
            server.server_close()


# ── transport_check.py contract verification ─────────────────────────


def test_transport_contract_is_valid_json():
    """The contract must be valid JSON with the expected structure."""
    import json
    from pathlib import Path

    contract = json.loads(Path("transport_contract.json").read_text(encoding="utf-8"))
    assert "axes" in contract
    assert "modes" in contract
    assert "permissive" in contract["modes"]
    assert "strict" in contract["modes"]
    assert len(contract["axes"]) >= 5


def test_transport_check_reports_divergence_honestly():
    """The checker must report the stdlib gap without crashing.

    With the neutral stdlib transport active, most axes diverge from Go.
    The checker must report this honestly (not crash, not claim parity).
    """
    import importlib.util
    from pathlib import Path as _Path

    checker_path = _Path(__file__).resolve().parent.parent / "tools" / "transport_check.py"
    spec = importlib.util.spec_from_file_location("transport_check", checker_path)
    checker = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(checker)

    result = checker.run_check("permissive")
    assert "error" not in result, result.get("error")
    assert result["summary"]["diverged"] > 0, (
        "stdlib backend must report divergence from Go")
    assert result["summary"]["matched"] < result["summary"]["total"], (
        "stdlib backend must not claim full parity")


def test_transport_check_strict_mode_fails_on_divergence():
    """Strict mode must fail (ok=False) when axes diverge."""
    import importlib.util
    from pathlib import Path as _Path

    checker_path = _Path(__file__).resolve().parent.parent / "tools" / "transport_check.py"
    spec = importlib.util.spec_from_file_location("transport_check", checker_path)
    checker = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(checker)

    result = checker.run_check("strict")
    assert "error" not in result, result.get("error")
    assert result["ok"] is False, (
        "strict mode must fail when axes diverge")
    assert len(result["failures"]) > 0
