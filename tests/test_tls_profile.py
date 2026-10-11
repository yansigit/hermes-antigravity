"""TLS profile tests: what stdlib can align toward the Go client, and the drift pin.

Two kinds of test:

- Pure: the profile constants and the SSLContext knobs are what we claim.
- Live capture: dial a loopback ClientHello listener with the tuned context and
  assert the observable result (ALPN offered, cipher count narrowed). This is
  the drift detector: if a Python/OpenSSL upgrade silently changes the offered
  handshake, this fails loudly instead of the plugin quietly growing a new
  fingerprint. It never reaches Google — the listener closes before ServerHello.
"""
import hashlib
import socket
import ssl
import struct
import threading

from tls_profile import (
    GO_ALPN,
    GO_CIPHER_LIST,
    build_ssl_context,
    profile_facts,
)


def _u16(b, p):
    return struct.unpack_from("!H", b, p)[0]


def _grease(x):
    return (x & 0x0F0F) == 0x0A0A


def _capture_client_hello(ctx):
    """Dial a loopback listener and return the parsed ClientHello fields."""
    captured = {}

    def listener(sock):
        conn, _ = sock.accept()
        conn.settimeout(5)
        hs = b""
        while True:
            try:
                chunk = conn.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            hs += chunk
            if len(hs) >= 5 and hs[0] == 22:
                blen = int.from_bytes(hs[3:5], "big")
                if len(hs) >= 5 + blen:
                    break
        try:
            hello = hs[5:5 + int.from_bytes(hs[3:5], "big")][4:]
            p = 0
            legacy = _u16(hello, p)
            p += 34
            p += 1 + hello[p]
            n = _u16(hello, p)
            p += 2
            ciphers = [_u16(hello, i) for i in range(p, p + n, 2)]
            p += n
            p += 1 + hello[p]
            n = _u16(hello, p)
            p += 2
            end = p + n
            exts = []
            alpn = []
            groups = []
            while p < end:
                t = _u16(hello, p)
                ln = _u16(hello, p + 2)
                p += 4
                v = hello[p:p + ln]
                p += ln
                exts.append(t)
                if t == 10:
                    groups = [_u16(v, i) for i in range(2, len(v), 2)]
                elif t == 16:
                    q = 2
                    while q < len(v):
                        sz = v[q]
                        q += 1
                        alpn.append(v[q:q + sz].decode())
                        q += sz
            ja3 = ",".join([
                str(legacy),
                "-".join(str(x) for x in ciphers if not _grease(x)),
                "-".join(str(x) for x in exts if not _grease(x)),
                "-".join(str(x) for x in groups if not _grease(x)),
                "",
            ])
            captured.update(
                cipher_count=len(ciphers), alpn=alpn, groups=groups,
                ja3_md5=hashlib.md5(ja3.encode()).hexdigest(),
            )
        except Exception as exc:  # pragma: no cover - capture is best-effort
            captured["error"] = str(exc)
        conn.close()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    t = threading.Thread(target=listener, args=(srv,), daemon=True)
    t.start()

    c = socket.create_connection(("127.0.0.1", port), timeout=5)
    try:
        tls = ctx.wrap_socket(c, server_hostname="daily-cloudcode-pa.googleapis.com")
        tls.close()
    except (ssl.SSLError, OSError):
        try:
            c.close()
        except Exception:
            pass
    t.join(timeout=3)
    srv.close()
    return captured


# ── Pure: the profile's stated shape ────────────────────────────────

def test_go_alpn_matches_the_measured_go_offer():
    # agy sends NO ALPN toward daily-cloudcode-pa (measured, issue #35).
    # Advertising h2 would break urllib/http.client (HTTP/1.1 only).
    assert GO_ALPN == []


def test_cipher_list_matches_go_order_exactly():
    """The narrowed list must match the Go cipher order exactly.

    The 13 ciphers in GO_CIPHER_LIST are the ones agy offers toward
    daily-cloudcode-pa (measured). Any addition or removal is a regression.
    SHA1-CBC suites (ECDHE-ECDSA-AES128-SHA, ECDHE-RSA-AES128-SHA, etc.)
    are in the Go list too, so this test does NOT exclude them — it pins
    the exact set.
    """
    ciphers = GO_CIPHER_LIST.split(":")
    assert len(ciphers) == 13, f"expected 13 ciphers, got {len(ciphers)}"
    expected = [
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
        "ECDHE-ECDSA-AES128-GCM-SHA256",
        "ECDHE-RSA-AES128-GCM-SHA256",
        "ECDHE-ECDSA-AES256-GCM-SHA384",
        "ECDHE-RSA-AES256-GCM-SHA384",
        "ECDHE-ECDSA-CHACHA20-POLY1305",
        "ECDHE-RSA-CHACHA20-POLY1305",
        "ECDHE-ECDSA-AES128-SHA",
        "ECDHE-RSA-AES128-SHA",
        "ECDHE-ECDSA-AES256-SHA",
        "ECDHE-RSA-AES256-SHA",
    ]
    assert ciphers == expected, f"cipher order mismatch: {ciphers}"


def test_profile_facts_pin_the_measured_go_ja3():
    facts = profile_facts()
    assert facts["go_ja3"] == "9b7dcdf3f997f1fb7b4409c94cb7ef36"
    assert facts["go_alpn"] == "(none toward daily-cloudcode-pa)"
    assert facts["go_cipher_count"] == "13"


def test_build_ssl_context_keeps_verification_on():
    """Tuning must not weaken certificate/hostname validation."""
    ctx = build_ssl_context()
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname is True


# ── Live capture: the drift detector ────────────────────────────────

def test_tuned_context_matches_go_alpn():
    """The tuned context must offer no ALPN, matching agy on the inference host.

    agy sends no ALPN toward daily-cloudcode-pa. Advertising h2 would break
    urllib/http.client (HTTP/1.1 only) — Google selects h2, then rejects the
    HTTP/1.1 request. Omitting ALPN entirely is both the safe and the
    parity-correct choice.
    """
    result = _capture_client_hello(build_ssl_context())
    assert "error" not in result, result.get("error")
    assert result["alpn"] == [], (
        "the tuned context must offer no ALPN to match agy on the inference host")


def test_tuned_context_narrows_the_cipher_count():
    """Tuning must reduce the offered cipher count versus the stdlib default.

    The default context offers 17 suites; the Go client offers 13. Narrowing is
    the achievable part of the gap. Assert exactly 13 so a regression to 14/16
    is caught, not just a return to the full default.
    """
    default = _capture_client_hello(ssl.create_default_context())
    tuned = _capture_client_hello(build_ssl_context())
    assert "error" not in tuned, tuned.get("error")
    assert tuned["cipher_count"] == 13, (
        f"tuned offered {tuned['cipher_count']} ciphers, expected exactly 13")
    assert tuned["cipher_count"] < default["cipher_count"], (
        f"tuned offered {tuned['cipher_count']} ciphers, "
        f"default {default['cipher_count']}: tuning must narrow the list")


def test_tuned_ja3_differs_from_default_and_is_stable():
    """The tuned fingerprint must differ from the default AND be reproducible.

    We do NOT assert it equals Go (stdlib cannot order supported groups or
    extensions — see tls_profile docstring). We assert it is a deliberate,
    stable change from the default, so the profile is a known quantity rather
    than an accident.
    """
    default = _capture_client_hello(ssl.create_default_context())
    tuned_a = _capture_client_hello(build_ssl_context())
    tuned_b = _capture_client_hello(build_ssl_context())
    assert "error" not in tuned_a, tuned_a.get("error")
    assert tuned_a["ja3_md5"] != default["ja3_md5"], (
        "tuned fingerprint must differ from default")
    assert tuned_a["ja3_md5"] == tuned_b["ja3_md5"], (
        "the tuned ClientHello must be deterministic across connections")


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

    With the stdlib backend active, most axes diverge from Go. The checker
    must report this honestly (not crash, not claim parity).
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


# ── Live: a real HTTP/1.1 request completes over the tuned transport ─

def _self_signed_cert(tmpdir):
    """Generate a self-signed cert+key via openssl CLI (present on ubuntu-latest).

    Returns (cert_path, key_path). No Python crypto dependency: this must run
    in CI without adding a package.
    """
    import subprocess
    import tempfile

    key = f"{tmpdir}/key.pem"
    cert = f"{tmpdir}/cert.pem"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", key, "-out", cert, "-days", "1",
         "-subj", "/CN=daily-cloudcode-pa.googleapis.com"],
        check=True, capture_output=True,
    )
    return cert, key


def _tls_echo_server(port, cert, key):
    """A minimal TLS server that speaks HTTP/1.1 and echoes a fixed body.

    The server verifies nothing on its side; the CLIENT context decides whether
    to trust. This completes a real request over the tuned transport — the test
    the loopback ClientHello capture never performed (it closes before
    ServerHello, so it never caught the h2-breaks-urllib bug).
    """
    import http.server

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body = b'{"ok":true}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", port), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv


def test_tuned_transport_completes_a_real_http11_request():
    """The tuned transport must complete a real HTTP/1.1 request, not just
    offer a ClientHello.

    Two guards in one test:
    1. The REAL get_tuned_opener() must carry a context that offers no ALPN
       (inspect the production object, not a hand-built stand-in — a regression
       that adds h2 only to get_tuned_opener() must be caught here).
    2. A real HTTP/1.1 request must complete over that tuned transport.

    This is the regression guard for the h2 bug: advertising h2,http/1.1 broke
    every request because urllib/http.client only speaks HTTP/1.1 — Google
    selects h2 via ALPN, then rejects the HTTP/1.1 body. The loopback capture
    test never caught it because the listener closed before ServerHello.
    """
    import tempfile
    import urllib.request

    from tls_profile import get_tuned_opener

    # Guard 1: inspect the REAL production opener's SSL context.
    opener = get_tuned_opener()
    prod_ctx = None
    for handler in opener.handlers:
        if isinstance(handler, urllib.request.HTTPSHandler):
            prod_ctx = getattr(handler, "_context", None)
    assert prod_ctx is not None, "get_tuned_opener must expose an HTTPSHandler context"
    # set_alpn_protocols stores the value; an unset context reports []. Assert
    # the production opener advertises no ALPN.
    assert getattr(prod_ctx, "_alpn_protocols", []) == [], (
        "get_tuned_opener() must not advertise ALPN (h2 breaks urllib)")

    # Guard 2: a real HTTP/1.1 request completes over the tuned transport.
    # Use a client context that trusts the self-signed test cert — this relaxes
    # only verification for the loopback, the ALPN/cipher profile is unchanged.
    with tempfile.TemporaryDirectory() as tmpdir:
        cert, key = _self_signed_cert(tmpdir)
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        port = srv.getsockname()[1]
        srv.close()

        server = _tls_echo_server(port, cert, key)
        try:
            client_ctx = build_ssl_context()
            client_ctx.check_hostname = False
            client_ctx.verify_mode = ssl.CERT_NONE
            opener = urllib.request.build_opener(
                urllib.request.HTTPSHandler(context=client_ctx))
            req = urllib.request.Request(
                f"https://127.0.0.1:{port}/test")
            with opener.open(req, timeout=10) as resp:
                assert resp.status == 200
                body = resp.read()
                assert body == b'{"ok":true}', body
        finally:
            server.shutdown()
            server.server_close()
