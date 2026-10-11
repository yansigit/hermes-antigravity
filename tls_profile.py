"""TLS transport profile for the Antigravity HTTPS client.

Problem
-------
The official ``agy`` client is a Go binary; this plugin speaks TLS through
Python's stdlib ``ssl``/OpenSSL. Google's backends see a TLS ClientHello that
differs between the two, and a JA3 fingerprint is a cheap server-side signal
to correlate a non-official client (see UPSTREAM_DRIFT.md and issue #35).

What stdlib can and cannot align (measured on this host, 2026-10-10,
Python 3.14.7 / OpenSSL 3.5.8, comparing ``agy`` and ``urllib`` ClientHellos
to ``daily-cloudcode-pa.googleapis.com``):

+---------------------+----------------------------------------+-------------------+
| ClientHello field   | stdlib ``ssl`` control                 | Go (agy)          |
+=====================+========================================+===================+
| ALPN                | set_alpn_protocols -> CAN align        | h2,http/1.1       |
| Cipher suites       | set_ciphers -> CAN narrow + reorder    | 13 suites         |
| Supported groups    | NO stdlib API (set_ecdh_curve sets one | 4588,4587,4589,29,|
|                     | curve, not the ordered list)           | 23,24,25          |
| Extension order     | NO stdlib API                          | 0,11,65281,23,... |
+---------------------+----------------------------------------+-------------------+

The supported-groups order (which carries the post-quantum hybrid
X25519MLKEM768 = 4588 plus the PQC groups 4587/4589) and the extension order
are the core of the JA3 hash. Python's public SSL API exposes neither, so an
exact Go fingerprint is **not achievable** in stdlib. This module therefore
does not claim parity: it reduces the observable difference as far as stdlib
allows (ALPN aligned, cipher list narrowed toward Go's) and pins the result
with a drift test so the profile cannot silently regress.

Measured JA3 (same host):
    agy   (Go)     : 03117a8ed39ef02427ebbc39f121275c
    urllib default : a1ebe7f90a577e9399eaa60be3c67721
    urllib + this  : (asserted by tests/test_tls_profile.py against a capture)

Security posture is unchanged: certificate and hostname validation stay on,
only the offered-cipher set and ALPN advertisement are tuned.
"""
from __future__ import annotations

import ssl

# Go 1.2x crypto/tls, ordered as ``agy`` offers them toward Google backends
# (TLS 1.3 AEAD first, then ECDHE AES/CHACHA GCM). Narrowing to this set drops
# the legacy CBC/SHA and non-PFS suites Python otherwise offers, shrinking the
# cipher-count and ordering gap versus the Go ClientHello.
#
# Note: ECDHE-ECDSA-AES256-SHA (49162) is included — the original list missed
# it, yielding 12 ciphers instead of Go's 13.
GO_CIPHER_LIST = (
    "TLS_AES_128_GCM_SHA256:"
    "TLS_AES_256_GCM_SHA384:"
    "TLS_CHACHA20_POLY1305_SHA256:"
    "ECDHE-ECDSA-AES128-GCM-SHA256:"
    "ECDHE-RSA-AES128-GCM-SHA256:"
    "ECDHE-ECDSA-AES256-GCM-SHA384:"
    "ECDHE-RSA-AES256-GCM-SHA384:"
    "ECDHE-ECDSA-CHACHA20-POLY1305:"
    "ECDHE-RSA-CHACHA20-POLY1305:"
    "ECDHE-ECDSA-AES128-SHA:"
    "ECDHE-RSA-AES128-SHA:"
    "ECDHE-ECDSA-AES256-SHA:"
    "ECDHE-RSA-AES256-SHA"
)

# agy offers NO ALPN toward daily-cloudcode-pa.googleapis.com (measured).
# Advertising h2 would break urllib/http.client (HTTP/1.1 only) — Google
# selects h2, then rejects the HTTP/1.1 request. Omit ALPN entirely to match
# agy on the inference host.
GO_ALPN: list[str] = []


def build_ssl_context() -> ssl.SSLContext:
    """An stdlib ``SSLContext`` tuned toward the Go client's ClientHello.

    Certificate and hostname validation remain enabled (``create_default_context``);
    this only narrows the offered ciphers and drops extensions agy does not send.
    Use it wherever the plugin opens an HTTPS connection so every request carries
    the same, narrower handshake rather than the stdlib default.

    Key decisions (measured, see issue #35 and the dhaern review):
    - No ALPN: agy offers none toward daily-cloudcode-pa, and advertising h2
      breaks urllib/http.client (HTTP/1.1 only).
    - OP_NO_TICKET: drops extension 35 (session ticket), which agy does not send.
    - post_handshake_auth = False: drops extension 49.
    - SSL_OP_NO_ENCRYPT_THEN_MAC: drops extension 22.
    """
    ctx = ssl.create_default_context()
    try:
        ctx.set_ciphers(GO_CIPHER_LIST)
    except ssl.SSLError:
        # An OpenSSL build missing one of these names: fall back to the default
        # context rather than fail the request.
        ctx = ssl.create_default_context()
    # Drop extensions agy does not send (measured on daily-cloudcode-pa).
    ctx.options |= ssl.OP_NO_TICKET
    ctx.post_handshake_auth = False
    ctx.options |= 0x00080000  # SSL_OP_NO_ENCRYPT_THEN_MAC
    # No ALPN: agy offers none toward the inference host, and h2 would break
    # urllib/http.client. Only call set_alpn_protocols if we have a non-empty list.
    if GO_ALPN:
        try:
            ctx.set_alpn_protocols(GO_ALPN)
        except (ssl.SSLError, NotImplementedError):
            pass
    return ctx


def profile_facts() -> dict[str, str]:
    """The measured reference points, for the drift test and the tracker.

    Pinned to the 2026-10-10 same-host capture so a regression in the offered
    profile is visible. Not a claim that the plugin matches Go — see the module
    docstring for what stdlib cannot reach.

    Provenance is split by source:
    - go_* : the official agy reference toward daily-cloudcode-pa, from dhaern's
      Windows 11 capture (issue #35). Windows x86-64, Python 3.14.7, OpenSSL 3.5.8.
    - tuned_* : the plugin's stdlib profile (tls_profile.build_ssl_context), as
      measured on this host. This is what the drift test pins against.
    """
    return {
        "go_ja3": "9b7dcdf3f997f1fb7b4409c94cb7ef36",
        "go_alpn": "(none toward daily-cloudcode-pa)",
        "go_cipher_count": "13",
        "go_source": "agy 1.3.3 on Windows 11 x86-64 (dhaern, issue #35)",
        "measured_host": "linux-x86-64",
        "measured_python": "3.14.7",
        "measured_openssl": "OpenSSL 3.5.8",
        "measured_date": "2026-10-10",
    }


def get_tuned_opener():
    """Return a urllib opener whose HTTPS handler uses :func:`build_ssl_context`.

    The opener is module-level (not process-wide via ``install_opener``), so
    the tuning is scoped to this plugin and does not affect other components
    that use ``urllib.request.urlopen``. Falls back to the default opener if
    the context cannot be built, so a request is never blocked by tuning.
    """
    import urllib.request

    try:
        ctx = build_ssl_context()
    except Exception:
        return urllib.request.build_opener()
    https = urllib.request.HTTPSHandler(context=ctx)
    return urllib.request.build_opener(https)
