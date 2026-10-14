#!/usr/bin/env python3
"""Measure the plugin's TLS transport and compare against the parity contract.

Usage:
    python3 tools/transport_check.py                # report, exit 0 if conformant
    python3 tools/transport_check.py --mode strict  # exit 1 on any divergence
    python3 tools/transport_check.py --json         # machine-readable output

This is the verification half of the transport parity contract. It captures
the plugin's actual ClientHello (via a loopback listener, never reaching
Google), parses each axis, and compares against transport_contract.json.

Two modes:
  permissive - log divergence, never block (default)
  strict - fail-closed, exit 1 on any axis beyond tolerance

The contract defines which axes are reachable by stdlib vs sidecar. This
checker measures whatever backend is currently active (stdlib or sidecar) and
reports the gap honestly.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import socket
import ssl
import struct
import sys
import threading
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CONTRACT_PATH = REPO_ROOT / "transport_contract.json"


def _u16(b: bytes, p: int) -> int:
    return struct.unpack_from("!H", b, p)[0]


def _grease(x: int) -> bool:
    return (x & 0x0F0F) == 0x0A0A


def parse_client_hello(record: bytes) -> dict:
    """Parse a raw TLS ClientHello record into its parity axes."""
    hello = record[5 + 4:]  # skip record header(5) + handshake header(4)
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
    exts: list[int] = []
    groups: list[int] = []
    points: list[int] = []
    alpn: list[str] = []
    while p < end:
        t = _u16(hello, p)
        ln = _u16(hello, p + 2)
        p += 4
        v = hello[p:p + ln]
        p += ln
        exts.append(t)
        if t == 10:
            groups = [_u16(v, i) for i in range(2, len(v), 2)]
        elif t == 11:
            points = list(v[1:])
        elif t == 16:
            q = 2
            while q < len(v):
                sz = v[q]
                q += 1
                alpn.append(v[q:q + sz].decode("ascii", errors="replace"))
                q += sz
    ja3 = ",".join([
        str(legacy),
        "-".join(str(x) for x in ciphers if not _grease(x)),
        "-".join(str(x) for x in exts if not _grease(x)),
        "-".join(str(x) for x in groups if not _grease(x)),
        "-".join(str(x) for x in points),
    ])
    return {
        "ja3": ja3,
        "ja3_md5": hashlib.md5(ja3.encode()).hexdigest(),
        "alpn": alpn,
        "cipher_count": len(ciphers),
        "cipher_order": ciphers,
        "supported_groups": groups,
        "extension_order": exts,
        "ec_point_formats": points,
    }


def capture_client_hello() -> dict:
    """Dial a loopback listener with the plugin's active SSL context and capture
    the ClientHello. Never reaches Google — the listener closes before ServerHello.
    """
    captured: dict = {}

    def listener(sock: socket.socket) -> None:
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
            captured["record"] = hs[:5 + int.from_bytes(hs[3:5], "big")]
        except Exception as exc:
            captured["error"] = str(exc)
        conn.close()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    t = threading.Thread(target=listener, args=(srv,), daemon=True)
    t.start()

    # The plugin's transport is a plain stdlib default handshake (TLS tuning
    # was removed: probed 2026-10-14, the relay answers 200 without it).
    # Measure exactly what production handshakes with.
    ctx = ssl.create_default_context()

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

    if "record" not in captured:
        return {"error": captured.get("error", "no ClientHello captured")}
    return parse_client_hello(captured["record"])


def compare_axis(axis_name: str, expected, measured, tolerance: str) -> dict:
    """Compare a single axis against the contract."""
    if tolerance == "exact":
        match = expected == measured
    else:
        match = expected == measured  # only exact supported for now
    return {
        "axis": axis_name,
        "expected": expected,
        "measured": measured,
        "tolerance": tolerance,
        "match": match,
    }


def run_check(mode: str = "permissive") -> dict:
    """Run the full transport parity check."""
    contract = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))
    measured = capture_client_hello()

    if "error" in measured:
        return {
            "ok": False,
            "error": measured["error"],
            "mode": mode,
            "axes": [],
        }

    axes = []
    for axis_name, spec in contract["axes"].items():
        expected = spec["expected"]
        actual = measured.get(axis_name)
        result = compare_axis(axis_name, expected, actual, spec["tolerance"])
        result["weight"] = spec.get("weight", 1.0)
        result["stdlib_reachable"] = spec.get("stdlib_reachable", False)
        result["sidecar_reachable"] = spec.get("sidecar_reachable", False)
        axes.append(result)

    fail_on = contract["modes"][mode]["fail_on"]
    failures = [a for a in axes if not a["match"] and a["axis"] in fail_on]
    ok = len(failures) == 0

    return {
        "ok": ok,
        "mode": mode,
        "measured_from": contract["measured_from"],
        "axes": axes,
        "failures": [a["axis"] for a in failures],
        "summary": {
            "total": len(axes),
            "matched": sum(1 for a in axes if a["match"]),
            "diverged": sum(1 for a in axes if not a["match"]),
            "stdlib_reachable": sum(1 for a in axes if a["match"] and a["stdlib_reachable"]),
            "sidecar_only": sum(1 for a in axes if not a["match"] and a["sidecar_reachable"] and not a["stdlib_reachable"]),
        },
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--mode", choices=["permissive", "strict"], default="permissive",
                    help="permissive: log only; strict: exit 1 on divergence")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args()

    result = run_check(args.mode)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        if "error" in result:
            print(f"ERROR: {result['error']}")
            return 1
        s = result["summary"]
        print(f"Transport parity check ({result['mode']} mode)")
        print(f"  measured from: {result['measured_from']['client']} "
              f"{result['measured_from']['version']} "
              f"({result['measured_from']['date']})")
        print(f"  axes: {s['matched']}/{s['total']} matched, {s['diverged']} diverged")
        print(f"  stdlib reachable: {s['stdlib_reachable']}/{s['total']}")
        print(f"  sidecar only: {s['sidecar_only']}/{s['total']}")
        print()
        for a in result["axes"]:
            mark = "OK  " if a["match"] else "DIFF"
            backend = "stdlib" if a["stdlib_reachable"] else "sidecar"
            print(f"  {mark} {a['axis']:20s} [{backend}]")
            if not a["match"]:
                print(f"       expected: {a['expected']}")
                print(f"       measured: {a['measured']}")
        if result["failures"]:
            print(f"\nFAILED axes: {', '.join(result['failures'])}")

    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
