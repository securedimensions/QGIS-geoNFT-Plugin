"""The drone's own chain: its DPoP proofs, their links, and the segments.

Every observation the gateway posts carries a DPoP proof (a compact JWS, ES256)
signed by the drone key. Besides the usual claims it carries the drone chain:

  boot   8 random bytes per power-up (base64url)
  n      1, 2, 3, … per boot
  prev   the previous link (base64url, 32 bytes)
  plh    SHA-256 of the posted JSON bytes, or
  imgh   SHA-256 of the posted picture bytes

  G      = SHA-256("tcs-drone-chain-v1:" ‖ deploymentId ‖ ":" ‖ hex(boot))
  L_n    = SHA-256(prev_n ‖ digest_n)
  prev_1 = G, prev_{n+1} = L_n

Connected Systems stores each proof with the observation and serves it in the
lineage. This module checks a proof's signature and recomputes the links and
the segment summary exactly as connected-systems/deploymentChain.mjs does, so
the result can be compared with the manifest on the ledger. It has no QGIS
imports so the tests run with plain Python.
"""

import base64
import hashlib
import json
import re

try:
    from . import fabric_proof
except ImportError:  # the tests import this module as top level
    import fabric_proof

DRONE_CHAIN_ALG = "tcs-drone-chain-v1"
MAX_DRONE_N = 0xFFFFFFFF
_B64URL = re.compile(r"^[A-Za-z0-9_-]+$")


class ChainError(ValueError):
    pass


def b64url(value, size=None, name="value"):
    """Bytes of a canonical unpadded base64url string, optionally of exactly size bytes. Raises ChainError."""
    if not isinstance(value, str) or not _B64URL.match(value):
        raise ChainError("%s must be base64url" % name)
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != value:
        raise ChainError("%s is not canonical base64url" % name)
    if size is not None and len(raw) != size:
        raise ChainError("%s must encode %d bytes" % (name, size))
    return raw


def b64url_encode(raw):
    return base64.urlsafe_b64encode(bytes(raw)).decode("ascii").rstrip("=")


# ── DPoP proofs ──────────────────────────────────────────────────────────────

def jwk_thumbprint(jwk):
    """RFC 7638 thumbprint of an EC key, as cnf.jkt: base64url SHA-256 of {crv, kty, x, y}."""
    members = ",".join('"%s":%s' % (k, json.dumps(jwk[k], ensure_ascii=False)) for k in ("crv", "kty", "x", "y"))
    return b64url_encode(hashlib.sha256(("{%s}" % members).encode("utf-8")).digest())


def _jwk_point(jwk):
    if not isinstance(jwk, dict) or jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise ChainError("the header key is not an EC P-256 JWK")
    x = b64url(jwk.get("x"), 32, "jwk.x")
    y = b64url(jwk.get("y"), 32, "jwk.y")
    return int.from_bytes(x, "big"), int.from_bytes(y, "big")


def read_proof(compact):
    """Parse a DPoP proof and check its ES256 signature with the key in its header.

    Returns {ok, error, header, claims, jkt}: ok means the signature verifies
    with the header's key; jkt is that key's thumbprint, which the caller
    compares with the deployment's cnfJkt.
    """
    result = {"ok": False, "error": None, "header": None, "claims": None, "jkt": None}
    parts = compact.split(".") if isinstance(compact, str) else []
    if len(parts) != 3:
        result["error"] = "not a compact JWS"
        return result
    try:
        header = json.loads(b64url(parts[0], name="header").decode("utf-8"))
        claims = json.loads(b64url(parts[1], name="payload").decode("utf-8"))
        signature = b64url(parts[2], name="signature")
        if not isinstance(header, dict) or not isinstance(claims, dict):
            raise ChainError("header and payload must be JSON objects")
        result["header"], result["claims"] = header, claims
        if header.get("alg") != "ES256":
            raise ChainError("alg is %s, expected ES256" % header.get("alg"))
        point = _jwk_point(header.get("jwk"))
        result["jkt"] = jwk_thumbprint(header["jwk"])
    except (ChainError, ValueError, UnicodeDecodeError, TypeError, KeyError) as err:
        result["error"] = str(err)
        return result
    if not fabric_proof.ecdsa_verify_raw(point, ("%s.%s" % (parts[0], parts[1])).encode("ascii"), signature):
        result["error"] = "the ES256 signature does not verify"
        return result
    result["ok"] = True
    return result


def chain_claims(claims):
    """(boot, n, prev bytes, digest bytes, digest claim name) of a proof's drone-chain claims, or None without any.

    Raises ChainError when some but not all are present or one is malformed,
    which Connected Systems answers with 400 at the post.
    """
    present = [name for name in ("boot", "n", "prev") if claims.get(name) is not None]
    if not present:
        return None
    if len(present) != 3:
        raise ChainError("boot, n and prev must come together")
    boot, n = claims["boot"], claims["n"]
    b64url(boot, 8, "boot")
    if isinstance(n, bool) or not isinstance(n, int) or not 1 <= n <= MAX_DRONE_N:
        raise ChainError("n must be an integer from 1 to %d" % MAX_DRONE_N)
    prev = b64url(claims["prev"], 32, "prev")
    name = "imgh" if claims.get("imgh") is not None else "plh"
    if claims.get(name) is None:
        raise ChainError("the proof has neither plh nor imgh")
    return boot, n, prev, b64url(claims[name], 32, name), name


# ── Links and segments ───────────────────────────────────────────────────────

def genesis(deployment_id, boot):
    boot_hex = b64url(boot, 8, "boot").hex()
    return hashlib.sha256(("%s:%s:%s" % (DRONE_CHAIN_ALG, deployment_id, boot_hex)).encode("utf-8")).digest()


def link(prev, digest):
    return hashlib.sha256(bytes(prev) + bytes(digest)).digest()


def missing_ranges(numbers, last_n):
    """[[first, last], …] of 1..last_n not in the sorted numbers, without walking every number."""
    ranges = []
    expected = 1
    for n in numbers:
        if n > last_n:
            break
        if n > expected:
            ranges.append([expected, n - 1])
        expected = max(expected, n + 1)
    if expected <= last_n:
        ranges.append([expected, last_n])
    return ranges


def segment_summary(deployment_id, rows, seal=None):
    """Segments from rows {seq, boot, n, prev, link} (hex), as segmentSummary in deploymentChain.mjs.

    One segment per boot, in the order of its first stored observation. A seal
    {boot, n} ends its segment: numbers below seal.n that never arrived count as
    missing. brokenLinks counts links whose prev is not the previous link (or the
    genesis for n = 1) although both are present.
    """
    by_boot = {}
    order = []
    for row in rows:
        boot = row.get("boot")
        if boot is None:
            continue
        segment = by_boot.get(boot)
        if segment is None:
            segment = by_boot[boot] = {"boot": boot, "firstSeq": float("inf"), "links": {}}
            order.append(boot)
        segment["firstSeq"] = min(segment["firstSeq"], int(row["seq"]))
        segment["links"][int(row["n"])] = row
    if seal and seal.get("boot") not in by_boot:
        by_boot[seal["boot"]] = {"boot": seal["boot"], "firstSeq": float("inf"), "links": {}}
        order.append(seal["boot"])

    out = []
    for boot in sorted(order, key=lambda b: by_boot[b]["firstSeq"]):  # stable, like Array.prototype.sort
        links = by_boot[boot]["links"]
        numbers = sorted(links)
        sealed = bool(seal) and seal.get("boot") == boot
        last_n = seal["n"] - 1 if sealed else (numbers[-1] if numbers else 0)
        first = genesis(deployment_id, boot).hex()
        broken = 0
        for n in numbers:
            expected = first if n == 1 else (links[n - 1]["link"] if (n - 1) in links else None)
            if expected is not None and links[n]["prev"] != expected:
                broken += 1
        received = [n for n in numbers if n <= last_n]
        out.append({
            "boot": boot,
            "firstN": numbers[0] if numbers else None,
            "lastN": last_n,
            "received": len(received),
            "missing": missing_ranges(received, last_n),
            "brokenLinks": broken,
            "head": first if last_n == 0 else (links[last_n]["link"] if last_n in links else None),
        })
    return out
