"""Tie the drone's DPoP key (cnfJkt) to its did:indy on the Hyperledger Indy ledger.

The manifest on Fabric fixes two drone facts: its DID (droneDid) and the RFC 7638
thumbprint of its ATECC P-256 key (cnfJkt), the key that signs every DPoP proof.
They are different keys: the NYM holds the drone's Ed25519 verkey. At
enrollment the drone writes, signed with that Ed25519 key, an ATTRIB on its own
NYM:

    {"cnf": {"jwk": {"crv": "P-256", "kty": "EC", "x": ..., "y": ...}}}

This module reads the DID document and the ATTRIB transactions from an Indy
resolver (indy-resolver: GET /1.0/identifiers/<did> and .../attribs) and checks

  indy.nym  the DID document is the manifest's DID, and the DID id is the
            base58 of the first 16 bytes of its Ed25519 verkey;
  indy.cnf  the cnf JWK that was in force when the flight started has the
            thumbprint the manifest fixed. A drone enrolled before the cnf
            ATTRIB existed has none; that is reported, not failed.

It has no QGIS imports so the tests run with plain Python. The resolver's
reading is trusted: the Ed25519 signature on the ATTRIB transaction is not
re-checked here.
"""

import datetime
import hashlib
import base64
import json
import urllib.error
import urllib.request
from urllib.parse import quote, urlsplit

try:
    from . import http_util
except ImportError:  # the tests import this module as top level
    import http_util

DEFAULT_RESOLVER_URL = "https://resolver.geonft.eu"
RESOLVER_TIMEOUT_S = 60

PASS, FAIL, SKIP = "pass", "fail", "skip"

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"  # pragma: allowlist secret (base58 alphabet)


class ResolverError(RuntimeError):
    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status


# ── Encoding ─────────────────────────────────────────────────────────────────

def b58decode(text):
    number = 0
    for ch in text:
        index = _B58.find(ch)
        if index < 0:
            raise ValueError("bad base58 character %r" % ch)
        number = number * 58 + index
    body = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    return b"\0" * (len(text) - len(text.lstrip("1"))) + body


def b58encode(data):
    number = int.from_bytes(data, "big")
    out = ""
    while number:
        number, rest = divmod(number, 58)
        out = _B58[rest] + out
    return "1" * (len(data) - len(data.lstrip(b"\0"))) + out


def jwk_thumbprint(jwk):
    """RFC 7638 SHA-256 thumbprint of an EC P-256 public JWK, base64url without padding."""
    if not isinstance(jwk, dict) or jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise ValueError("not an EC P-256 JWK")
    if not isinstance(jwk.get("x"), str) or not isinstance(jwk.get("y"), str):
        raise ValueError("the JWK has no x and y")
    canon = json.dumps({"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"], "y": jwk["y"]},
                       separators=(",", ":"), sort_keys=True)
    return base64.urlsafe_b64encode(hashlib.sha256(canon.encode("utf-8")).digest()).rstrip(b"=").decode("ascii")


def full_verkey(nym, verkey):
    """The ledger may abbreviate a verkey as ~<last 16 bytes>; the first 16 bytes are the DID id."""
    if verkey.startswith("~"):
        return b58encode(b58decode(nym) + b58decode(verkey[1:]))
    return verkey


def nym_from_verkey(verkey):
    raw = b58decode(verkey)
    if len(raw) != 32:
        raise ValueError("the verkey is %d bytes, not 32 (Ed25519)" % len(raw))
    return b58encode(raw[:16])


# ── Reading ──────────────────────────────────────────────────────────────────

def http_get_public_json(url, timeout=RESOLVER_TIMEOUT_S):
    """GET a public JSON document. No bearer token: the resolver is public and must not see the user's."""
    if urlsplit(str(url)).scheme not in ("http", "https"):
        raise ResolverError("refused to read %s: only http and https URLs are read" % url)
    request = urllib.request.Request(str(url), headers={"Accept": "application/json"}, method="GET")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def once():
        try:
            with opener.open(request, timeout=timeout) as response:
                return http_util.read_body(response, 4 * 1024 * 1024)
        except urllib.error.HTTPError as err:
            raise ResolverError("the Indy resolver answered %s" % err.code, err.code) from err
        except urllib.error.URLError as err:
            if http_util.transient(err):
                raise
            raise ResolverError("the Indy resolver is unavailable: %s" % err.reason) from err
        except TimeoutError as err:
            raise ResolverError("the Indy resolver did not answer within %s s" % timeout) from err

    try:
        raw = http_util.with_retries(once)
    except OSError as err:
        raise ResolverError("the Indy resolver dropped the connection: %s" % err) from err
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as err:
        raise ResolverError("the Indy resolver did not answer with JSON") from err


def read_drone_identity(resolver_base, did, fetch=http_get_public_json):
    """{resolver, didDocument, attribs} for a did:indy, or raises ResolverError."""
    base = str(resolver_base or DEFAULT_RESOLVER_URL).strip().rstrip("/")
    path = "%s/1.0/identifiers/%s" % (base, quote(str(did), safe=":"))
    resolved = fetch(path)
    document = resolved.get("didDocument") if isinstance(resolved, dict) and "didDocument" in resolved else resolved
    if not isinstance(document, dict):
        raise ResolverError("the Indy resolver did not return a DID document")
    listed = fetch(path + "/attribs")
    attribs = listed.get("transactions") if isinstance(listed, dict) else None
    if not isinstance(attribs, list):
        raise ResolverError("the Indy resolver did not return the ATTRIB transactions")
    return {"resolver": base, "didDocument": document, "attribs": attribs}


# ── Checks ───────────────────────────────────────────────────────────────────

def _instant(text):
    if not isinstance(text, str):
        return None
    try:
        return datetime.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None


def _ed25519_verkey(document):
    for method in document.get("verificationMethod") or []:
        if isinstance(method, dict) and method.get("type") == "Ed25519VerificationKey2018" \
                and isinstance(method.get("publicKeyBase58"), str):
            return method["publicKeyBase58"]
    return None


def cnf_entries(attribs):
    """The cnf ATTRIBs in ledger order: [{seqNo, txnTime, jkt}] (jkt None when the JWK is unusable)."""
    entries = []
    for txn in attribs:
        if not isinstance(txn, dict) or not isinstance(txn.get("raw"), str):
            continue
        try:
            raw = json.loads(txn["raw"])
        except ValueError:
            continue
        if not isinstance(raw, dict) or "cnf" not in raw:
            continue
        cnf = raw["cnf"]
        try:
            jkt = jwk_thumbprint(cnf.get("jwk") if isinstance(cnf, dict) else None)
        except ValueError:
            jkt = None
        entries.append({"seqNo": txn.get("seqNo"), "txnTime": txn.get("txnTime"), "jkt": jkt})
    entries.sort(key=lambda e: e["seqNo"] if isinstance(e["seqNo"], int) else 0)
    return entries


def check_drone_identity(manifest, identity, note=None):
    """Checks for the Indy level, plus facts.

    Returns {checks: [(key, title, status, detail, required)], verkey, cnf}. All
    checks are optional for the verdict: an unreadable resolver or a drone
    without a cnf ATTRIB leaves it as it is. A key that does not match fails it.
    """
    manifest = manifest or {}
    did, cnf_jkt = manifest.get("droneDid"), manifest.get("cnfJkt")
    nym_title = "The drone DID is on Indy and its id derives from its Ed25519 verkey"
    cnf_title = "The drone's Indy identity published the DPoP key the ledger fixed (cnfJkt)"
    checks, facts = [], {"verkey": None, "cnf": None}

    if not isinstance(did, str) or not did.startswith("did:indy:"):
        checks.append(("indy.nym", nym_title, SKIP, "the manifest has no did:indy (droneDid %s)" % did, False))
        return dict(checks=checks, **facts)
    if identity is None:
        reason = note or "not read"
        checks.append(("indy.nym", nym_title, SKIP, reason, False))
        checks.append(("indy.cnf", cnf_title, SKIP, reason, False))
        return dict(checks=checks, **facts)

    document = identity.get("didDocument") or {}
    nym = did.rsplit(":", 1)[-1]
    verkey = _ed25519_verkey(document)
    problems = []
    if document.get("id") != did:
        problems.append("the resolver returned %s for %s" % (document.get("id"), did))
    if verkey is None:
        problems.append("the DID document has no Ed25519 verkey")
    else:
        try:
            verkey = full_verkey(nym, verkey)
            derived = nym_from_verkey(verkey)
        except ValueError as err:
            problems.append(str(err))
        else:
            facts["verkey"] = verkey
            if derived != nym:
                problems.append("base58(first 16 bytes of the verkey) is %s, not %s" % (derived, nym))
    checks.append(("indy.nym", nym_title, FAIL if problems else PASS, "; ".join(problems) or "verkey %s" % verkey, False))

    entries = cnf_entries(identity.get("attribs") or [])
    if not entries:
        checks.append(("indy.cnf", cnf_title, SKIP,
                       "the DID has no cnf ATTRIB: the drone was enrolled before its DPoP key was published on Indy; "
                       "re-enrolling it adds one", False))
        return dict(checks=checks, **facts)

    start = _instant(manifest.get("validFrom"))
    before = [e for e in entries if start and _instant(e["txnTime"]) and _instant(e["txnTime"]) <= start]
    matching = [e for e in entries if e["jkt"] == cnf_jkt]
    where = lambda e: "ATTRIB seqNo %s (%s)" % (e["seqNo"], e["txnTime"])  # noqa: E731
    if before:
        # The key the drone's identity named when the flight started.
        in_force = before[-1]
        facts["cnf"] = in_force
        if in_force["jkt"] == cnf_jkt:
            status, detail = PASS, "%s, thumbprint %s, in force when the flight started" % (where(in_force), cnf_jkt)
        else:
            status, detail = FAIL, "when the flight started the drone's identity named key %s (%s), not cnfJkt %s" % (
                in_force["jkt"], where(in_force), cnf_jkt)
    elif matching:
        # Every cnf ATTRIB is newer than the flight: the drone named this key later.
        facts["cnf"] = matching[0]
        status, detail = PASS, "%s, thumbprint %s, published after this flight started" % (where(matching[0]), cnf_jkt)
    else:
        facts["cnf"] = entries[-1]
        status, detail = FAIL, "no cnf ATTRIB has thumbprint %s; the latest names %s (%s)" % (
            cnf_jkt, entries[-1]["jkt"], where(entries[-1]))
    checks.append(("indy.cnf", cnf_title, status, detail, False))
    return dict(checks=checks, **facts)
