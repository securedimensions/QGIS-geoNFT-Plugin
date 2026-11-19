"""Verify a closed deployment against its NFT on the Fabric ledger.

The ledger API (geoNFT-Fabric/ledger-api) answers ReadDeployment for a
deploymentId: the manifest written at close, its deployment hash, and the mint
transaction. Connected Systems answers GET /deployments/{id}/lineage: every
observation's anchor hash and server-chain value in storage order. This module
recomputes, from those documents alone:

  L0  the NFT belongs to the deployment, was minted by Connected Systems'
      identity, and its mint transaction is VALID in a block; the endorsing
      peers' signatures verify against the pinned CA certificate of their
      organisation (trust/<mspId>.pem), the signed write set is exactly this
      NFT, and the signers satisfy AND(SecdMSP, OR(EngineeringMSP, GeoidworksMSP));
  L1  SHA-256 of the RFC 8785 canonical manifest is the deployment hash on the
      ledger (and Connected Systems still serves the same manifest);
  L2  the server chain over the lineage reproduces the count and head that the
      manifest fixed on the ledger, link by link:
        S_0 = SHA-256("tcs-deployment-chain-v1:" + deploymentId)
        S_k = SHA-256(S_{k-1} || raw32(anchorHash_k))
  L3  the drone chain: every stored DPoP proof is an ES256 signature by the
      drone key whose thumbprint the manifest fixed (cnfJkt), names this
      deployment, and its boot, n, prev and plh/imgh give the stored link; the
      segments recomputed from the proofs are the manifest's; the gateway's seal
      is signed by the same key, ends its segment, and that segment has no gaps
      (see drone_chain.py);
  L4  the content: each picture's anchor hash is SHA-256 of the canonical
      { deploymentId, result }, and the bytes downloaded from result.url hash to
      result.sha256 and to the imgh the drone signed. For position fixes the
      plh the drone signed is compared with the anchor hash (equal when the
      gateway sent canonical JSON, which current firmware does).
  L5  the drone identity on Indy: the manifest's droneDid derives from its
      Ed25519 verkey, and the cnf ATTRIB the drone wrote on that NYM (signed
      with the Ed25519 key) names the DPoP key whose thumbprint is cnfJkt
      (see indy_identity.py). Optional for the verdict, except a mismatch.

The ledger API reads from EngineeringMSP's peer, so the record does not pass
through SecD, which runs Connected Systems. The endorsement signatures add that
a peer of a second organisation signed the same write set. That the transaction
is VALID and in which block is the word of the peer it was read from. This
module has no QGIS imports so the tests run with plain Python.
"""

import base64
import concurrent.futures
import datetime
import hashlib
import html
import json
import math
import os
import urllib.error
import urllib.request
from urllib.parse import quote, urlsplit

try:
    from . import cs_api, drone_chain, fabric_proof, http_util, indy_identity, observation_view
except ImportError:  # the tests import this module as top level
    import cs_api
    import http_util
    import drone_chain
    import fabric_proof
    import indy_identity
    import observation_view

DEFAULT_LEDGER_URL = "https://ledger.geonft.eu"
LEDGER_TIMEOUT_S = 30
LINEAGE_TIMEOUT_S = 180
LINEAGE_LIMIT = 1000
LINEAGE_MAX_PAGES = 1000

SERVER_CHAIN_ALG = "tcs-deployment-chain-v1"
MINTER = "SecdMSP/csapi@geonft.eu"
NFT_CHAINCODE = "deployments"
# Endorsement policy of the deployments chaincode since sequence 2 (2026-11-18):
# AND('SecdMSP.peer', OR('EngineeringMSP.peer', 'GeoidworksMSP.peer')).
MINTER_MSP = "SecdMSP"
WITNESS_MSPS = ("EngineeringMSP", "GeoidworksMSP")
TRUST_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "trust")

IMAGE_TIMEOUT_S = 60
IMAGE_MAX_BYTES = 64 * 1024 * 1024
IMAGE_WORKERS = 4
# Pictures posted before the public gateway was configured were anchored with
# these hosts in result.url; Connected Systems now serves the public URL for the same CID.
LEGACY_IMAGE_GATEWAYS = ("http://localhost:8091", "http://127.0.0.1:8091")

PASS, FAIL, SKIP, INFO = "pass", "fail", "skip", "info"
VERIFIED, FAILED, INCOMPLETE = "verified", "failed", "incomplete"

# Per observation, written onto the map features as chain_check.
OBS_OK = "ok"
OBS_BROKEN = "broken link"
OBS_ANCHOR = "anchor differs"
OBS_MISSING = "not in lineage"
OBS_PROOF = "bad drone proof"
OBS_CONTENT = "content differs"
OBS_IMAGE = "picture differs"
OBS_UNREAD = "picture not read"
# The most serious first: an observation shows one status.
_OBS_RANK = (OBS_MISSING, OBS_ANCHOR, OBS_BROKEN, OBS_PROOF, OBS_CONTENT, OBS_IMAGE, OBS_UNREAD, OBS_OK)


# ── RFC 8785 (JSON Canonicalization Scheme) ──────────────────────────────────

def canonical_json(value):
    """RFC 8785 serialization: the bytes the deployment hash is computed over."""
    return "".join(_canonical(value))


def canonical_hash(value):
    """Lowercase hex SHA-256 of the RFC 8785 form, as canonicalHash in Connected Systems."""
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _canonical(value):
    if value is None:
        yield "null"
    elif value is True:
        yield "true"
    elif value is False:
        yield "false"
    elif isinstance(value, int):
        # JSON.parse gives a double; beyond 2^53 the value has already been rounded.
        yield str(value) if abs(value) < 2 ** 53 else es_number(float(value))
    elif isinstance(value, float):
        yield es_number(value)
    elif isinstance(value, str):
        yield _string(value)
    elif isinstance(value, (list, tuple)):
        yield "["
        for index, item in enumerate(value):
            if index:
                yield ","
            yield from _canonical(item)
        yield "]"
    elif isinstance(value, dict):
        for key in value:
            if not isinstance(key, str):
                raise TypeError("object keys must be strings")
        yield "{"
        # Sorted by UTF-16 code units, as JavaScript compares strings.
        for index, key in enumerate(sorted(value, key=lambda k: k.encode("utf-16-be", "surrogatepass"))):
            if index:
                yield ","
            yield _string(key)
            yield ":"
            yield from _canonical(value[key])
        yield "}"
    else:
        raise TypeError("cannot canonicalize %s" % type(value).__name__)


def _string(text):
    # JSON.stringify escaping: ", \, the short forms and \u00xx for other controls.
    return json.dumps(text, ensure_ascii=False)


def es_number(x):
    """ECMAScript Number::toString, which RFC 8785 uses for numbers."""
    if math.isnan(x) or math.isinf(x):
        raise ValueError("NaN and Infinity have no JSON form")
    if x == 0:
        return "0"
    if x < 0:
        return "-" + es_number(-x)
    mantissa, _, exponent = repr(x).partition("e")
    whole, _, fraction = mantissa.partition(".")
    digits = (whole + fraction).lstrip("0")
    exp10 = int(exponent or 0) - len(fraction)
    stripped = digits.rstrip("0")
    exp10 += len(digits) - len(stripped)
    s, k = stripped, len(stripped)
    n = exp10 + k  # x = 0.s × 10^n
    if k <= n <= 21:
        return s + "0" * (n - k)
    if 0 < n <= 21:
        return s[:n] + "." + s[n:]
    if -6 < n <= 0:
        return "0." + "0" * (-n) + s
    e = n - 1
    sign = "+" if e >= 0 else "-"
    return (s if k == 1 else s[0] + "." + s[1:]) + "e" + sign + str(abs(e))


# ── Server chain ─────────────────────────────────────────────────────────────

def server_genesis(deployment_id):
    return hashlib.sha256(("%s:%s" % (SERVER_CHAIN_ALG, deployment_id)).encode("utf-8")).digest()


def server_step(previous, anchor_hash):
    return hashlib.sha256(previous + _hex32(anchor_hash, "anchorHash")).digest()


def server_chain(deployment_id, anchor_hashes):
    head = server_genesis(deployment_id)
    for anchor in anchor_hashes:
        head = server_step(head, anchor)
    return head.hex()


def _hex32(value, name):
    if not isinstance(value, str) or len(value) != 64 or value != value.lower():
        raise ValueError("%s must be 64 lowercase hex characters" % name)
    try:
        return bytes.fromhex(value)
    except ValueError as err:
        raise ValueError("%s must be 64 lowercase hex characters" % name) from err


# ── Reads ────────────────────────────────────────────────────────────────────

def _ledger_message(status, deployment_id, fallback):
    if status == 401:
        return "The ledger API rejected the sign-in (401). Sign in again."
    if status == 404:
        return ("The ledger has no NFT for %s (404). The deployment is not closed yet, "
                "or its NFT is not minted or committed yet." % deployment_id)
    if status == 429:
        return "The ledger API refused more requests for now (429). Try again in a minute."
    if status == 502:
        return "The ledger API could not read the Fabric peer (502)."
    if status is None:
        return fallback.replace("Connected Systems", "The ledger API", 1)
    return "The ledger API answered %s for %s." % (status, deployment_id)


def ledger_deployment(ledger_base, token, deployment_id, fetch=cs_api.http_get_json):
    """GET {ledger}/deployments/{id}: { record, transaction, transactionError?, source, readAt }."""
    url = "%s/deployments/%s" % (cs_api.normalize_base(ledger_base, DEFAULT_LEDGER_URL), quote(str(deployment_id), safe=""))
    try:
        body = fetch(url, token, LEDGER_TIMEOUT_S)
    except cs_api.CsApiError as err:
        raise cs_api.CsApiError(_ledger_message(err.status, deployment_id, str(err)), err.status, err.detail) from err
    if not isinstance(body, dict) or not isinstance(body.get("record"), dict):
        raise cs_api.CsApiError("The ledger API answered without an NFT record.", None, json.dumps(body)[:2000])
    return body


def deployment_lineage(base, token, deployment_id, fetch=cs_api.http_get_json):
    """{items, seal}: all lineage items in seq order (Connected Systems pages with rel=next) and the gateway's seal or None."""
    url = "%s/deployments/%s/lineage?limit=%d" % (cs_api.normalize_base(base), quote(str(deployment_id), safe=""), LINEAGE_LIMIT)
    items = []
    seal = None
    for body in cs_api._pages(url, token, LINEAGE_TIMEOUT_S, fetch, LINEAGE_MAX_PAGES):
        page = body.get("items")
        if not isinstance(page, list):
            raise cs_api.CsApiError("Connected Systems did not answer with lineage items.", None, json.dumps(body)[:2000])
        items.extend(item for item in page if isinstance(item, dict))
        seal = body.get("seal") if isinstance(body.get("seal"), dict) else None
    return {"items": items, "seal": seal}


def observation_fields(member):
    """{id, deploymentId, resultType, result} of an Observation item or of the Feature cs_api made from one."""
    if not isinstance(member, dict):
        return None
    properties = member.get("properties") if member.get("type") == "Feature" else member
    properties = properties if isinstance(properties, dict) else {}
    result = observation_view.parse_result(properties.get("result"))
    return {
        "id": member.get("id"),
        "deploymentId": properties.get("deploymentId"),
        "kind": observation_view.kind_of(dict(properties, result=result)),
        "result": result,
    }


def http_get_bytes(url, timeout=IMAGE_TIMEOUT_S, max_bytes=IMAGE_MAX_BYTES):
    """GET a picture from its gateway, without the bearer token: the gateway is public and needs none."""
    if urlsplit(str(url)).scheme not in ("http", "https"):
        raise cs_api.CsApiError("refused to read %s: only http and https URLs are read" % url)
    request = urllib.request.Request(str(url), headers={"Accept": "*/*"}, method="GET")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def once():
        try:
            with opener.open(request, timeout=timeout) as response:
                return http_util.read_body(response, max_bytes + 1)
        except urllib.error.HTTPError as err:
            raise cs_api.CsApiError("the gateway answered %s" % err.code, err.code) from err
        except urllib.error.URLError as err:
            if http_util.transient(err):
                raise
            raise cs_api.CsApiError("the gateway is unavailable: %s" % err.reason) from err
        except TimeoutError as err:
            raise cs_api.CsApiError("the gateway did not answer within %s s" % timeout) from err

    try:
        data = http_util.with_retries(once)
    except http_util.TruncatedBody as err:
        # A cut picture would otherwise fail its hash check and look like tampering.
        raise cs_api.CsApiError("the gateway closed the connection after %s of %s" % (
            http_util.size_text(err.received), http_util.size_text(err.expected))) from err
    except OSError as err:
        raise cs_api.CsApiError("the gateway dropped the connection: %s" % err) from err
    if len(data) > max_bytes:
        raise cs_api.CsApiError("the picture is larger than %d MB" % (max_bytes // (1024 * 1024)))
    return data


def read_images(members, fetch_bytes=http_get_bytes, workers=IMAGE_WORKERS):
    """{observation id: {"data": bytes} or {"error": text}} for every picture among the observations.

    Pictures on IPFS are downloaded from result.url; a server without IPFS keeps
    the bytes inline as base64 in result.body.
    """
    wanted = {}
    out = {}
    for member in members or []:
        fields = observation_fields(member)
        if not fields or fields["kind"] != observation_view.IMAGE or fields["id"] is None:
            continue
        reference = observation_view.image_reference(fields["result"])
        if reference["data"] is not None:
            out[_int_id(fields["id"])] = {"data": reference["data"]}
        elif reference["url"]:
            wanted[_int_id(fields["id"])] = reference["url"]
        else:
            out[_int_id(fields["id"])] = {"error": "the result names no picture URL"}

    def one(url):
        try:
            return {"data": fetch_bytes(url)}
        except cs_api.CsApiError as err:
            return {"error": str(err)}

    if wanted:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, min(workers, len(wanted)))) as pool:
            for obs_id, outcome in zip(wanted, pool.map(one, wanted.values())):
                out[obs_id] = outcome
    return out


def deployment_manifest(base, token, deployment_id, fetch=cs_api.http_get_json):
    """The manifest Connected Systems serves now, or (None, reason) when it does not serve it to this account."""
    url = "%s/deployments/%s/manifest" % (cs_api.normalize_base(base), quote(str(deployment_id), safe=""))
    try:
        body = fetch(url, token, LEDGER_TIMEOUT_S)
    except cs_api.CsApiError as err:
        if err.status in (403, 404):
            return None, "Connected Systems does not serve the manifest to this account (%s)." % err.status
        raise
    if not isinstance(body, dict):
        return None, "Connected Systems answered the manifest with an unexpected document."
    return body, None


# ── Pinned CA certificates ───────────────────────────────────────────────────

def bundled_trust(directory=TRUST_DIR):
    """{mspId: [Certificate]} from <directory>/<mspId>.pem (one or more CA certificates each)."""
    pems = {}
    if os.path.isdir(directory):
        for name in sorted(os.listdir(directory)):
            if name.endswith(".pem"):
                with open(os.path.join(directory, name), encoding="ascii", errors="replace") as handle:
                    pems[name[:-4]] = handle.read()
    return fabric_proof.load_trust(pems)


# ── Verification ─────────────────────────────────────────────────────────────

def verify_deployment(deployment_id, ledger_doc, lineage, cs_manifest=None, cs_manifest_note=None, observations=None,
                      trust=None, cs_observations=None, cs_observations_note=None, images=None,
                      indy=None, indy_note=None):
    """Run L0 to L5.

    lineage is {items, seal} as deployment_lineage returns it (a bare list of
    items means no seal). observations maps observation id → {anchorHash,
    chainHash} from the map layer. trust is {mspId: [Certificate]}; by default
    the certificates in trust/. cs_observations are the deployment's
    observations from Connected Systems (Observation items or Features), None
    when they were not read (cs_observations_note says why); images is
    read_images() over them. indy is indy_identity.read_drone_identity() for the
    manifest's droneDid, None when it was not read (indy_note says why).

    Returns {deploymentId, verdict, checks, facts, observations}. A check is
    {level, key, title, status, detail, required}. verdict is failed when a check
    failed, incomplete when a required check could not run, else verified.
    """
    checks = []
    trust = bundled_trust() if trust is None else trust
    endorsers = []
    if isinstance(lineage, dict):
        lineage_items, seal = lineage.get("items") or [], lineage.get("seal")
    else:
        lineage_items, seal = list(lineage or []), None

    def add(level, key, title, status, detail="", required=True):
        checks.append({"level": level, "key": key, "title": title, "status": status, "detail": detail, "required": required})

    record = ledger_doc.get("record") or {}
    tx = ledger_doc.get("transaction")
    manifest = record.get("manifest")
    manifest = manifest if isinstance(manifest, dict) else None

    # L0 — the record on the ledger
    owned = record.get("tokenId") == deployment_id and manifest is not None and manifest.get("deploymentId") == deployment_id
    add(0, "ledger.token", "The NFT belongs to this deployment", PASS if owned else FAIL,
        "tokenId %s, manifest.deploymentId %s" % (record.get("tokenId"), (manifest or {}).get("deploymentId")))
    add(0, "ledger.minter", "Minted by Connected Systems' identity", PASS if record.get("mintedBy") == MINTER else FAIL,
        "mintedBy %s" % record.get("mintedBy"))
    if not isinstance(tx, dict):
        add(0, "ledger.transaction", "The mint transaction is valid in a block", SKIP,
            "The ledger API could not read the transaction: %s" % (ledger_doc.get("transactionError") or "no transaction"))
    else:
        problems = []
        if tx.get("txId") != record.get("txId"):
            problems.append("transaction %s is not the record's %s" % (tx.get("txId"), record.get("txId")))
        if tx.get("validationCode") != 0:
            problems.append("validation %s" % (tx.get("validation") or tx.get("validationCode")))
        if tx.get("chaincode") not in (None, NFT_CHAINCODE):
            problems.append("chaincode %s" % tx.get("chaincode"))
        add(0, "ledger.transaction", "The mint transaction is valid in a block", FAIL if problems else PASS,
            "; ".join(problems) or "%s, block %s" % (tx.get("validation"), tx.get("blockNumber")))
        for check in _check_endorsements(record, tx, trust, endorsers):
            add(0, *check)

    # L1 — the manifest hashes to the deployment hash
    computed = None
    if manifest is None:
        add(1, "manifest.hash", "The manifest hashes to the deployment hash", FAIL, "the record has no manifest")
    else:
        try:
            computed = canonical_hash(manifest)
        except (TypeError, ValueError) as err:
            add(1, "manifest.hash", "The manifest hashes to the deployment hash", FAIL, "cannot canonicalize: %s" % err)
        else:
            same = computed == record.get("deploymentHash")
            add(1, "manifest.hash", "The manifest hashes to the deployment hash", PASS if same else FAIL,
                "computed %s, ledger %s" % (computed, record.get("deploymentHash")))
    if cs_manifest is None:
        add(1, "manifest.cs", "Connected Systems serves the same manifest", SKIP,
            cs_manifest_note or "not read", required=False)
    elif manifest is not None:
        same = _same_document(cs_manifest, manifest)
        add(1, "manifest.cs", "Connected Systems serves the same manifest", PASS if same else FAIL,
            "" if same else "the manifest from Connected Systems differs from the one on the ledger", required=False)

    # L2 — the server chain over the lineage
    chain = _check_chain(deployment_id, manifest, lineage_items)
    for check in chain["checks"]:
        add(2, *check)

    # L3 — the drone chain
    drone = _check_drone(deployment_id, manifest, lineage_items, seal)
    for check in drone["checks"]:
        add(3, *check)

    # L4 — the content
    content = _check_content(deployment_id, lineage_items, drone["digests"], cs_observations, cs_observations_note, images)
    for check in content["checks"]:
        add(4, *check)

    # L5 — the drone identity on Indy
    identity = indy_identity.check_drone_identity(manifest, indy, indy_note)
    for check in identity["checks"]:
        add(5, *check)

    flagged = {}
    for obs_id, status in list(drone["flags"].items()) + list(content["flags"].items()):
        flagged[obs_id] = _worse(flagged.get(obs_id), status)
    for obs_id, item in chain["items"].items():
        if not item["ok"]:
            flagged[obs_id] = _worse(flagged.get(obs_id), OBS_BROKEN)
    obs_status = _observation_status(observations or {}, chain["items"], flagged)

    failed = any(c["status"] == FAIL for c in checks)
    incomplete = any(c["status"] == SKIP and c["required"] for c in checks)
    return {
        "deploymentId": deployment_id,
        "verdict": FAILED if failed else INCOMPLETE if incomplete else VERIFIED,
        "checks": checks,
        "facts": {
            "deploymentHash": record.get("deploymentHash"),
            "computedHash": computed,
            "mintedAt": record.get("mintedAt"),
            "txId": record.get("txId"),
            "blockNumber": (tx or {}).get("blockNumber") if isinstance(tx, dict) else None,
            "endorsements": [e.get("mspId") for e in (tx or {}).get("endorsements") or []] if isinstance(tx, dict) else [],
            "endorsers": endorsers,
            "source": ledger_doc.get("source"),
            "readAt": ledger_doc.get("readAt"),
            "lineageCount": len(lineage_items),
            "serverHead": chain["head"],
            "firstBrokenSeq": chain["firstBrokenSeq"],
            "droneDid": (manifest or {}).get("droneDid"),
            "cnfJkt": (manifest or {}).get("cnfJkt"),
            "indyVerkey": identity["verkey"],
            "indyCnf": identity["cnf"],
            "indyResolver": (indy or {}).get("resolver"),
            "droneSegments": drone["segments"],
            "droneSigned": drone["signed"],
            "sealed": seal is not None,
            "pictures": content["pictures"],
            "picturesMatched": content["picturesMatched"],
            "flagged": {obs_id: status for obs_id, status in flagged.items() if status != OBS_OK},
        },
        "observations": obs_status,
    }


def _check_endorsements(record, tx, trust, endorsers):
    """Checks on the signed endorsements of the mint transaction; fills endorsers with one result per signature."""
    action = tx.get("endorsedAction")
    title_sig = "The endorsement signatures verify against the pinned CA certificates"
    title_writes = "The endorsed write set is this NFT"
    title_policy = "Endorsed by %s and %s" % (MINTER_MSP, " or ".join(WITNESS_MSPS))
    if not isinstance(action, dict):
        return [("endorse.signatures", title_sig, SKIP,
                 "The ledger API did not return the signed endorsements (it needs version 1.1).")]
    try:
        prp = base64.b64decode(action.get("proposalResponsePayload") or "", validate=True)
        signed = fabric_proof.chaincode_action(prp)
    except (ValueError, TypeError) as err:
        return [("endorse.signatures", title_sig, FAIL, "unreadable proposal response: %s" % err)]

    at = _instant(record.get("mintedAt"))
    for endorsement in action.get("endorsements") or []:
        endorsers.append(fabric_proof.check_endorsement(prp, endorsement if isinstance(endorsement, dict) else {}, trust, at))
    checks = []

    # Signatures: a wrong one is a failure; an organisation without a pinned CA is only unverified.
    bad = [e for e in endorsers if not e["ok"] and not (e["problem"] or "").startswith("no pinned CA")]
    verified = [e for e in endorsers if e["ok"]]
    detail = "; ".join("%s %s: %s" % (e["mspId"], _cn(e["subject"]), "verified" if e["ok"] else e["problem"]) for e in endorsers)
    if not endorsers:
        checks.append(("endorse.signatures", title_sig, FAIL, "the transaction has no endorsements"))
    elif bad:
        checks.append(("endorse.signatures", title_sig, FAIL, detail))
    elif not verified:
        checks.append(("endorse.signatures", title_sig, SKIP, detail))
    else:
        checks.append(("endorse.signatures", title_sig, PASS, detail))

    # What they signed: the NFT record under its key and the hash index, by the deployments chaincode.
    problems = []
    if signed["chaincode"] != NFT_CHAINCODE:
        problems.append("chaincode %s" % (signed["chaincode"] or "unnamed"))
    if signed["status"] != 200:
        problems.append("chaincode status %s" % signed["status"])
    writes = {key: (value, deleted) for key, value, deleted in signed["writes"].get(NFT_CHAINCODE, [])}
    token_key = fabric_proof.composite_key("deployment", str(record.get("tokenId")))
    hash_key = fabric_proof.composite_key("dephash", str(record.get("deploymentHash")))
    written = writes.get(token_key)
    if written is None or written[1]:
        problems.append("no write of the NFT %s" % record.get("tokenId"))
    else:
        try:
            same = _same_document(json.loads(written[0].decode("utf-8")), record)
        except (ValueError, UnicodeDecodeError):
            same = False
        if not same:
            problems.append("the signed record differs from the record the ledger API returned")
    indexed = writes.get(hash_key)
    if indexed is None or indexed[1] or indexed[0].decode("utf-8", "replace") != record.get("tokenId"):
        problems.append("no hash index %s → %s" % (record.get("deploymentHash"), record.get("tokenId")))
    checks.append(("endorse.writes", title_writes, FAIL if problems else PASS,
                   "; ".join(problems) or "%s writes %s with this record and its hash index" % (NFT_CHAINCODE, record.get("tokenId"))))

    # Policy: SecD plus one other organisation, counting verified signatures only.
    orgs = {e["mspId"] for e in verified}
    witnesses = sorted(orgs.intersection(WITNESS_MSPS))
    if MINTER_MSP in orgs and witnesses:
        checks.append(("endorse.policy", title_policy, PASS, "verified signatures of %s and %s" % (MINTER_MSP, ", ".join(witnesses))))
    elif not bad:
        missing = sorted({e["mspId"] for e in endorsers if (e["problem"] or "").startswith("no pinned CA")})
        note = ("Only %s signed. NFTs minted before the policy change of 2026-11-18 carry SecD's endorsement only, "
                "and SecD also runs Connected Systems." % ", ".join(sorted(orgs)) if orgs else "No signature verified.")
        if missing:
            note += " No CA certificate is pinned for %s: add trust/<mspId>.pem to the plugin." % ", ".join(missing)
        checks.append(("endorse.policy", title_policy, SKIP, note))
    else:
        checks.append(("endorse.policy", title_policy, FAIL, "not every endorsement verifies"))
    return checks


def _instant(text):
    """An aware datetime from an ISO 8601 UTC string such as 2026-11-18T13:00:00.000Z, else None."""
    if not isinstance(text, str):
        return None
    try:
        return datetime.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None


def _cn(subject):
    if not subject:
        return "?"
    for part in subject.split(", "):
        if part.startswith("CN="):
            return part[3:]
    return subject


def _same_document(a, b):
    try:
        return canonical_json(a) == canonical_json(b)
    except (TypeError, ValueError):
        return False


def _check_chain(deployment_id, manifest, items):
    """Checks for L2, plus per item whether its link holds: {id: {anchorHash, ok}}."""
    checks = []
    server = (manifest or {}).get("serverChain")
    server = server if isinstance(server, dict) else {}
    result = {"checks": checks, "items": {}, "head": None, "firstBrokenSeq": None}

    if server.get("alg") != SERVER_CHAIN_ALG:
        checks.append(("chain.manifest", "The manifest fixes a server chain", FAIL,
                       "serverChain.alg is %s, expected %s" % (server.get("alg"), SERVER_CHAIN_ALG)))
        return result
    if server.get("head") is None:
        checks.append(("chain.manifest", "The manifest fixes a server chain", FAIL,
                       "the deployment closed with an incomplete server chain: %s" % (server.get("error") or "no head")))
        return result
    checks.append(("chain.manifest", "The manifest fixes a server chain", PASS,
                   "%s observation(s), head %s" % (server.get("count"), server.get("head"))))

    # Storage order: seq strictly increasing, each observation once.
    seqs = [item.get("seq") for item in items]
    ids = [item.get("id") for item in items]
    ordered = all(isinstance(s, int) for s in seqs) and all(a < b for a, b in zip(seqs, seqs[1:]))
    unique = len(set(ids)) == len(ids)
    checks.append(("chain.order", "The lineage is in storage order", PASS if ordered and unique else FAIL,
                   "" if ordered and unique else ("seq is not strictly increasing" if not ordered else "an observation appears twice")))

    # Recompute from the genesis, and check each stored link on its own so a
    # changed observation is named even though everything after it differs too.
    head = server_genesis(deployment_id)
    stored_previous = head.hex()
    broken = []
    for item in items:
        anchor = item.get("anchorHash")
        link = None
        if _is_hex32(stored_previous):
            try:
                link = server_step(bytes.fromhex(stored_previous), anchor).hex()
            except ValueError:
                link = None
        if head is not None:
            try:
                head = server_step(head, anchor)
            except ValueError:
                head = None  # a malformed anchor: the head cannot be recomputed
        ok = link is not None and link == item.get("chainHash")
        if not ok:
            broken.append(item.get("seq"))
        result["items"][_int_id(item.get("id"))] = {"anchorHash": anchor, "ok": ok}
        stored_previous = item.get("chainHash") if isinstance(item.get("chainHash"), str) else ""
    computed_head = head.hex() if head is not None else None
    result["head"] = computed_head
    result["firstBrokenSeq"] = broken[0] if broken else None

    checks.append(("chain.links", "Each stored chain value follows from the one before", PASS if not broken else FAIL,
                   "" if not broken else "%d broken link(s), first at seq %s" % (len(broken), broken[0])))
    count_ok = len(items) == server.get("count")
    checks.append(("chain.count", "The lineage has as many observations as the manifest", PASS if count_ok else FAIL,
                   "lineage %d, manifest %s" % (len(items), server.get("count"))))
    head_ok = computed_head is not None and computed_head == server.get("head")
    checks.append(("chain.head", "The recomputed chain head is the head on the ledger", PASS if head_ok else FAIL,
                   "computed %s, manifest %s" % (computed_head, server.get("head"))))
    return result


def _is_hex32(value):
    try:
        _hex32(value, "chainHash")
        return True
    except ValueError:
        return False


def _worse(a, b):
    if a is None:
        return b
    return a if _OBS_RANK.index(a) <= _OBS_RANK.index(b) else b


def _observation_status(observations, items, flagged=None):
    """The status of each observation on the map: its place in the lineage, then the lineage-level flags."""
    flagged = flagged or {}
    status = {}
    for obs_id, obs in observations.items():
        key = _int_id(obs_id)
        item = items.get(key)
        if item is None:
            status[obs_id] = OBS_MISSING
        elif (obs or {}).get("anchorHash") not in (None, "", item["anchorHash"]):
            status[obs_id] = OBS_ANCHOR
        else:
            status[obs_id] = flagged.get(key, OBS_OK)
    return status


# ── L3: drone chain ──────────────────────────────────────────────────────────

def _check_drone(deployment_id, manifest, items, seal):
    """Checks for L3, plus {flags: {id: status}, digests: {id: (claim, hex)}, segments, signed}."""
    checks = []
    flags = {}
    digests = {}
    out = {"checks": checks, "flags": flags, "digests": digests, "segments": None, "signed": 0}
    manifest = manifest or {}
    recorded = manifest.get("droneChain")
    cnf = manifest.get("cnfJkt")

    with_proof = [item for item in items if item.get("proof")]
    if not with_proof:
        if recorded is None and seal is None:
            checks.append(("drone.chain", "The gateway signed a drone chain", SKIP,
                           "The manifest has no drone chain and no observation carries a stored proof: the gateway's "
                           "firmware predates the drone-chain claims, so only the server's order is on the ledger."))
        else:
            checks.append(("drone.signatures", "Every observation carries a valid ES256 proof by the drone key", SKIP,
                           "Connected Systems returned no stored proofs, so the drone chain the manifest records cannot be "
                           "recomputed."))
        return out

    bad_sig, bad_key, wrong_dep, bad_link, unsigned, unchained = [], [], [], [], [], []
    rows = []
    for item in items:
        obs_id = _int_id(item.get("id"))
        if not item.get("proof"):
            unsigned.append(item.get("seq"))
            flags[obs_id] = OBS_PROOF
            continue
        proof = drone_chain.read_proof(item["proof"])
        if not proof["ok"]:
            bad_sig.append("seq %s: %s" % (item.get("seq"), proof["error"]))
            flags[obs_id] = OBS_PROOF
            continue
        out["signed"] += 1
        claims = proof["claims"]
        if proof["jkt"] != cnf:
            bad_key.append(item.get("seq"))
            flags[obs_id] = OBS_PROOF
        if claims.get("deployment") is not None and claims.get("deployment") != deployment_id:
            wrong_dep.append(item.get("seq"))
            flags[obs_id] = OBS_PROOF
        for name in ("imgh", "plh"):
            if isinstance(claims.get(name), str):
                try:
                    digests[obs_id] = (name, drone_chain.b64url(claims[name], 32, name).hex())
                except drone_chain.ChainError:
                    pass
                break
        try:
            parsed = drone_chain.chain_claims(claims)
        except drone_chain.ChainError as err:
            bad_link.append("seq %s: %s" % (item.get("seq"), err))
            flags[obs_id] = OBS_PROOF
            continue
        if parsed is None:
            unchained.append(item.get("seq"))
            if item.get("droneN") is not None:
                bad_link.append("seq %s: stored n %s without drone-chain claims" % (item.get("seq"), item.get("droneN")))
                flags[obs_id] = OBS_PROOF
            continue
        boot, n, prev, digest, _ = parsed
        link_hex = drone_chain.link(prev, digest).hex()
        stored = (item.get("droneBoot"), item.get("droneN"), item.get("dronePrev"), item.get("droneLink"))
        if stored != (boot, n, prev.hex(), link_hex):
            bad_link.append("seq %s" % item.get("seq"))
            flags[obs_id] = OBS_PROOF
        rows.append({"seq": item.get("seq"), "boot": boot, "n": n, "prev": prev.hex(), "link": link_hex})

    problems = []
    if unsigned:
        problems.append("%d observation(s) without a proof (seq %s)" % (len(unsigned), _short_list(unsigned)))
    if bad_sig:
        problems.append("%d proof(s) that do not verify (%s)" % (len(bad_sig), _short_list(bad_sig)))
    checks.append(("drone.signatures", "Every observation carries a valid ES256 proof", FAIL if problems else PASS,
                   "; ".join(problems) or "%d proof(s) verified" % out["signed"]))
    checks.append(("drone.key", "Every proof is signed by the drone key the ledger fixed (cnfJkt)", FAIL if bad_key else PASS,
                   "%d proof(s) by another key (seq %s)" % (len(bad_key), _short_list(bad_key)) if bad_key else "cnfJkt %s" % cnf))
    checks.append(("drone.deployment", "Every proof names this deployment", FAIL if wrong_dep else PASS,
                   "%d proof(s) for another deployment (seq %s)" % (len(wrong_dep), _short_list(wrong_dep)) if wrong_dep else ""))

    if recorded is None and not rows and seal is None:
        checks.append(("drone.chain", "The gateway signed a drone chain", SKIP,
                       "The proofs carry no drone-chain claims (older firmware): the drone signed each observation, "
                       "but not their order or completeness."))
        return out

    checks.append(("drone.links", "The stored drone-chain columns follow from the signed claims", FAIL if bad_link else PASS,
                   "%d mismatched (%s)" % (len(bad_link), _short_list(bad_link)) if bad_link else
                   "%d link(s) recomputed" % len(rows)))
    if unchained:
        checks.append(("drone.unchained", "Proofs without drone-chain claims", INFO,
                       "%d proof(s) carry no boot, n and prev (seq %s)" % (len(unchained), _short_list(unchained)), False))

    # The seal.
    seal_ref = None
    if seal is not None:
        seal_ref, seal_problems = _check_seal(deployment_id, seal, cnf, recorded)
        checks.append(("drone.seal", "The gateway's seal is signed by the drone key and is the manifest's",
                       FAIL if seal_problems else PASS,
                       "; ".join(seal_problems) or "sealed at n %s, head %s" % (seal_ref["n"], seal_ref["head"])))
    else:
        recorded_seal = (recorded or {}).get("seal")
        checks.append(("drone.seal", "The gateway's seal is signed by the drone key and is the manifest's",
                       FAIL if recorded_seal else PASS,
                       "the manifest records a seal that Connected Systems did not return" if recorded_seal else
                       "no seal, and the manifest records none"))
    sealed_reason = manifest.get("closeReason") == "sealed"
    checks.append(("drone.close", "The close reason fits the seal", PASS if sealed_reason == (seal is not None) else FAIL,
                   "closeReason %s, %s" % (manifest.get("closeReason"), "sealed" if seal is not None else "no seal")))

    # The segments, recomputed from the proofs.
    seal_end = {"boot": seal_ref["boot"], "n": seal_ref["n"]} if seal_ref and isinstance(seal_ref.get("n"), int) else None
    segments = drone_chain.segment_summary(deployment_id, rows, seal_end)
    out["segments"] = segments
    expected = None if not segments and not seal_ref else segments
    same = _same_document(expected, None if recorded is None else recorded.get("segments"))
    checks.append(("drone.segments", "The segments recomputed from the proofs are the manifest's", PASS if same else FAIL,
                   _segments_text(segments) if same else "recomputed %s; manifest %s" % (
                       _segments_text(segments), _segments_text((recorded or {}).get("segments") or []))))
    broken = [s for s in segments if s["brokenLinks"]]
    checks.append(("drone.broken", "No link of the drone chain is broken", FAIL if broken else PASS,
                   "; ".join("%s: %d broken link(s)" % (s["boot"], s["brokenLinks"]) for s in broken)))

    if seal_end:
        sealed = next((s for s in segments if s["boot"] == seal_end["boot"]), None)
        complete = sealed is not None and not sealed["missing"] and not sealed["brokenLinks"]
        checks.append(("drone.complete", "The sealed segment is complete", PASS if complete else FAIL,
                       "n 1 to %s all received" % sealed["lastN"] if complete else
                       "missing %s" % _ranges_text((sealed or {}).get("missing") or [])))
    else:
        checks.append(("drone.complete", "The sealed segment is complete", SKIP,
                       "The flight closed without a seal (%s): the drone chain shows the gaps it has, but does not prove "
                       "that nothing is missing after its last received link." % manifest.get("closeReason"), False))
    gaps = [s for s in segments if s["missing"] and not (seal_end and s["boot"] == seal_end["boot"])]
    if gaps:
        checks.append(("drone.gaps", "Gaps in unsealed segments", INFO,
                       "; ".join("%s: missing %s" % (s["boot"], _ranges_text(s["missing"])) for s in gaps)
                       + ". The ground module drops observations when its queue is full; the gaps are counted, not recovered.",
                       False))
    if len(segments) > 1:
        checks.append(("drone.reboots", "Segments", INFO,
                       "%d segments (the gateway restarted). Only the last one is sealed: an earlier segment may have lost "
                       "observations at its end without a trace." % len(segments), False))
    return out


def _check_seal(deployment_id, seal, cnf, recorded):
    """(seal reference {boot, n, head, sealHash}, problems) for the lineage's seal {doc, proof}."""
    problems = []
    doc = seal.get("doc")
    try:
        fields = json.loads(doc) if isinstance(doc, str) else None
    except ValueError:
        fields = None
    if not isinstance(fields, dict):
        return None, ["the seal is not a JSON object"]
    if not _same_text(fields, doc):
        problems.append("the seal is not canonical JSON")
    if fields.get("type") != "seal" or fields.get("deployment") != deployment_id:
        problems.append("the seal is not a seal of this deployment")
    try:
        head_hex = drone_chain.b64url(fields.get("head"), 32, "head").hex()
    except drone_chain.ChainError as err:
        head_hex = None
        problems.append("seal %s" % err)
    reference = {"boot": fields.get("boot"), "n": fields.get("n"), "head": head_hex,
                 "sealHash": hashlib.sha256(doc.encode("utf-8")).hexdigest()}
    proof = drone_chain.read_proof(seal.get("proof"))
    if not proof["ok"]:
        problems.append("the seal proof does not verify: %s" % proof["error"])
    else:
        claims = proof["claims"]
        if proof["jkt"] != cnf:
            problems.append("the seal proof is signed by another key")
        if claims.get("plh") != drone_chain.b64url_encode(hashlib.sha256(doc.encode("utf-8")).digest()):
            problems.append("the seal proof's plh does not cover the seal")
        if (claims.get("boot"), claims.get("n"), claims.get("prev")) != (fields.get("boot"), fields.get("n"), fields.get("head")):
            problems.append("the seal proof's boot, n and prev are not the seal's")
    if not _same_document(reference, (recorded or {}).get("seal")):
        problems.append("the manifest records another seal")
    return reference, problems


def _same_text(value, text):
    try:
        return canonical_json(value) == text
    except (TypeError, ValueError):
        return False


def _short_list(values, limit=10):
    values = list(values)
    text = ", ".join(str(v) for v in values[:limit])
    return text + (" …" if len(values) > limit else "")


def _ranges_text(ranges):
    return ", ".join("%s" % a if a == b else "%s–%s" % (a, b) for a, b in ranges) or "none"


def _segments_text(segments):
    if not segments:
        return "no drone chain"
    return "; ".join("%s: %s received of n %s–%s, missing %s, head %s" % (
        s.get("boot"), s.get("received"), s.get("firstN"), s.get("lastN"), _ranges_text(s.get("missing") or []),
        (s.get("head") or "none")[:12]) for s in segments)


# ── L4: content ──────────────────────────────────────────────────────────────

def image_anchor_candidates(deployment_id, result):
    """The documents an image anchor may have been computed over: the served result, and for a picture
    first stored with a local gateway URL, the same result with that URL (Connected Systems now serves
    the public one for the same CID)."""
    docs = [{"deploymentId": deployment_id, "result": result}]
    cid = result.get("cid") if isinstance(result, dict) else None
    if isinstance(cid, str) and cid:
        for gateway in LEGACY_IMAGE_GATEWAYS:
            legacy = dict(result, url="%s/ipfs/%s" % (gateway, cid))
            if legacy != result:
                docs.append({"deploymentId": deployment_id, "result": legacy})
    return docs


def _check_content(deployment_id, items, digests, cs_observations, cs_observations_note, images):
    """Checks for L4, plus {flags, pictures, picturesMatched}."""
    checks = []
    flags = {}
    out = {"checks": checks, "flags": flags, "pictures": 0, "picturesMatched": 0}
    by_id = {_int_id(item.get("id")): item for item in items}

    # Position fixes: did the drone sign exactly the anchored document?
    fixes = [(obs_id, hex_) for obs_id, (claim, hex_) in digests.items() if claim == "plh" and obs_id in by_id]
    if fixes:
        same = sum(1 for obs_id, hex_ in fixes if by_id[obs_id].get("anchorHash") == hex_)
        checks.append(("content.fixes", "Position fixes signed as anchored", INFO,
                       ("%d of %d: the drone's plh is the anchor hash, so its signature covers the anchored document. %s" % (
                           same, len(fixes),
                           "" if same == len(fixes) else "For the others the gateway sent non-canonical JSON: the drone "
                           "signed raw bytes Connected Systems does not keep, and the anchor rests on the server.")).rstrip(),
                       False))

    if cs_observations is None:
        checks.append(("content.pictures", "The pictures are the ones anchored and signed", SKIP,
                       cs_observations_note or "The observations were not read from Connected Systems."))
        return out
    pictures = [f for f in (observation_fields(m) for m in cs_observations) if f and f["kind"] == observation_view.IMAGE]
    out["pictures"] = len(pictures)
    if not pictures:
        checks.append(("content.pictures", "The pictures are the ones anchored and signed", INFO, "The deployment has no pictures.", False))
        return out

    images = images or {}
    anchor_bad, bytes_bad, unread = [], [], []
    for picture in pictures:
        obs_id = _int_id(picture["id"])
        result = picture["result"] if isinstance(picture["result"], dict) else {}
        item = by_id.get(obs_id)
        anchored = item is not None and any(
            _canonical_hash_or_none(doc) == item.get("anchorHash") for doc in image_anchor_candidates(deployment_id, result))
        if not anchored:
            anchor_bad.append(obs_id)
            flags[obs_id] = OBS_CONTENT
        outcome = images.get(obs_id) or {"error": "not read"}
        if "data" not in outcome:
            unread.append("%s: %s" % (obs_id, outcome.get("error")))
            flags[obs_id] = _worse(flags.get(obs_id), OBS_UNREAD)
            continue
        digest = hashlib.sha256(outcome["data"]).hexdigest()
        problems = []
        if result.get("sha256") is not None and digest != result.get("sha256"):
            problems.append("not result.sha256")
        if "body" not in result and result.get("sha256") is None:
            problems.append("no result.sha256")
        signed = digests.get(obs_id)
        if signed is not None and signed[0] == "imgh" and signed[1] != digest:
            problems.append("not the bytes the drone signed (imgh)")
        if problems:
            bytes_bad.append("%s: %s" % (obs_id, ", ".join(problems)))
            flags[obs_id] = _worse(flags.get(obs_id), OBS_IMAGE)
        elif anchored:
            out["picturesMatched"] += 1

    checks.append(("content.anchors", "Each picture's result hashes to its anchor", FAIL if anchor_bad else PASS,
                   "%d of %d differ (observation %s)" % (len(anchor_bad), len(pictures), _short_list(anchor_bad)) if anchor_bad
                   else "%d picture(s)" % len(pictures)))
    unsigned = [p["id"] for p in pictures if (digests.get(_int_id(p["id"])) or ("",))[0] != "imgh"]
    if bytes_bad:
        status, detail = FAIL, "; ".join(bytes_bad[:10]) + (" …" if len(bytes_bad) > 10 else "")
    elif unread:
        status, detail = SKIP, "%d picture(s) could not be read: %s" % (len(unread), "; ".join(unread[:5]))
    else:
        status, detail = PASS, "%d picture(s) downloaded and hashed" % (len(pictures) - len(unread))
    if unsigned and status != FAIL:
        detail += "; %d without a drone imgh to compare with (observation %s)" % (len(unsigned), _short_list(unsigned))
    checks.append(("content.bytes", "The picture bytes hash to result.sha256 and to the drone's imgh", status, detail))
    return out


def _canonical_hash_or_none(doc):
    try:
        return canonical_hash(doc)
    except (TypeError, ValueError):
        return None


def _int_id(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return value


# ── Report ───────────────────────────────────────────────────────────────────

_VERDICT_TEXT = {
    VERIFIED: ("#1a7f37", "Verified against the ledger"),
    FAILED: ("#c62828", "Verification failed"),
    INCOMPLETE: ("#9a6700", "Verification incomplete"),
}
_STATUS_TEXT = {PASS: ("#1a7f37", "✓ pass"), FAIL: ("#c62828", "✗ fail"), SKIP: ("#9a6700", "– skipped"), INFO: ("#57606a", "i info")}
_LEVELS = {0: "L0 Ledger record and endorsements", 1: "L1 Manifest hash", 2: "L2 Server chain", 3: "L3 Drone chain",
           4: "L4 Pictures and content", 5: "L5 Drone identity on Indy"}


def summary_line(report):
    counts = {}
    for status in report["observations"].values():
        counts[status] = counts.get(status, 0) + 1
    text = "%s: %s." % (report["deploymentId"], _VERDICT_TEXT[report["verdict"]][1])
    if counts:
        text += " Observations: " + ", ".join("%d %s" % (n, s) for s, n in sorted(counts.items())) + "."
    return text


def _endorsed_by(facts):
    if facts.get("endorsers"):
        return ", ".join("%s (%s)" % (e["mspId"], "verified" if e["ok"] else "not verified") for e in facts["endorsers"])
    return ", ".join(facts.get("endorsements") or []) or None


def report_html(report, title=None):
    esc = lambda value: html.escape("" if value is None else str(value))  # noqa: E731
    color, verdict = _VERDICT_TEXT[report["verdict"]]
    facts = report["facts"]
    source = facts.get("source") or {}
    parts = [
        "<h3 style='color:%s'>%s</h3>" % (color, esc(verdict)),
        "<p><b>%s</b><br>%s</p>" % (esc(title or report["deploymentId"]), esc(report["deploymentId"])),
        "<table cellspacing='0' cellpadding='3'>",
    ]
    for label, value in (
        ("Deployment hash (ledger)", facts.get("deploymentHash")),
        ("Deployment hash (computed)", facts.get("computedHash")),
        ("Minted", facts.get("mintedAt")),
        ("Transaction", facts.get("txId")),
        ("Block", facts.get("blockNumber")),
        ("Endorsed by", _endorsed_by(facts)),
        ("Ledger read from", "%s (%s), %s" % (source.get("peer"), source.get("mspId"), facts.get("readAt")) if source else None),
        ("Lineage", "%s observation(s), recomputed head %s" % (facts.get("lineageCount"), facts.get("serverHead"))),
        ("Drone DID", facts.get("droneDid")),
        ("Drone key (cnfJkt)", facts.get("cnfJkt")),
        ("Drone verkey (Indy)", facts.get("indyVerkey")),
        ("DPoP key on Indy", _indy_cnf_fact(facts)),
        ("Drone chain", _drone_fact(facts)),
        ("Pictures", "%s of %s match their anchor and the drone's signature" % (facts.get("picturesMatched"), facts.get("pictures"))
         if facts.get("pictures") else None),
    ):
        parts.append("<tr><td><b>%s</b></td><td><code>%s</code></td></tr>" % (esc(label), esc(value if value is not None else "—")))
    parts.append("</table>")

    level = None
    for check in report["checks"]:
        if check["level"] != level:
            if level is not None:
                parts.append("</table>")
            level = check["level"]
            parts.append("<h4>%s</h4><table cellspacing='0' cellpadding='3'>" % esc(_LEVELS.get(level, "L%s" % level)))
        status_color, status_text = _STATUS_TEXT[check["status"]]
        parts.append("<tr><td style='color:%s;white-space:nowrap'>%s</td><td>%s%s</td></tr>" % (
            status_color, esc(status_text), esc(check["title"]),
            "<br><small>%s</small>" % esc(check["detail"]) if check["detail"] else "",
        ))
    if level is not None:
        parts.append("</table>")

    statuses = report["observations"] or facts.get("flagged") or {}
    bad = sorted((oid for oid, s in statuses.items() if s != OBS_OK), key=lambda v: (str(type(v)), v))
    if bad:
        parts.append("<h4>Observations that do not match</h4><p>")
        parts.append(", ".join("%s (%s)" % (esc(oid), esc(statuses[oid])) for oid in bad[:200]))
        if len(bad) > 200:
            parts.append(" … and %d more" % (len(bad) - 200))
        parts.append("</p>")
    reader = "%s (%s)" % (source.get("peer"), source.get("mspId")) if source.get("mspId") else "the ledger API's peer"
    parts.append(
        "<p><small>The ledger is read from %s. The endorsement signatures are checked here against the "
        "CA certificates pinned in the plugin, so a pass means a peer of a second organisation signed this NFT; "
        "that the transaction is valid and in that block is reported by %s. The drone proofs are checked against "
        "the DPoP key the manifest on the ledger fixes (cnfJkt). That this key belongs to the drone's did:indy is "
        "read from the Indy ledger through %s: the cnf ATTRIB the drone wrote on its NYM must name the same key; "
        "the resolver's reading is trusted and the Ed25519 signature on that ATTRIB is not re-checked here. "
        "Pictures are compared by SHA-256 with the bytes the drone "
        "signed; their IPFS CID is not recomputed. A position fix's content is covered when the drone's plh equals "
        "its anchor hash; observations that never reached the server are counted as gaps, not recovered."
        "</small></p>" % (esc(reader), esc(reader), esc(facts.get("indyResolver") or "an Indy resolver"))
    )
    return "".join(parts)


def _indy_cnf_fact(facts):
    cnf = facts.get("indyCnf")
    if not cnf:
        return None
    return "%s (ATTRIB seqNo %s, %s)" % (cnf.get("jkt") or "unusable JWK", cnf.get("seqNo"), cnf.get("txnTime"))


def _drone_fact(facts):
    segments = facts.get("droneSegments")
    if not segments:
        return None
    received = sum(s.get("received") or 0 for s in segments)
    text = "%d segment(s), %d signed link(s) received" % (len(segments), received)
    missing = sum(b - a + 1 for s in segments for a, b in s.get("missing") or [])
    if missing:
        text += ", %d missing" % missing
    return text + (", sealed" if facts.get("sealed") else ", not sealed")
