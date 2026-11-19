"""Check Fabric endorsement signatures without a crypto library.

QGIS ships no Python crypto package, so this module carries what verifying an
endorsement needs, in plain Python:

  - a protobuf wire reader for the few Fabric messages involved;
  - a DER reader for X.509 certificates (P-256 keys, ecdsa-with-SHA256);
  - ECDSA P-256 / SHA-256 signature verification.

A Fabric peer signs proposalResponsePayload || endorser, where endorser is the
SerializedIdentity {mspid, PEM certificate}. The payload carries the chaincode's
read-write set, so a valid signature means that peer ran the chaincode and got
those writes. Only verification happens here, so constant time does not matter.
"""

import base64
import datetime
import hashlib
import re

# ── Protobuf wire format ─────────────────────────────────────────────────────


class ProofError(ValueError):
    pass


def _varint(data, pos):
    result = shift = 0
    while True:
        if pos >= len(data):
            raise ProofError("truncated varint")
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, pos
        shift += 7
        if shift > 63:
            raise ProofError("varint too long")


def pb_fields(data):
    """[(field number, value)] of a protobuf message; length-delimited values are bytes, varints ints."""
    fields = []
    pos = 0
    data = bytes(data)
    while pos < len(data):
        key, pos = _varint(data, pos)
        number, wire = key >> 3, key & 7
        if wire == 0:
            value, pos = _varint(data, pos)
        elif wire == 1:
            value, pos = data[pos:pos + 8], pos + 8
        elif wire == 2:
            length, pos = _varint(data, pos)
            value, pos = data[pos:pos + length], pos + length
        elif wire == 5:
            value, pos = data[pos:pos + 4], pos + 4
        else:
            raise ProofError("unsupported wire type %d" % wire)
        if pos > len(data):
            raise ProofError("truncated field %d" % number)
        fields.append((number, value))
    return fields


def _first(fields, number, default=b""):
    for n, value in fields:
        if n == number:
            return value
    return default


def _all(fields, number):
    return [value for n, value in fields if n == number]


def serialized_identity(data):
    """msp.SerializedIdentity → (mspid, certificate PEM bytes)."""
    fields = pb_fields(data)
    return _first(fields, 1).decode("utf-8", "replace"), bytes(_first(fields, 2))


def chaincode_action(proposal_response_payload):
    """What the endorsers signed: {chaincode, version, status, writes: {namespace: [(key, value, is_delete)]}}."""
    prp = pb_fields(proposal_response_payload)
    action = pb_fields(_first(prp, 2))  # ProposalResponsePayload.extension = ChaincodeAction
    chaincode_id = pb_fields(_first(action, 4))
    response = pb_fields(_first(action, 3))
    writes = {}
    for ns_bytes in _all(pb_fields(_first(action, 1)), 2):  # TxReadWriteSet.ns_rwset
        ns = pb_fields(ns_bytes)
        namespace = _first(ns, 1).decode("utf-8", "replace")
        for write_bytes in _all(pb_fields(_first(ns, 2)), 3):  # KVRWSet.writes
            write = pb_fields(write_bytes)
            writes.setdefault(namespace, []).append(
                (_first(write, 1).decode("utf-8", "replace"), bytes(_first(write, 3)), bool(_first(write, 2, 0))))
    return {
        "chaincode": _first(chaincode_id, 2).decode("utf-8", "replace"),
        "version": _first(chaincode_id, 3).decode("utf-8", "replace"),
        "status": _first(response, 1, 0),
        "writes": writes,
    }


def composite_key(object_type, *attributes):
    """Fabric's createCompositeKey: U+0000 type U+0000 attr U+0000 …"""
    return "\x00" + object_type + "\x00" + "".join(a + "\x00" for a in attributes)


# ── DER / X.509 ──────────────────────────────────────────────────────────────

OID_EC_PUBLIC_KEY = "1.2.840.10045.2.1"
OID_P256 = "1.2.840.10045.3.1.7"
OID_ECDSA_SHA256 = "1.2.840.10045.4.3.2"
OID_CN = "2.5.4.3"
OID_OU = "2.5.4.11"
OID_O = "2.5.4.10"


def _der(data, pos=0):
    """(tag, content start, content end, element end) of the DER element at pos."""
    if pos + 2 > len(data):
        raise ProofError("truncated DER")
    tag = data[pos]
    length = data[pos + 1]
    pos += 2
    if length & 0x80:
        count = length & 0x7F
        if count == 0 or count > 4 or pos + count > len(data):
            raise ProofError("bad DER length")
        length = int.from_bytes(data[pos:pos + count], "big")
        pos += count
    end = pos + length
    if end > len(data):
        raise ProofError("truncated DER")
    return tag, pos, end, end


def _children(data, start, end):
    out = []
    pos = start
    while pos < end:
        tag, cstart, cend, nxt = _der(data, pos)
        out.append((tag, cstart, cend, pos, nxt))
        pos = nxt
    return out


def _oid(raw):
    first = raw[0]
    parts = [first // 40 if first < 80 else 2, first % 40 if first < 80 else first - 80]
    value = 0
    for byte in raw[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(value)
            value = 0
    return ".".join(str(p) for p in parts)


def _time(tag, raw):
    text = raw.decode("ascii")
    if tag == 0x17:  # UTCTime YYMMDDHHMMSSZ
        year = int(text[:2])
        text = ("19" if year >= 50 else "20") + text
    if not re.fullmatch(r"\d{14}Z", text):
        raise ProofError("unsupported certificate time %r" % raw)
    return datetime.datetime.strptime(text, "%Y%m%d%H%M%SZ").replace(tzinfo=datetime.timezone.utc)


def _name(data, start, end):
    """[(oid, text)] of an X.509 Name, in order."""
    out = []
    for _, rs, re_, _, _ in _children(data, start, end):  # SET
        for _, as_, ae, _, _ in _children(data, rs, re_):  # SEQUENCE {oid, value}
            parts = _children(data, as_, ae)
            if len(parts) == 2:
                out.append((_oid(data[parts[0][1]:parts[0][2]]), data[parts[1][1]:parts[1][2]].decode("utf-8", "replace")))
    return out


def pem_certificates(text):
    """DER bytes of every CERTIFICATE block in a PEM string or bytes."""
    if isinstance(text, bytes):
        text = text.decode("ascii", "replace")
    blocks = re.findall(r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", text, re.S)
    return [base64.b64decode("".join(block.split())) for block in blocks]


class Certificate:
    """The parts of an X.509 certificate that endorsement checks use."""

    def __init__(self, der):
        self.der = der = bytes(der)
        _, s, e, _ = _der(der)
        top = _children(der, s, e)
        if len(top) != 3:
            raise ProofError("not an X.509 certificate")
        tbs, alg, sig = top
        self.tbs = der[tbs[3]:tbs[4]]
        self.signature_alg = _oid(der[_children(der, alg[1], alg[2])[0][1]:_children(der, alg[1], alg[2])[0][2]])
        if der[sig[1]] != 0:
            raise ProofError("certificate signature has unused bits")
        self.signature = der[sig[1] + 1:sig[2]]

        fields = _children(der, tbs[1], tbs[2])
        if fields and fields[0][0] == 0xA0:  # [0] version
            fields = fields[1:]
        _serial, _sigalg, issuer, validity, subject, spki = fields[:6]
        self.issuer_der = der[issuer[3]:issuer[4]]
        self.subject_der = der[subject[3]:subject[4]]
        self.issuer = _name(der, issuer[1], issuer[2])
        self.subject = _name(der, subject[1], subject[2])
        times = _children(der, validity[1], validity[2])
        self.not_before = _time(times[0][0], der[times[0][1]:times[0][2]])
        self.not_after = _time(times[1][0], der[times[1][1]:times[1][2]])

        alg_id, key_bits = _children(der, spki[1], spki[2])
        alg_parts = _children(der, alg_id[1], alg_id[2])
        key_alg = _oid(der[alg_parts[0][1]:alg_parts[0][2]])
        curve = _oid(der[alg_parts[1][1]:alg_parts[1][2]]) if len(alg_parts) > 1 and alg_parts[1][0] == 0x06 else None
        if key_alg != OID_EC_PUBLIC_KEY or curve != OID_P256:
            raise ProofError("only P-256 keys are supported")
        point = der[key_bits[1] + 1:key_bits[2]]
        if len(point) != 65 or point[0] != 4:
            raise ProofError("expected an uncompressed P-256 point")
        self.public_key = (int.from_bytes(point[1:33], "big"), int.from_bytes(point[33:], "big"))

    def attribute(self, oid):
        return [value for key, value in self.subject if key == oid]

    @property
    def common_name(self):
        names = self.attribute(OID_CN)
        return names[0] if names else None

    @property
    def subject_text(self):
        labels = {OID_CN: "CN", OID_OU: "OU", OID_O: "O", "2.5.4.6": "C", "2.5.4.8": "ST", "2.5.4.7": "L"}
        return ", ".join("%s=%s" % (labels.get(k, k), v) for k, v in self.subject)

    def issued_by(self, ca):
        """True when ca's key signed this certificate and the issuer name is ca's subject."""
        return (self.issuer_der == ca.subject_der and self.signature_alg == OID_ECDSA_SHA256
                and ecdsa_verify(ca.public_key, self.tbs, self.signature))


# ── ECDSA P-256 ──────────────────────────────────────────────────────────────

_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
_A = _P - 3
_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
_G = (0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
      0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5)


def _on_curve(point):
    x, y = point
    return 0 <= x < _P and 0 <= y < _P and (y * y - (x * x * x + _A * x + _B)) % _P == 0


def _jdouble(p):
    x, y, z = p
    if y == 0 or z == 0:
        return (0, 1, 0)
    ysq = y * y % _P
    s = 4 * x * ysq % _P
    zsq = z * z % _P
    m = 3 * (x - zsq) * (x + zsq) % _P  # a = -3
    nx = (m * m - 2 * s) % _P
    ny = (m * (s - nx) - 8 * ysq * ysq) % _P
    nz = 2 * y * z % _P
    return (nx, ny, nz)


def _jadd(p, q):
    if p[2] == 0:
        return q
    if q[2] == 0:
        return p
    x1, y1, z1 = p
    x2, y2, z2 = q
    z1sq, z2sq = z1 * z1 % _P, z2 * z2 % _P
    u1, u2 = x1 * z2sq % _P, x2 * z1sq % _P
    s1, s2 = y1 * z2sq * z2 % _P, y2 * z1sq * z1 % _P
    if u1 == u2:
        return _jdouble(p) if s1 == s2 else (0, 1, 0)
    h, r = (u2 - u1) % _P, (s2 - s1) % _P
    hsq = h * h % _P
    hcu = hsq * h % _P
    nx = (r * r - hcu - 2 * u1 * hsq) % _P
    ny = (r * (u1 * hsq - nx) - s1 * hcu) % _P
    nz = h * z1 * z2 % _P
    return (nx, ny, nz)


def _shamir(k1, p1, k2, p2):
    """k1·P1 + k2·P2 in one double-and-add pass."""
    j1, j2 = (p1[0], p1[1], 1), (p2[0], p2[1], 1)
    both = _jadd(j1, j2)
    acc = (0, 1, 0)
    for bit in range(max(k1.bit_length(), k2.bit_length()) - 1, -1, -1):
        acc = _jdouble(acc)
        b1, b2 = (k1 >> bit) & 1, (k2 >> bit) & 1
        if b1 and b2:
            acc = _jadd(acc, both)
        elif b1:
            acc = _jadd(acc, j1)
        elif b2:
            acc = _jadd(acc, j2)
    return acc


def _der_signature(sig):
    """(r, s) of a DER ECDSA-Sig-Value."""
    sig = bytes(sig)
    tag, s, e, end = _der(sig)
    parts = _children(sig, s, e)
    if tag != 0x30 or end != len(sig) or len(parts) != 2 or any(p[0] != 0x02 for p in parts):
        raise ProofError("not a DER ECDSA signature")
    return tuple(int.from_bytes(sig[p[1]:p[2]], "big") for p in parts)


def ecdsa_verify(public_key, message, signature):
    """ECDSA P-256 with SHA-256 over message; signature is DER. False on any malformed input."""
    try:
        r, s = _der_signature(signature)
    except ProofError:
        return False
    return _ecdsa_verify_rs(public_key, message, r, s)


def ecdsa_verify_raw(public_key, message, signature):
    """ECDSA P-256 with SHA-256; signature is r ‖ s, 32 bytes each (JWS ES256). False on any malformed input."""
    signature = bytes(signature)
    if len(signature) != 64:
        return False
    return _ecdsa_verify_rs(public_key, message, int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big"))


def _ecdsa_verify_rs(public_key, message, r, s):
    if not (1 <= r < _N and 1 <= s < _N) or not _on_curve(public_key):
        return False
    e = int.from_bytes(hashlib.sha256(bytes(message)).digest(), "big")
    w = pow(s, -1, _N)
    x, _, z = _shamir(e * w % _N, _G, r * w % _N, public_key)
    if z == 0:
        return False
    return (x * pow(z * z, -1, _P) % _P) % _N == r


# ── Endorsements ─────────────────────────────────────────────────────────────

def load_trust(pems):
    """{mspId: [Certificate]} from {mspId: PEM text with one or more CA certificates}."""
    trust = {}
    for msp_id, text in (pems or {}).items():
        certs = []
        for der in pem_certificates(text):
            certs.append(Certificate(der))
        if certs:
            trust[msp_id] = certs
    return trust


def check_endorsement(prp, endorsement, trust, at=None, role="peer"):
    """Verify one endorsement {endorser, signature} (base64) over the payload prp (bytes).

    Returns {mspId, subject, ok, problem}. ok means: the signature is valid for the
    endorser's certificate, the certificate was issued by a pinned CA of the MSP it
    names, carries OU=<role>, and was valid at `at` (an aware datetime) when given.
    """
    result = {"mspId": None, "subject": None, "ok": False, "problem": None}
    try:
        endorser = base64.b64decode(endorsement.get("endorser") or "", validate=True)
        signature = base64.b64decode(endorsement.get("signature") or "", validate=True)
        msp_id, pem = serialized_identity(endorser)
        result["mspId"] = msp_id
        ders = pem_certificates(pem)
        if not ders:
            raise ProofError("the endorser has no certificate")
        cert = Certificate(ders[0])
        result["subject"] = cert.subject_text
    except (ProofError, ValueError, IndexError, TypeError) as err:
        result["problem"] = "unreadable endorsement: %s" % err
        return result

    cas = trust.get(msp_id)
    if not cas:
        result["problem"] = "no pinned CA for %s" % msp_id
        return result
    if not any(cert.issued_by(ca) for ca in cas):
        result["problem"] = "certificate not issued by the pinned %s CA" % msp_id
        return result
    if role and role not in cert.attribute(OID_OU):
        result["problem"] = "not a %s certificate (OU %s)" % (role, ", ".join(cert.attribute(OID_OU)) or "none")
        return result
    if at is not None and not (cert.not_before <= at <= cert.not_after):
        result["problem"] = "certificate not valid at %s" % at.isoformat()
        return result
    if not ecdsa_verify(cert.public_key, bytes(prp) + endorser, signature):
        result["problem"] = "signature does not verify"
        return result
    result["ok"] = True
    return result
