import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import indy_identity as ii

# What https://resolver.geonft.eu returned on 2026-11-18 for a drone re-enrolled
# with the cnf ATTRIB. The thumbprint was computed by
# indy-jwt.v2/operator-server/scripts/verify-drone-keys.mjs (Node).
DID = "did:indy:sandbox:TCTDGc4ZpkXYWB9kF9fYhF"
VERKEY = "FH9sW5idrRAozWQMoVk6oFb9Ddb7EQxfYtTJuaAEzoZW"
JWK = {"crv": "P-256", "kty": "EC", "x": "pJqVUPIg5aY_aHxYcCHGjOK1tynLr8wcOD0XucWzYno",
       "y": "2CJjP0LNPqxTPgIS_Q6MwBHRa7Wq4B9rJn5xQ_jLLVc"}
JKT = "JBgW1chgLox2bOAv0B69nCuzgYQdCrQ4EIDMIpApzw0"
RESOLVED = {
    "@context": "https://w3id.org/did-resolution/v1",
    "didDocument": {"id": DID, "verificationMethod": [{
        "id": DID + "#verkey", "type": "Ed25519VerificationKey2018", "controller": DID, "publicKeyBase58": VERKEY}],
        "authentication": [DID + "#verkey"]},
    "didDocumentMetadata": {"versionId": "21"},
}
ATTRIBS = {"did": DID, "transactions": [
    {"seqNo": 22, "dest": "TCTDGc4ZpkXYWB9kF9fYhF", "txnTime": "2026-11-14T16:34:18.000Z", "raw": '{"dri":"DEU87astrdge12k8"}'},
    {"seqNo": 23, "dest": "TCTDGc4ZpkXYWB9kF9fYhF", "txnTime": "2026-11-18T18:46:34.000Z", "raw": json.dumps({"cnf": {"jwk": JWK}})},
]}
OTHER_JKT = "8sNi-yreNckztqVHe0DwbLJBia2aHF-zAT99n53PubE"


def identity(attribs=None, document=None):
    return {"resolver": "https://resolver.geonft.eu", "didDocument": document or RESOLVED["didDocument"],
            "attribs": ATTRIBS["transactions"] if attribs is None else attribs}


def manifest(valid_from="2026-11-19T08:00:00.000Z", jkt=JKT, did=DID):
    return {"droneDid": did, "cnfJkt": jkt, "validFrom": valid_from}


def statuses(result):
    return {key: status for key, _title, status, _detail, _required in result["checks"]}


def detail(result, key):
    return [d for k, _t, _s, d, _r in result["checks"] if k == key][0]


class EncodingTests(unittest.TestCase):
    def test_thumbprint_matches_the_node_script(self):
        self.assertEqual(ii.jwk_thumbprint(JWK), JKT)

    def test_the_nym_is_the_first_16_bytes_of_the_verkey(self):
        self.assertEqual(ii.nym_from_verkey(VERKEY), "TCTDGc4ZpkXYWB9kF9fYhF")

    def test_abbreviated_verkey_is_expanded(self):
        raw = ii.b58decode(VERKEY)
        self.assertEqual(ii.full_verkey("TCTDGc4ZpkXYWB9kF9fYhF", "~" + ii.b58encode(raw[16:])), VERKEY)

    def test_base58_round_trips_leading_zeros(self):
        for data in (b"", b"\0", b"\0\0\x01\xff", bytes(range(32))):
            self.assertEqual(ii.b58decode(ii.b58encode(data)), data)

    def test_rejects_a_non_p256_jwk(self):
        with self.assertRaises(ValueError):
            ii.jwk_thumbprint({"kty": "OKP", "crv": "Ed25519", "x": "AAAA"})


class CheckTests(unittest.TestCase):
    def test_the_key_in_force_at_the_flight_passes(self):
        result = ii.check_drone_identity(manifest(), identity())
        self.assertEqual(statuses(result), {"indy.nym": ii.PASS, "indy.cnf": ii.PASS})
        self.assertIn("in force when the flight started", detail(result, "indy.cnf"))
        self.assertEqual((result["verkey"], result["cnf"]["seqNo"]), (VERKEY, 23))

    def test_a_key_published_after_the_flight_passes_and_says_so(self):
        result = ii.check_drone_identity(manifest(valid_from="2026-11-17T08:00:00.000Z"), identity())
        self.assertEqual(statuses(result)["indy.cnf"], ii.PASS)
        self.assertIn("published after this flight started", detail(result, "indy.cnf"))

    def test_another_key_fails(self):
        result = ii.check_drone_identity(manifest(jkt=OTHER_JKT), identity())
        self.assertEqual(statuses(result)["indy.cnf"], ii.FAIL)
        self.assertIn(JKT, detail(result, "indy.cnf"))

    def test_a_key_superseded_before_the_flight_fails(self):
        newer = {"seqNo": 30, "txnTime": "2026-11-18T20:00:00.000Z",
                 "raw": json.dumps({"cnf": {"jwk": dict(JWK, x="AAAA" + JWK["x"][4:])}})}
        result = ii.check_drone_identity(manifest(), identity(ATTRIBS["transactions"] + [newer]))
        self.assertEqual(statuses(result)["indy.cnf"], ii.FAIL)
        self.assertIn("seqNo 30", detail(result, "indy.cnf"))

    def test_no_cnf_attrib_skips_and_is_optional(self):
        result = ii.check_drone_identity(manifest(), identity(ATTRIBS["transactions"][:1]))
        self.assertEqual(statuses(result), {"indy.nym": ii.PASS, "indy.cnf": ii.SKIP})
        self.assertTrue(all(required is False for *_rest, required in result["checks"]))

    def test_a_verkey_that_does_not_derive_the_did_fails(self):
        raw = bytearray(ii.b58decode(VERKEY))
        raw[0] ^= 1
        document = dict(RESOLVED["didDocument"], verificationMethod=[
            dict(RESOLVED["didDocument"]["verificationMethod"][0], publicKeyBase58=ii.b58encode(bytes(raw)))])
        self.assertEqual(statuses(ii.check_drone_identity(manifest(), identity(document=document)))["indy.nym"], ii.FAIL)

    def test_a_document_for_another_did_fails(self):
        document = dict(RESOLVED["didDocument"], id="did:indy:sandbox:JrqC2m6GGcvkQUb7qXQiUV")
        self.assertEqual(statuses(ii.check_drone_identity(manifest(), identity(document=document)))["indy.nym"], ii.FAIL)

    def test_unread_resolver_skips_both(self):
        result = ii.check_drone_identity(manifest(), None, "The Indy resolver could not be read: 503")
        self.assertEqual(statuses(result), {"indy.nym": ii.SKIP, "indy.cnf": ii.SKIP})
        self.assertIn("503", detail(result, "indy.cnf"))

    def test_a_malformed_cnf_attrib_is_not_a_match(self):
        bad = [{"seqNo": 23, "txnTime": "2026-11-18T18:46:34.000Z", "raw": '{"cnf":{"jwk":{"kty":"EC"}}}'}]
        self.assertEqual(statuses(ii.check_drone_identity(manifest(), identity(bad)))["indy.cnf"], ii.FAIL)


class ReadTests(unittest.TestCase):
    def test_reads_the_document_and_the_attribs_without_a_token(self):
        calls = []

        def fetch(url):
            calls.append(url)
            return ATTRIBS if url.endswith("/attribs") else RESOLVED

        got = ii.read_drone_identity("https://resolver.geonft.eu/", DID, fetch)
        self.assertEqual(calls, ["https://resolver.geonft.eu/1.0/identifiers/" + DID,
                                 "https://resolver.geonft.eu/1.0/identifiers/%s/attribs" % DID])
        self.assertEqual(got["didDocument"]["id"], DID)
        self.assertEqual(len(got["attribs"]), 2)

    def test_a_bad_answer_raises(self):
        with self.assertRaises(ii.ResolverError):
            ii.read_drone_identity("https://r", DID, lambda url: {"error": "notFound"} if url.endswith("/attribs") else RESOLVED)

    def test_refuses_non_http_urls(self):
        with self.assertRaises(ii.ResolverError):
            ii.http_get_public_json("file:///etc/passwd")


if __name__ == "__main__":
    unittest.main()
