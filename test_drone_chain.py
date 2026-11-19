import base64
import hashlib
import json
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import drone_chain as dc
import fabric_proof as fp

HERE = Path(__file__).resolve().parent
FIXTURE = json.loads((HERE / "test_fixtures" / "endorsed_mint.json").read_text())
DEPLOYMENT_ID = FIXTURE["record"]["tokenId"]
ITEMS = FIXTURE["lineage"]["items"]


def b64(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


class ProofTests(unittest.TestCase):
    def test_reads_a_stored_proof_and_its_thumbprint_is_the_manifest_cnf(self):
        proof = dc.read_proof(ITEMS[0]["proof"])
        self.assertTrue(proof["ok"], proof["error"])
        self.assertEqual(proof["jkt"], FIXTURE["record"]["manifest"]["cnfJkt"])
        self.assertEqual(dc.jwk_thumbprint(FIXTURE["droneJwk"]), proof["jkt"])
        self.assertEqual(proof["claims"]["deployment"], DEPLOYMENT_ID)

    def test_a_changed_payload_or_signature_does_not_verify(self):
        header, payload, signature = ITEMS[0]["proof"].split(".")
        claims = json.loads(base64.urlsafe_b64decode(payload + "=="))
        claims["n"] = 9
        self.assertFalse(dc.read_proof("%s.%s.%s" % (header, b64(json.dumps(claims).encode()), signature))["ok"])
        raw = bytearray(base64.urlsafe_b64decode(signature + "=="))
        raw[0] ^= 1
        self.assertEqual(dc.read_proof("%s.%s.%s" % (header, payload, b64(bytes(raw))))["error"], "the ES256 signature does not verify")

    def test_refuses_other_algorithms_and_keys(self):
        header, payload, signature = ITEMS[0]["proof"].split(".")
        fields = json.loads(base64.urlsafe_b64decode(header + "=="))
        for change, problem in (({"alg": "none"}, "alg is none"), ({"jwk": dict(fields["jwk"], crv="P-384")}, "not an EC P-256 JWK")):
            forged = b64(json.dumps(dict(fields, **change)).encode())
            self.assertIn(problem, dc.read_proof("%s.%s.%s" % (forged, payload, signature))["error"])
        self.assertEqual(dc.read_proof("a.b")["error"], "not a compact JWS")
        self.assertFalse(dc.read_proof(None)["ok"])

    def test_raw_ecdsa_rejects_a_der_signature_or_wrong_length(self):
        header, payload, signature = ITEMS[0]["proof"].split(".")
        jwk = FIXTURE["droneJwk"]
        key = (int.from_bytes(dc.b64url(jwk["x"], 32), "big"), int.from_bytes(dc.b64url(jwk["y"], 32), "big"))
        raw = dc.b64url(signature, 64)
        message = ("%s.%s" % (header, payload)).encode()
        self.assertTrue(fp.ecdsa_verify_raw(key, message, raw))
        self.assertFalse(fp.ecdsa_verify_raw(key, message, raw[:-1]))
        self.assertFalse(fp.ecdsa_verify_raw(key, message + b"x", raw))


class ClaimTests(unittest.TestCase):
    def test_base64url_must_be_canonical_and_sized(self):
        self.assertEqual(dc.b64url("AAECAwQFBgc", 8), bytes(range(8)))
        for value in ("AAECAwQFBgc=", "AAECAwQFBgd", "AA+CAwQFBgc", 12):
            with self.assertRaises(dc.ChainError):
                dc.b64url(value, 8)
        with self.assertRaises(dc.ChainError):
            dc.b64url("AAECAwQFBgc", 32)

    def test_chain_claims(self):
        prev, digest = b64(b"\x01" * 32), b64(b"\x02" * 32)
        self.assertIsNone(dc.chain_claims({"plh": digest}))
        boot, n, raw_prev, raw_digest, name = dc.chain_claims({"boot": "AAECAwQFBgc", "n": 2, "prev": prev, "imgh": digest})
        self.assertEqual((boot, n, raw_prev, raw_digest, name), ("AAECAwQFBgc", 2, b"\x01" * 32, b"\x02" * 32, "imgh"))
        for claims in ({"boot": "AAECAwQFBgc", "n": 1}, {"boot": "AAECAwQFBgc", "n": 0, "prev": prev, "plh": digest},
                       {"boot": "AAECAwQFBgc", "n": True, "prev": prev, "plh": digest},
                       {"boot": "AAECAwQFBgc", "n": 1, "prev": prev}):
            with self.assertRaises(dc.ChainError):
                dc.chain_claims(claims)

    def test_links_match_the_stored_columns(self):
        for item in ITEMS:
            claims = dc.read_proof(item["proof"])["claims"]
            boot, n, prev, digest, _ = dc.chain_claims(claims)
            self.assertEqual((boot, n, prev.hex(), dc.link(prev, digest).hex()),
                             (item["droneBoot"], item["droneN"], item["dronePrev"], item["droneLink"]))
        self.assertEqual(dc.read_proof(ITEMS[0]["proof"])["claims"]["prev"], b64(dc.genesis(DEPLOYMENT_ID, "AAECAwQFBgc")))


class SegmentTests(unittest.TestCase):
    def test_missing_ranges(self):
        self.assertEqual(dc.missing_ranges([], 0), [])
        self.assertEqual(dc.missing_ranges([], 3), [[1, 3]])
        self.assertEqual(dc.missing_ranges([1, 2, 3], 3), [])
        self.assertEqual(dc.missing_ranges([2, 5, 6], 9), [[1, 1], [3, 4], [7, 9]])
        self.assertEqual(dc.missing_ranges([1, 7], 4), [[2, 4]])

    def test_matches_segment_summary_of_deployment_chain_mjs(self):
        # Expected output from connected-systems/deploymentChain.mjs segmentSummary for the same rows.
        h = lambda c: c * 64  # noqa: E731
        a, b = "AAAAAAAAAAA", "AQEBAQEBAQE"
        g_a = "53f7660115c1acbf18d0d2b57b27627ccb45b6d1d5359a02252f89de0b3d61f4"
        self.assertEqual(dc.genesis("dep-x", a).hex(), g_a)
        rows = [
            {"seq": 1, "boot": a, "n": 1, "prev": g_a, "link": h("1")},
            {"seq": 2, "boot": a, "n": 3, "prev": h("9"), "link": h("3")},
            {"seq": 3, "boot": b, "n": 2, "prev": h("8"), "link": h("b")},
            {"seq": 4, "boot": a, "n": 4, "prev": h("7"), "link": h("4")},
            {"seq": 5, "boot": a, "n": 2, "prev": h("1"), "link": h("2")},
        ]
        self.assertEqual(dc.segment_summary("dep-x", rows, {"boot": a, "n": 7}), [
            {"boot": a, "firstN": 1, "lastN": 6, "received": 4, "missing": [[5, 6]], "brokenLinks": 2, "head": None},
            {"boot": b, "firstN": 2, "lastN": 2, "received": 1, "missing": [[1, 1]], "brokenLinks": 0, "head": h("b")},
        ])

    def test_a_seal_without_observations_is_an_empty_segment_ending_at_the_genesis(self):
        segment = dc.segment_summary("dep-x", [], {"boot": "AAAAAAAAAAA", "n": 1})
        self.assertEqual(segment, [{"boot": "AAAAAAAAAAA", "firstN": None, "lastN": 0, "received": 0, "missing": [],
                                    "brokenLinks": 0, "head": dc.genesis("dep-x", "AAAAAAAAAAA").hex()}])

    def test_a_huge_sequence_number_does_not_stall(self):
        started = time.monotonic()
        segment = dc.segment_summary("dep-x", [{"seq": 1, "boot": "AAAAAAAAAAA", "n": dc.MAX_DRONE_N, "prev": "0" * 64, "link": "1" * 64}])
        self.assertEqual(segment[0]["missing"], [[1, dc.MAX_DRONE_N - 1]])
        self.assertLess(time.monotonic() - started, 1)

    def test_fixture_segments_are_the_manifests(self):
        rows = []
        for item in ITEMS:
            boot, n, prev, digest, _ = dc.chain_claims(dc.read_proof(item["proof"])["claims"])
            rows.append({"seq": item["seq"], "boot": boot, "n": n, "prev": prev.hex(), "link": dc.link(prev, digest).hex()})
        seal = FIXTURE["record"]["manifest"]["droneChain"]["seal"]
        self.assertEqual(dc.segment_summary(DEPLOYMENT_ID, rows, {"boot": seal["boot"], "n": seal["n"]}),
                         FIXTURE["record"]["manifest"]["droneChain"]["segments"])
        self.assertEqual(seal["sealHash"], hashlib.sha256(FIXTURE["lineage"]["seal"]["doc"].encode()).hexdigest())


if __name__ == "__main__":
    unittest.main()
