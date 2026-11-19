import base64
import copy
import hashlib
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import cs_api
import deployment_verify as dv

# Test manifest from indy-jwt.v2/docs/fabric-deployment-nft.md. Its server chain
# is the chain over the anchors 11…11 and 22…22 (values from deploymentChain.mjs).
DEPLOYMENT_ID = "dep-0bbec562-1526-516f-b2e5-eb6f03023f0d"
MANIFEST = {
    "v": 1,
    "deploymentId": DEPLOYMENT_ID,
    "systemId": "sys-5f2c",
    "droneDid": "did:indy:sandbox:JrqC2m6GGcvkQUb7qXQiUV",
    "cnfJkt": "kQ9w3lq5oCH2bXaKZ1u2yT0hYV3x5Vd8mN1p0r4sT6E",
    "operator": "urn:ogc:feature:operator:op-zek6yrf5",
    "validFrom": "2026-11-17T08:00:00.000Z",
    "validTo": "2026-11-17T09:00:00.000Z",
    "closeReason": "sealed",
    "serverChain": {
        "alg": "tcs-deployment-chain-v1",
        "count": 2,
        "head": "90d281e2ef0554baa20bd735e16a95b313b7d02817115c1281d15ddf295077c1",
    },
    "droneChain": {
        "alg": "tcs-drone-chain-v1",
        "segments": [{
            "boot": "AAECAwQFBgc", "firstN": 1, "lastN": 2, "received": 2, "missing": [], "brokenLinks": 0,
            "head": "3333333333333333333333333333333333333333333333333333333333333333",
        }],
        "seal": {
            "boot": "AAECAwQFBgc", "n": 3,
            "head": "3333333333333333333333333333333333333333333333333333333333333333",
            "sealHash": "4444444444444444444444444444444444444444444444444444444444444444",
        },
    },
}
MANIFEST_HASH = "5cff4eb4aaba1af24ce70bdc99bfe0d4cdd955a6ce5395e0e8169d89932e7663"
CANONICAL = (
    '{"closeReason":"sealed","cnfJkt":"kQ9w3lq5oCH2bXaKZ1u2yT0hYV3x5Vd8mN1p0r4sT6E","deploymentId":"dep-0bbec562-1526-516f-b2e5-eb6f03023f0d",'
    '"droneChain":{"alg":"tcs-drone-chain-v1","seal":{"boot":"AAECAwQFBgc","head":"3333333333333333333333333333333333333333333333333333333333333333",'
    '"n":3,"sealHash":"4444444444444444444444444444444444444444444444444444444444444444"},"segments":[{"boot":"AAECAwQFBgc","brokenLinks":0,"firstN":1,'
    '"head":"3333333333333333333333333333333333333333333333333333333333333333","lastN":2,"missing":[],"received":2}]},'
    '"droneDid":"did:indy:sandbox:JrqC2m6GGcvkQUb7qXQiUV","operator":"urn:ogc:feature:operator:op-zek6yrf5",'
    '"serverChain":{"alg":"tcs-deployment-chain-v1","count":2,"head":"90d281e2ef0554baa20bd735e16a95b313b7d02817115c1281d15ddf295077c1"},'
    '"systemId":"sys-5f2c","v":1,"validFrom":"2026-11-17T08:00:00.000Z","validTo":"2026-11-17T09:00:00.000Z"}'
)

A1, A2, A3 = "11" * 32, "22" * 32, "33" * 32
GENESIS = "c1caa504dd2bcd71b424a234ea120cbec863c31ec2cbbcb82f1d4d2cf2f3563a"
S1 = "048607314198521af75d6a0fcf246ab10a9e823b4381707a09d7ae717991a149"
S2 = "90d281e2ef0554baa20bd735e16a95b313b7d02817115c1281d15ddf295077c1"
S3 = "860f1f43e44c83ed32066483ac30ec83e70955f2e97585ec1b790f6f120b094b"

# A closed, sealed deployment and its MintDeployment transaction signed by SecdMSP
# and GeoidworksMSP test peers, with the lineage, observations and picture:
# throwaway keys from test_fixtures/make_fixture.mjs. Server order seq 1, 2, 3 is
# fix (n 1), fix (n 3), picture (n 2); the seal is n 4.
FIXTURE = json.loads((Path(__file__).resolve().parent / "test_fixtures" / "endorsed_mint.json").read_text())
TRUST = dv.fabric_proof.load_trust(FIXTURE["trust"])
F_MANIFEST = FIXTURE["record"]["manifest"]
F_HASH = FIXTURE["record"]["deploymentHash"]
FIX1, FIX2, PICTURE = (item["id"] for item in FIXTURE["lineage"]["items"])
PICTURE_URL = next(iter(FIXTURE["images"]))
PICTURE_BYTES = base64.b64decode(FIXTURE["images"][PICTURE_URL])


def lineage():
    return copy.deepcopy(FIXTURE["lineage"])


def cs_observations():
    return copy.deepcopy(FIXTURE["observations"])


def images(data=PICTURE_BYTES):
    return {PICTURE: {"data": data}}


def ledger_doc(**changes):
    doc = {
        "deploymentId": DEPLOYMENT_ID,
        "record": copy.deepcopy(FIXTURE["record"]),
        "transaction": copy.deepcopy(FIXTURE["transaction"]),
        "source": {"peer": "peer0.4113engineering.eu:7051", "mspId": "EngineeringMSP", "channel": "geonftchannel", "chaincode": "deployments"},
        "readAt": "2027-01-15T10:00:00.000Z",
    }
    doc.update(changes)
    return doc


def with_manifest(change):
    """A ledger document whose manifest change() edited, with a matching hash (the signed writes no longer match)."""
    doc = ledger_doc()
    change(doc["record"]["manifest"])
    doc["record"]["deploymentHash"] = dv.canonical_hash(doc["record"]["manifest"])
    return doc


def endorsed_by(*names):
    doc = ledger_doc()
    doc["transaction"]["endorsedAction"]["endorsements"] = [copy.deepcopy(FIXTURE["endorsements"][n]) for n in names]
    return doc


def drone_identity(cnf_jwk=None, cnf_time="2026-11-14T16:34:18.000Z"):
    """What the Indy resolver returns for the fixture drone: a verkey whose first 16 bytes are the DID id,
    and a cnf ATTRIB with the fixture's DPoP key, published before the flight."""
    did = F_MANIFEST["droneDid"]
    nym = did.rsplit(":", 1)[-1]
    verkey = dv.indy_identity.b58encode(dv.indy_identity.b58decode(nym) + bytes(range(16)))
    attribs = [{"seqNo": 22, "dest": nym, "txnTime": "2026-11-14T16:34:17.000Z", "raw": '{"dri":"SN12345"}'}]
    if cnf_jwk is not False:
        attribs.append({"seqNo": 23, "dest": nym, "txnTime": cnf_time,
                        "raw": json.dumps({"cnf": {"jwk": cnf_jwk or FIXTURE["droneJwk"]}})})
    return {
        "resolver": "https://resolver.test",
        "didDocument": {"id": did, "verificationMethod": [
            {"id": did + "#verkey", "type": "Ed25519VerificationKey2018", "controller": did, "publicKeyBase58": verkey}]},
        "attribs": attribs,
    }


def verify(*args, **kwargs):
    kwargs.setdefault("trust", TRUST)
    kwargs.setdefault("cs_observations", cs_observations())
    kwargs.setdefault("images", images())
    kwargs.setdefault("indy", drone_identity())
    return dv.verify_deployment(*args, **kwargs)


def statuses(report):
    return {check["key"]: check["status"] for check in report["checks"]}


def detail(report, key):
    return [c for c in report["checks"] if c["key"] == key][0]["detail"]


def map_observations():
    return {str(o["id"]): {"anchorHash": o["anchorHash"], "chainHash": o["chainHash"]} for o in FIXTURE["observations"]}


class CanonicalJsonTests(unittest.TestCase):
    def test_documented_manifest_gives_the_documented_bytes_and_hash(self):
        self.assertEqual(dv.canonical_json(MANIFEST), CANONICAL)
        self.assertEqual(dv.canonical_hash(MANIFEST), MANIFEST_HASH)

    def test_numbers_follow_ecmascript_like_canonicalize(self):
        # Expected strings from the canonicalize package used by Connected Systems and the chaincode.
        cases = [
            (0, "0"), (-0.0, "0"), (1e21, "1e+21"), (1e-7, "1e-7"), (0.000001, "0.000001"),
            (123456789012345680000.0, "123456789012345680000"), (5e-324, "5e-324"),
            (1.7976931348623157e308, "1.7976931348623157e+308"), (333333333.3333333, "333333333.3333333"),
            (1e23, "1e+23"), (4.5, "4.5"), (0.1, "0.1"), (-1.5e-9, "-1.5e-9"), (9007199254740993, "9007199254740992"),
            (2.0, "2"), (100, "100"),
        ]
        for value, expected in cases:
            self.assertEqual(dv.canonical_json(value), expected, value)
        with self.assertRaises(ValueError):
            dv.canonical_json(float("nan"))

    def test_keys_sort_by_utf16_code_units_and_strings_escape_like_json_stringify(self):
        keys = {"\u20ac": 1, "\r": 2, "\ufb33": 3, "1": 4, "\U0001F600": 5, "\u0080": 6, "\u00f6": 7}
        self.assertEqual(dv.canonical_json(keys), '{"\\r":2,"1":4,"\u0080":6,"\u00f6":7,"\u20ac":1,"\U0001F600":5,"\ufb33":3}')
        text = "\u000f\u001f\b\t\n\f\r\"\\/\u007f\u00e9\u2028"
        self.assertEqual(dv.canonical_json({"s": text}), '{"s":"\\u000f\\u001f\\b\\t\\n\\f\\r\\"\\\\/\u007f\u00e9\u2028"}')
        self.assertEqual(dv.canonical_json([True, False, None, [], {}]), "[true,false,null,[],{}]")


class ServerChainTests(unittest.TestCase):
    def test_matches_deployment_chain_mjs(self):
        self.assertEqual(dv.server_genesis(DEPLOYMENT_ID).hex(), GENESIS)
        self.assertEqual(dv.server_chain(DEPLOYMENT_ID, []), GENESIS)
        self.assertEqual(dv.server_chain(DEPLOYMENT_ID, [A1]), S1)
        self.assertEqual(dv.server_chain(DEPLOYMENT_ID, [A1, A2]), S2)
        self.assertEqual(dv.server_chain(DEPLOYMENT_ID, [A1, A2, A3]), S3)

    def test_rejects_malformed_anchor(self):
        with self.assertRaises(ValueError):
            dv.server_chain(DEPLOYMENT_ID, ["AB" * 32])
        with self.assertRaises(ValueError):
            dv.server_chain(DEPLOYMENT_ID, ["11" * 31])


class VerifyTests(unittest.TestCase):
    def test_untouched_deployment_verifies(self):
        report = verify(DEPLOYMENT_ID, ledger_doc(), lineage(), copy.deepcopy(F_MANIFEST), None, map_observations())
        self.assertEqual(report["verdict"], dv.VERIFIED, report["checks"])
        self.assertEqual(set(statuses(report).values()) - {dv.INFO}, {dv.PASS})
        self.assertEqual(report["observations"], {str(FIX1): dv.OBS_OK, str(FIX2): dv.OBS_OK, str(PICTURE): dv.OBS_OK})
        self.assertEqual(report["facts"]["computedHash"], F_HASH)
        self.assertEqual(report["facts"]["serverHead"], F_MANIFEST["serverChain"]["head"])
        self.assertEqual(report["facts"]["endorsements"], ["SecdMSP", "GeoidworksMSP"])
        self.assertEqual([(e["mspId"], e["ok"]) for e in report["facts"]["endorsers"]], [("SecdMSP", True), ("GeoidworksMSP", True)])
        self.assertEqual(report["facts"]["droneSegments"], F_MANIFEST["droneChain"]["segments"])
        self.assertEqual((report["facts"]["pictures"], report["facts"]["picturesMatched"]), (1, 1))
        self.assertEqual(report["facts"]["flagged"], {})
        self.assertEqual({c["level"] for c in report["checks"]}, {0, 1, 2, 3, 4, 5})
        self.assertEqual(report["facts"]["indyCnf"]["jkt"], F_MANIFEST["cnfJkt"])

    def test_without_the_cs_manifest_it_still_verifies(self):
        report = verify(DEPLOYMENT_ID, ledger_doc(), lineage(), None, "Connected Systems does not serve the manifest to this account (403).")
        self.assertEqual(report["verdict"], dv.VERIFIED)
        self.assertEqual(statuses(report)["manifest.cs"], dv.SKIP)

    def test_a_changed_anchor_names_the_observation(self):
        lin = lineage()
        lin["items"][0]["anchorHash"] = A3
        report = verify(DEPLOYMENT_ID, ledger_doc(), lin, observations=map_observations())
        self.assertEqual(report["verdict"], dv.FAILED)
        s = statuses(report)
        self.assertEqual(s["chain.links"], dv.FAIL)
        self.assertEqual(s["chain.head"], dv.FAIL)
        self.assertEqual(report["facts"]["firstBrokenSeq"], 1)
        self.assertEqual(report["observations"][str(FIX1)], dv.OBS_ANCHOR)
        # The second link still follows from the stored first one.
        self.assertEqual(report["observations"][str(FIX2)], dv.OBS_OK)

    def test_a_rewritten_chain_is_caught_by_the_head_on_the_ledger(self):
        # Anchor and stored chain value both changed consistently: every link holds, the head does not.
        items = [
            {"seq": 1, "id": 1, "anchorHash": A3, "chainHash": dv.server_chain(DEPLOYMENT_ID, [A3])},
            {"seq": 2, "id": 2, "anchorHash": A2, "chainHash": dv.server_chain(DEPLOYMENT_ID, [A3, A2])},
            {"seq": 3, "id": 3, "anchorHash": A1, "chainHash": dv.server_chain(DEPLOYMENT_ID, [A3, A2, A1])},
        ]
        s = statuses(verify(DEPLOYMENT_ID, ledger_doc(), items))
        self.assertEqual(s["chain.links"], dv.PASS)
        self.assertEqual(s["chain.count"], dv.PASS)
        self.assertEqual(s["chain.head"], dv.FAIL)

    def test_a_removed_observation_fails_count_and_head(self):
        lin = lineage()
        lin["items"] = lin["items"][:1]
        report = verify(DEPLOYMENT_ID, ledger_doc(), lin, observations=map_observations())
        s = statuses(report)
        self.assertEqual(s["chain.count"], dv.FAIL)
        self.assertEqual(s["chain.head"], dv.FAIL)
        self.assertEqual(report["observations"][str(FIX2)], dv.OBS_MISSING)

    def test_out_of_order_lineage_fails(self):
        lin = lineage()
        lin["items"].reverse()
        self.assertEqual(statuses(verify(DEPLOYMENT_ID, ledger_doc(), lin))["chain.order"], dv.FAIL)

    def test_ledger_hash_that_does_not_match_the_manifest_fails(self):
        doc = ledger_doc()
        doc["record"]["deploymentHash"] = "0" * 64
        report = verify(DEPLOYMENT_ID, doc, lineage())
        self.assertEqual(statuses(report)["manifest.hash"], dv.FAIL)
        self.assertEqual(report["verdict"], dv.FAILED)

    def test_cs_serving_another_manifest_fails(self):
        changed = copy.deepcopy(F_MANIFEST)
        changed["closeReason"] = "operator-forced-unsealed"
        report = verify(DEPLOYMENT_ID, ledger_doc(), lineage(), changed)
        self.assertEqual(statuses(report)["manifest.cs"], dv.FAIL)
        self.assertEqual(report["verdict"], dv.FAILED)

    def test_ledger_record_problems(self):
        doc = ledger_doc()
        doc["record"]["mintedBy"] = "SecdMSP/User1@geonft.eu"
        doc["transaction"]["validationCode"] = 10
        doc["transaction"]["validation"] = "ENDORSEMENT_POLICY_FAILURE"
        s = statuses(verify(DEPLOYMENT_ID, doc, lineage()))
        self.assertEqual(s["ledger.minter"], dv.FAIL)
        self.assertEqual(s["ledger.transaction"], dv.FAIL)
        self.assertEqual(statuses(verify("dep-other", ledger_doc(), lineage()))["ledger.token"], dv.FAIL)

    def test_unreadable_transaction_makes_it_incomplete(self):
        report = verify(DEPLOYMENT_ID, ledger_doc(transaction=None, transactionError="failed to get block"), lineage())
        self.assertEqual(report["verdict"], dv.INCOMPLETE)
        self.assertIn("failed to get block", detail(report, "ledger.transaction"))

    def test_incomplete_server_chain_in_the_manifest_fails(self):
        doc = with_manifest(lambda m: m.update(serverChain={"alg": "tcs-deployment-chain-v1", "count": 3, "head": None, "error": "seq gap"}))
        report = verify(DEPLOYMENT_ID, doc, lineage())
        self.assertEqual(statuses(report)["chain.manifest"], dv.FAIL)
        self.assertIn("seq gap", detail(report, "chain.manifest"))

    def test_engineering_as_second_endorser_also_satisfies_the_policy(self):
        report = verify(DEPLOYMENT_ID, endorsed_by("eng", "secd"), lineage())
        self.assertEqual(report["verdict"], dv.VERIFIED, report["checks"])

    def test_secd_alone_is_incomplete_not_failed(self):
        report = verify(DEPLOYMENT_ID, endorsed_by("secd"), lineage())
        s = statuses(report)
        self.assertEqual(s["endorse.signatures"], dv.PASS)
        self.assertEqual(s["endorse.policy"], dv.SKIP)
        self.assertEqual(report["verdict"], dv.INCOMPLETE)
        self.assertIn("before the policy change", detail(report, "endorse.policy"))

    def test_an_organisation_without_a_pinned_ca_is_unverified_and_named(self):
        trust = {k: v for k, v in TRUST.items() if k != "GeoidworksMSP"}
        report = verify(DEPLOYMENT_ID, ledger_doc(), lineage(), trust=trust)
        s = statuses(report)
        self.assertEqual(s["endorse.signatures"], dv.PASS)
        self.assertEqual(s["endorse.policy"], dv.SKIP)
        self.assertIn("No CA certificate is pinned for GeoidworksMSP", detail(report, "endorse.policy"))

    def test_no_pinned_ca_at_all_skips(self):
        report = verify(DEPLOYMENT_ID, ledger_doc(), lineage(), trust={})
        self.assertEqual(statuses(report)["endorse.signatures"], dv.SKIP)
        self.assertEqual(report["verdict"], dv.INCOMPLETE)

    def test_a_forged_or_misissued_endorsement_fails(self):
        for names, problem in (
            (("secd", "geoidRogue"), "not issued by the pinned GeoidworksMSP CA"),
            (("secdClient", "geoid"), "not a peer certificate"),
        ):
            report = verify(DEPLOYMENT_ID, endorsed_by(*names), lineage())
            self.assertEqual(statuses(report)["endorse.signatures"], dv.FAIL, names)
            self.assertEqual(report["verdict"], dv.FAILED)
            self.assertIn(problem, detail(report, "endorse.signatures"))

    def test_a_changed_signature_fails(self):
        doc = ledger_doc()
        sig = bytearray(dv.base64.b64decode(doc["transaction"]["endorsedAction"]["endorsements"][1]["signature"]))
        sig[-1] ^= 1
        doc["transaction"]["endorsedAction"]["endorsements"][1]["signature"] = dv.base64.b64encode(bytes(sig)).decode()
        report = verify(DEPLOYMENT_ID, doc, lineage())
        self.assertEqual(statuses(report)["endorse.signatures"], dv.FAIL)
        self.assertEqual(statuses(report)["endorse.policy"], dv.FAIL)

    def test_a_record_that_differs_from_the_signed_one_fails(self):
        # The ledger API changes the record and recomputes a matching hash: L1 passes, the signed writes do not.
        report = verify(DEPLOYMENT_ID, with_manifest(lambda m: m.update(systemId="sys-other")), lineage())
        s = statuses(report)
        self.assertEqual(s["manifest.hash"], dv.PASS)
        self.assertEqual(s["endorse.signatures"], dv.PASS)
        self.assertEqual(s["endorse.writes"], dv.FAIL)
        self.assertEqual(report["verdict"], dv.FAILED)

    def test_signatures_over_another_payload_fail(self):
        doc = ledger_doc()
        prp = bytearray(dv.base64.b64decode(doc["transaction"]["endorsedAction"]["proposalResponsePayload"]))
        prp[5] ^= 1  # inside proposal_hash: still decodes, no longer what was signed
        doc["transaction"]["endorsedAction"]["proposalResponsePayload"] = dv.base64.b64encode(bytes(prp)).decode()
        self.assertEqual(statuses(verify(DEPLOYMENT_ID, doc, lineage()))["endorse.signatures"], dv.FAIL)

    def test_an_old_ledger_api_without_signed_endorsements_is_incomplete(self):
        doc = ledger_doc()
        del doc["transaction"]["endorsedAction"]
        report = verify(DEPLOYMENT_ID, doc, lineage())
        self.assertEqual(statuses(report)["endorse.signatures"], dv.SKIP)
        self.assertEqual(report["verdict"], dv.INCOMPLETE)

    def test_bundled_trust_pins_the_three_real_cas(self):
        trust = dv.bundled_trust()
        self.assertEqual({msp: [c.common_name for c in certs] for msp, certs in trust.items()}, {
            "SecdMSP": ["ca.geonft.eu"],
            "EngineeringMSP": ["ca.4113engineering.eu"],
            "GeoidworksMSP": ["ca.geoidworks.eu"],
        })
        for certs in trust.values():
            self.assertTrue(certs[0].issued_by(certs[0]))  # self-signed roots

    def test_report_html_names_verdict_and_mismatches(self):
        lin = lineage()
        lin["items"][1]["chainHash"] = "0" * 64
        report = verify(DEPLOYMENT_ID, ledger_doc(), lin, observations=map_observations())
        page = dv.report_html(report, "North pasture")
        self.assertIn("Verification failed", page)
        self.assertIn("%s (broken link)" % FIX2, page)
        self.assertIn("North pasture", page)
        self.assertIn("<td><b>Drone DID</b></td><td><code>did:indy:sandbox:JrqC2m6GGcvkQUb7qXQiUV</code></td>", page)
        self.assertIn("read from peer0.4113engineering.eu:7051 (EngineeringMSP)", page)
        self.assertIn("L3 Drone chain", page)
        self.assertIn("L4 Pictures and content", page)
        self.assertIn("1 segment(s), 3 signed link(s) received, sealed", page)
        self.assertIn("Verification failed", dv.summary_line(report))

    def test_report_lists_flagged_observations_without_a_map_layer(self):
        report = verify(DEPLOYMENT_ID, ledger_doc(), lineage(), images=images(b"other bytes"))
        self.assertEqual(report["observations"], {})
        self.assertIn("%s (picture differs)" % PICTURE, dv.report_html(report))


class DroneChainVerifyTests(unittest.TestCase):
    def test_a_proof_with_a_changed_signature_fails_and_names_the_observation(self):
        lin = lineage()
        proof = lin["items"][1]["proof"]
        lin["items"][1]["proof"] = proof[:-2] + ("AA" if proof[-2:] != "AA" else "BA")
        report = verify(DEPLOYMENT_ID, ledger_doc(), lin, observations=map_observations())
        self.assertEqual(statuses(report)["drone.signatures"], dv.FAIL)
        self.assertIn("seq 2", detail(report, "drone.signatures"))
        self.assertEqual(report["observations"][str(FIX2)], dv.OBS_PROOF)
        self.assertEqual(report["verdict"], dv.FAILED)

    def test_proofs_swapped_between_observations_break_the_stored_links(self):
        lin = lineage()
        lin["items"][0]["proof"], lin["items"][1]["proof"] = lin["items"][1]["proof"], lin["items"][0]["proof"]
        report = verify(DEPLOYMENT_ID, ledger_doc(), lin, observations=map_observations())
        s = statuses(report)
        self.assertEqual(s["drone.signatures"], dv.PASS)
        self.assertEqual(s["drone.links"], dv.FAIL)
        self.assertEqual({report["observations"][str(FIX1)], report["observations"][str(FIX2)]}, {dv.OBS_PROOF})

    def test_an_observation_without_its_proof_fails(self):
        lin = lineage()
        lin["items"][2]["proof"] = None
        report = verify(DEPLOYMENT_ID, ledger_doc(), lin)
        self.assertEqual(statuses(report)["drone.signatures"], dv.FAIL)
        self.assertEqual(report["facts"]["flagged"][PICTURE], dv.OBS_PROOF)

    def test_an_observation_withheld_by_the_server_shows_as_a_gap_in_the_sealed_segment(self):
        # The server drops the fix the drone signed as n 3: it cannot hide the gap, the seal says n 4.
        lin = lineage()
        del lin["items"][1]
        s = statuses(verify(DEPLOYMENT_ID, ledger_doc(), lin))
        self.assertEqual(s["drone.signatures"], dv.PASS)
        self.assertEqual(s["drone.segments"], dv.FAIL)
        self.assertEqual(s["drone.complete"], dv.FAIL)
        report = verify(DEPLOYMENT_ID, ledger_doc(), lin)
        self.assertIn("missing 3", detail(report, "drone.complete"))

    def test_a_withheld_seal_fails(self):
        lin = lineage()
        lin["seal"] = None
        s = statuses(verify(DEPLOYMENT_ID, ledger_doc(), lin))
        self.assertEqual(s["drone.seal"], dv.FAIL)
        self.assertEqual(s["drone.close"], dv.FAIL)

    def test_a_changed_seal_fails(self):
        lin = lineage()
        fields = json.loads(lin["seal"]["doc"])
        fields["n"] = 5
        lin["seal"]["doc"] = dv.canonical_json(fields)
        report = verify(DEPLOYMENT_ID, ledger_doc(), lin)
        self.assertEqual(statuses(report)["drone.seal"], dv.FAIL)
        self.assertIn("plh does not cover the seal", detail(report, "drone.seal"))

    def test_proofs_by_another_key_than_the_ledger_fixed_fail(self):
        report = verify(DEPLOYMENT_ID, with_manifest(lambda m: m.update(cnfJkt="A" * 43)), lineage())
        s = statuses(report)
        self.assertEqual(s["drone.key"], dv.FAIL)
        self.assertEqual(s["drone.seal"], dv.FAIL)
        self.assertIn("signed by another key", detail(report, "drone.seal"))

    def test_without_a_drone_chain_it_is_incomplete(self):
        def legacy(m):
            m.update(droneChain=None, closeReason="unsealed")
        lin = lineage()
        lin["seal"] = None
        for item in lin["items"]:
            item.update(proof=None, droneBoot=None, droneN=None, dronePrev=None, droneLink=None)
        report = verify(DEPLOYMENT_ID, with_manifest(legacy), lin)
        self.assertEqual(statuses(report)["drone.chain"], dv.SKIP)
        self.assertIn("predates the drone-chain claims", detail(report, "drone.chain"))
        self.assertNotIn("drone.segments", statuses(report))

    def test_closed_without_a_seal_does_not_prove_completeness(self):
        def forced(m):
            m.update(closeReason="operator-forced-unsealed")
            m["droneChain"]["seal"] = None
        lin = lineage()
        lin["seal"] = None
        report = verify(DEPLOYMENT_ID, with_manifest(forced), lin)
        s = statuses(report)
        self.assertEqual((s["drone.seal"], s["drone.close"], s["drone.segments"]), (dv.PASS, dv.PASS, dv.PASS))
        self.assertEqual(s["drone.complete"], dv.SKIP)
        self.assertFalse([c for c in report["checks"] if c["key"] == "drone.complete"][0]["required"])
        self.assertIn("operator-forced-unsealed", detail(report, "drone.complete"))


class ContentVerifyTests(unittest.TestCase):
    def test_position_fixes_signed_as_anchored(self):
        report = verify(DEPLOYMENT_ID, ledger_doc(), lineage())
        self.assertEqual(statuses(report)["content.fixes"], dv.INFO)
        self.assertTrue(detail(report, "content.fixes").startswith("2 of 2"))

    def test_changed_picture_bytes_fail(self):
        report = verify(DEPLOYMENT_ID, ledger_doc(), lineage(), observations=map_observations(),
                        images=images(PICTURE_BYTES + b"\x00"))
        s = statuses(report)
        self.assertEqual(s["content.anchors"], dv.PASS)
        self.assertEqual(s["content.bytes"], dv.FAIL)
        self.assertIn("not the bytes the drone signed", detail(report, "content.bytes"))
        self.assertEqual(report["observations"][str(PICTURE)], dv.OBS_IMAGE)
        self.assertEqual(report["verdict"], dv.FAILED)

    def test_a_swapped_picture_fails_the_anchor_and_the_drone_signature(self):
        # Connected Systems serves another picture with a consistent sha256: the anchor and imgh still catch it.
        other = b"another picture"
        observations = cs_observations()
        picture = [o for o in observations if o["id"] == PICTURE][0]
        picture["result"] = dict(picture["result"], sha256=hashlib.sha256(other).hexdigest())
        report = verify(DEPLOYMENT_ID, ledger_doc(), lineage(), observations=map_observations(),
                        cs_observations=observations, images=images(other))
        s = statuses(report)
        self.assertEqual(s["content.anchors"], dv.FAIL)
        self.assertEqual(s["content.bytes"], dv.FAIL)
        self.assertEqual(report["observations"][str(PICTURE)], dv.OBS_CONTENT)

    def test_an_unreadable_picture_makes_it_incomplete(self):
        report = verify(DEPLOYMENT_ID, ledger_doc(), lineage(), observations=map_observations(),
                        images={PICTURE: {"error": "the gateway answered 504"}})
        self.assertEqual(statuses(report)["content.bytes"], dv.SKIP)
        self.assertIn("504", detail(report, "content.bytes"))
        self.assertEqual(report["verdict"], dv.INCOMPLETE)
        self.assertEqual(report["observations"][str(PICTURE)], dv.OBS_UNREAD)

    def test_observations_not_read_make_it_incomplete(self):
        report = verify(DEPLOYMENT_ID, ledger_doc(), lineage(), cs_observations=None, images=None,
                        cs_observations_note="The observations could not be read: refused (403)")
        self.assertEqual(statuses(report)["content.pictures"], dv.SKIP)
        self.assertIn("403", detail(report, "content.pictures"))
        self.assertEqual(report["verdict"], dv.INCOMPLETE)

    def test_a_picture_anchored_with_a_local_gateway_url_still_matches(self):
        result = {"contentType": "application/octet-stream", "cid": "bafkreiabc",
                  "url": "https://ipfs.geonft.eu/ipfs/bafkreiabc", "sha256": "ab" * 32}
        anchored = dv.canonical_hash({"deploymentId": DEPLOYMENT_ID,
                                      "result": dict(result, url="http://localhost:8091/ipfs/bafkreiabc")})
        hashes = [dv.canonical_hash(doc) for doc in dv.image_anchor_candidates(DEPLOYMENT_ID, result)]
        self.assertIn(anchored, hashes)
        self.assertEqual(hashes[0], dv.canonical_hash({"deploymentId": DEPLOYMENT_ID, "result": result}))


class ReadImagesTests(unittest.TestCase):
    def test_downloads_ipfs_pictures_and_decodes_inline_ones(self):
        inline = {"id": 7, "type": "Observation", "result": {"contentType": "application/octet-stream", "body": "aGVsbG8="}}
        fix = {"id": 8, "type": "Observation", "resultType": "telemetry", "result": {"lat": 1, "lon": 2}}
        calls = []

        def fetch(url):
            calls.append(url)
            return PICTURE_BYTES

        got = dv.read_images(cs_observations() + [inline, fix], fetch_bytes=fetch)
        self.assertEqual(got, {PICTURE: {"data": PICTURE_BYTES}, 7: {"data": b"hello"}})
        self.assertEqual(calls, [PICTURE_URL])

    def test_reads_flattened_features_from_the_map_collection(self):
        feature = cs_api.feature_from_observation(cs_observations()[2])
        flat = cs_api.flatten_feature_collection({"features": [feature]})["features"][0]
        self.assertEqual(dv.read_images([flat], fetch_bytes=lambda url: b"x"), {PICTURE: {"data": b"x"}})

    def test_a_failed_download_is_reported_not_raised(self):
        def fetch(url):
            raise cs_api.CsApiError("the gateway answered 504", 504)
        self.assertEqual(dv.read_images(cs_observations(), fetch_bytes=fetch), {PICTURE: {"error": "the gateway answered 504"}})

    def test_only_http_urls_are_read(self):
        with self.assertRaises(cs_api.CsApiError):
            dv.http_get_bytes("file:///etc/passwd")


class FakeFetch:
    def __init__(self, pages=None, error=None):
        self.pages = pages or {}
        self.error = error
        self.calls = []

    def __call__(self, url, token, timeout):
        self.calls.append(url)
        if self.error:
            raise self.error
        return self.pages[url]


class ReadTests(unittest.TestCase):
    def test_reads_the_ledger_record(self):
        url = "https://ledger.example/deployments/dep%3A1"
        fetch = FakeFetch({url: ledger_doc()})
        body = dv.ledger_deployment("https://ledger.example/", "tok", "dep:1", fetch)
        self.assertEqual(body["record"]["tokenId"], DEPLOYMENT_ID)
        self.assertEqual(fetch.calls, [url])

    def test_ledger_errors_name_the_ledger_and_keep_the_status(self):
        fetch = FakeFetch(error=cs_api.CsApiError("Connected Systems does not know x (404).", 404))
        with self.assertRaises(cs_api.CsApiError) as caught:
            dv.ledger_deployment(None, "tok", "dep-1", fetch)
        self.assertEqual(caught.exception.status, 404)
        self.assertIn("The ledger has no NFT for dep-1", str(caught.exception))
        self.assertEqual(fetch.calls, ["https://ledger.geonft.eu/deployments/dep-1"])
        down = FakeFetch(error=cs_api.CsApiError("Connected Systems is unavailable: refused"))
        with self.assertRaises(cs_api.CsApiError) as caught:
            dv.ledger_deployment(None, "tok", "dep-1", down)
        self.assertEqual(str(caught.exception), "The ledger API is unavailable: refused")
        with self.assertRaises(cs_api.CsApiError) as caught:
            dv.ledger_deployment(None, "tok", "dep-1", FakeFetch(error=cs_api.CsApiError("x", 401)))
        self.assertEqual(caught.exception.status, 401)

    def test_reads_all_lineage_pages_and_the_seal(self):
        first = "https://cs.example/deployments/dep-1/lineage?limit=1000"
        second = "https://cs.example/deployments/dep-1/lineage?afterSeq=1&limit=1000"
        items, seal = lineage()["items"], lineage()["seal"]
        fetch = FakeFetch({
            first: {"deploymentId": "dep-1", "items": items[:1], "seal": seal,
                    "links": [{"rel": "next", "href": "/deployments/dep-1/lineage?afterSeq=1&limit=1000"}]},
            second: {"deploymentId": "dep-1", "items": items[1:], "seal": seal, "links": []},
        })
        got = dv.deployment_lineage("https://cs.example", "tok", "dep-1", fetch)
        self.assertEqual([i["seq"] for i in got["items"]], [1, 2, 3])
        self.assertEqual(got["seal"], seal)
        self.assertEqual(fetch.calls, [first, second])

    def test_manifest_not_served_to_users_is_a_note(self):
        fetch = FakeFetch(error=cs_api.CsApiError("refused", 403))
        manifest, note = dv.deployment_manifest("https://cs.example", "tok", "dep-1", fetch)
        self.assertIsNone(manifest)
        self.assertIn("403", note)
        with self.assertRaises(cs_api.CsApiError):
            dv.deployment_manifest("https://cs.example", "tok", "dep-1", FakeFetch(error=cs_api.CsApiError("x", 401)))
        url = "https://cs.example/deployments/dep-1/manifest"
        self.assertEqual(dv.deployment_manifest("https://cs.example", "tok", "dep-1", FakeFetch({url: MANIFEST}))[0], MANIFEST)



class IndyIdentityVerifyTests(unittest.TestCase):
    def run_verify(self, **kwargs):
        return verify(DEPLOYMENT_ID, ledger_doc(), lineage(), copy.deepcopy(F_MANIFEST), None, map_observations(), **kwargs)

    def test_another_dpop_key_on_indy_fails_the_verdict(self):
        other = dict(FIXTURE["droneJwk"], x="pJqVUPIg5aY_aHxYcCHGjOK1tynLr8wcOD0XucWzYno")
        report = self.run_verify(indy=drone_identity(cnf_jwk=other))
        self.assertEqual(statuses(report)["indy.cnf"], dv.FAIL)
        self.assertEqual(report["verdict"], dv.FAILED)

    def test_a_drone_without_a_cnf_attrib_still_verifies(self):
        report = self.run_verify(indy=drone_identity(cnf_jwk=False))
        self.assertEqual(statuses(report)["indy.nym"], dv.PASS)
        self.assertEqual(statuses(report)["indy.cnf"], dv.SKIP)
        self.assertIn("re-enrolling", detail(report, "indy.cnf"))
        self.assertEqual(report["verdict"], dv.VERIFIED)

    def test_an_unreadable_resolver_skips_without_changing_the_verdict(self):
        report = self.run_verify(indy=None, indy_note="The Indy resolver could not be read: timeout")
        self.assertEqual((statuses(report)["indy.nym"], statuses(report)["indy.cnf"]), (dv.SKIP, dv.SKIP))
        self.assertEqual(report["verdict"], dv.VERIFIED)

    def test_report_html_shows_the_indy_level_and_key(self):
        page = dv.report_html(self.run_verify(), "North pasture")
        self.assertIn("L5 Drone identity on Indy", page)
        self.assertIn("DPoP key on Indy", page)
        self.assertIn("%s (ATTRIB seqNo 23" % F_MANIFEST["cnfJkt"], page)
        self.assertIn("https://resolver.test", page)
        self.assertNotIn("the access token's word", page)


if __name__ == "__main__":
    unittest.main()
