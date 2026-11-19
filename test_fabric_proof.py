import base64
import datetime
import json
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import fabric_proof as fp

FIXTURE = json.loads((HERE / "test_fixtures" / "endorsed_mint.json").read_text())
TRUST = fp.load_trust(FIXTURE["trust"])
PRP = base64.b64decode(FIXTURE["transaction"]["endorsedAction"]["proposalResponsePayload"])
AT = datetime.datetime(2027, 1, 15, 9, 0, 5, tzinfo=datetime.timezone.utc)


def cert(pem_text):
    return fp.Certificate(fp.pem_certificates(pem_text)[0])


class CertificateTests(unittest.TestCase):
    def test_reads_the_real_secd_certificates(self):
        # ca.geonft.eu as pinned in trust/, and Connected Systems' writer certificate it issued.
        ca = cert((HERE / "trust" / "SecdMSP.pem").read_text())
        writer = cert((HERE / "test_fixtures" / "csapi-cert.pem").read_text())
        self.assertEqual(ca.common_name, "ca.geonft.eu")
        self.assertEqual(writer.common_name, "csapi@geonft.eu")
        self.assertEqual(writer.attribute(fp.OID_OU), ["client"])
        self.assertTrue(writer.issued_by(ca))
        self.assertFalse(ca.issued_by(writer))
        self.assertLess(writer.not_before, writer.not_after)

    def test_rejects_a_certificate_with_a_changed_body(self):
        ca = TRUST["SecdMSP"][0]
        der = bytearray(cert((HERE / "test_fixtures" / "csapi-cert.pem").read_text()).der)
        der[-80] ^= 1  # one changed byte near the end
        self.assertFalse(fp.Certificate(bytes(der)).issued_by(ca))


class EcdsaTests(unittest.TestCase):
    def test_verifies_and_rejects(self):
        endorsement = FIXTURE["endorsements"]["secd"]
        endorser = base64.b64decode(endorsement["endorser"])
        signature = base64.b64decode(endorsement["signature"])
        _, pem = fp.serialized_identity(endorser)
        key = cert(pem).public_key
        self.assertTrue(fp.ecdsa_verify(key, PRP + endorser, signature))
        self.assertFalse(fp.ecdsa_verify(key, PRP + endorser + b"x", signature))
        self.assertFalse(fp.ecdsa_verify(key, PRP + endorser, signature[:-1]))
        self.assertFalse(fp.ecdsa_verify(key, PRP + endorser, b"not der"))
        self.assertFalse(fp.ecdsa_verify((1, 2), PRP + endorser, signature))  # not on the curve


class PayloadTests(unittest.TestCase):
    def test_reads_what_the_endorsers_signed(self):
        action = fp.chaincode_action(PRP)
        self.assertEqual((action["chaincode"], action["version"], action["status"]), ("deployments", "1.0", 200))
        writes = {key: value for key, value, _ in action["writes"]["deployments"]}
        token_key = fp.composite_key("deployment", FIXTURE["record"]["tokenId"])
        self.assertEqual(json.loads(writes[token_key]), FIXTURE["record"])
        self.assertEqual(writes[fp.composite_key("dephash", FIXTURE["record"]["deploymentHash"])].decode(), FIXTURE["record"]["tokenId"])
        self.assertNotIn("_lifecycle", action["writes"])  # reads only

    def test_composite_key_matches_fabric(self):
        self.assertEqual(fp.composite_key("deployment", "dep-1"), "\x00deployment\x00dep-1\x00")

    def test_truncated_payload_raises(self):
        with self.assertRaises(fp.ProofError):
            fp.chaincode_action(PRP[:-3])


class EndorsementTests(unittest.TestCase):
    def check(self, name, trust=TRUST, at=AT):
        return fp.check_endorsement(PRP, FIXTURE["endorsements"][name], trust, at)

    def test_peers_of_pinned_cas_verify(self):
        for name, msp in (("secd", "SecdMSP"), ("geoid", "GeoidworksMSP"), ("eng", "EngineeringMSP")):
            result = self.check(name)
            self.assertTrue(result["ok"], result)
            self.assertEqual(result["mspId"], msp)
            self.assertIn("OU=peer", result["subject"])

    def test_problems_are_named(self):
        self.assertEqual(self.check("secdClient")["problem"], "not a peer certificate (OU client)")
        self.assertEqual(self.check("geoidRogue")["problem"], "certificate not issued by the pinned GeoidworksMSP CA")
        self.assertEqual(self.check("geoid", trust={})["problem"], "no pinned CA for GeoidworksMSP")
        late = datetime.datetime(2040, 1, 1, tzinfo=datetime.timezone.utc)
        self.assertIn("not valid at", self.check("secd", at=late)["problem"])
        broken = fp.check_endorsement(PRP, {"endorser": "!!", "signature": ""}, TRUST, AT)
        self.assertIn("unreadable endorsement", broken["problem"])

    def test_an_endorsement_claiming_another_msp_fails(self):
        # The Geoidworks peer certificate relabelled as SecdMSP: not issued by the SecD CA.
        endorser = base64.b64decode(FIXTURE["endorsements"]["geoid"]["endorser"])
        _, pem = fp.serialized_identity(endorser)
        relabelled = bytes([0x0A, 7]) + b"SecdMSP" + bytes([0x12]) + _varint(len(pem)) + pem
        result = fp.check_endorsement(PRP, {"endorser": base64.b64encode(relabelled).decode(),
                                            "signature": FIXTURE["endorsements"]["geoid"]["signature"]}, TRUST, AT)
        self.assertEqual(result["problem"], "certificate not issued by the pinned SecdMSP CA")


def _varint(n):
    out = bytearray()
    while True:
        byte = n & 0x7F
        n >>= 7
        out.append(byte | (0x80 if n else 0))
        if not n:
            return bytes(out)


if __name__ == "__main__":
    unittest.main()
