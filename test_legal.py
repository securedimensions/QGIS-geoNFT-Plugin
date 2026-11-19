import datetime
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import legal


class LegalTests(unittest.TestCase):
    def test_documents_exist_and_render_without_placeholders(self):
        operator = {"name": "Op GmbH", "address": "Street 1, City", "email": "privacy@example.org",
                    "website": "https://example.org", "dpo": "", "jurisdiction": "Germany"}
        for name in legal.DOCUMENTS:
            text = legal.render(name, operator=operator)
            self.assertNotIn("{{", text, name)
            self.assertIn(legal.LEGAL_VERSION, text, name)
            self.assertIn("Op GmbH", text, name)

    def test_operator_values_are_escaped(self):
        operator = dict.fromkeys(legal.OPERATOR_FIELDS, "")
        operator["name"] = "<script>x</script>"
        text = legal.render(legal.TERMS, operator=operator)
        self.assertNotIn("<script>x", text)
        self.assertIn("&lt;script&gt;", text)

    def test_dpo_block_only_when_set(self):
        operator = dict.fromkeys(legal.OPERATOR_FIELDS, "")
        self.assertNotIn("Data protection officer", legal.render(legal.PRIVACY, operator=operator))
        operator["dpo"] = "dpo@example.org"
        self.assertIn("Data protection officer: dpo@example.org", legal.render(legal.PRIVACY, operator=operator))

    def test_load_operator_and_unfinished_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "operator.ini"), "w", encoding="utf-8") as handle:
                handle.write("[operator]\nname=Op\naddress=CHANGE_ME\nemail=a@b.c\njurisdiction=\n")
            operator = legal.load_operator(tmp)
        self.assertEqual(operator["name"], "Op")
        self.assertEqual(operator["website"], "")
        self.assertEqual(legal.unfinished_operator_fields(operator), ["address", "jurisdiction"])

    def test_document_name(self):
        self.assertEqual(legal.document_name("privacy.html"), legal.PRIVACY)
        self.assertEqual(legal.document_name("file:///x/docs/cookies.html#top"), legal.COOKIES)
        self.assertEqual(legal.document_name("docs/terms.html#s2"), legal.TERMS)
        self.assertIsNone(legal.document_name("https://portal.geonft.eu/privacy.html"))
        self.assertIsNone(legal.document_name("other.html"))

    def test_acceptance_round_trip(self):
        store = {}
        self.assertFalse(legal.accepted(store.get))
        legal.record_acceptance(store.__setitem__, now=datetime.datetime(2026, 11, 19, 10, 0, 0, 5,
                                                                         tzinfo=datetime.timezone.utc))
        self.assertTrue(legal.accepted(store.get))
        self.assertEqual(store[legal.ACCEPTED_AT_KEY], "2026-11-19T10:00:00+00:00")
        store[legal.ACCEPTED_KEY] = "2000-01-01"
        self.assertFalse(legal.accepted(store.get))
        legal.withdraw_acceptance(store.__setitem__)
        self.assertFalse(legal.accepted(store.get))


if __name__ == "__main__":
    unittest.main()
