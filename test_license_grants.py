import base64
import json
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import cs_api
import license_grants as lg


def _jwt(sub):
    body = base64.urlsafe_b64encode(json.dumps({"sub": sub}).encode()).rstrip(b"=").decode()
    return "eyJhbGciOiJub25lIn0.%s.sig" % body


T0 = 1_795_000_000.0  # some moment; the tests pass `now` explicitly
CS = "https://cs.geonft.eu"
WAIT = "Reading…"
WALLET = "Authorize with your wallet app"


class LicenseGrantTests(unittest.TestCase):
    def setUp(self):
        lg.clear()
        self.alice, self.bob = _jwt("alice"), _jwt("bob")

    def test_licensed_paths_name_their_deployment(self):
        self.assertEqual(lg.deployment_of(CS + "/deployments/drone-1-flight-2/observations?limit=1000"), "drone-1-flight-2")
        self.assertEqual(lg.deployment_of(CS + "/deployments/a%2Fb/manifest"), "a/b")
        self.assertEqual(lg.deployment_of(CS + "/deployments/d1/lineage?afterSeq=0"), "d1")
        self.assertEqual(lg.deployment_of(CS + "/deployments/d1/observations/42"), "d1")
        self.assertIsNone(lg.deployment_of("https://ledger.geonft.eu/deployments/d1"))
        self.assertIsNone(lg.deployment_of("https://portal.geonft.eu/licensed-deployments"))

    def test_parse_time(self):
        self.assertEqual(lg.parse_time("2026-11-19T12:05:00.000Z"), lg.parse_time("2026-11-19T13:05:00+01:00"))
        self.assertIsNone(lg.parse_time("soon"))
        self.assertIsNone(lg.parse_time(None))

    def test_a_grant_is_kept_per_account_and_deployment_until_shortly_before_it_ends(self):
        url = CS + "/deployments/d1/observations"
        expires = lg.observe(url, self.alice, "2026-11-19T12:05:00Z")
        self.assertIsNotNone(expires)
        self.assertFalse(lg.wallet_needed(self.alice, "d1", now=expires - 60))
        self.assertTrue(lg.wallet_needed(self.alice, "d1", now=expires - lg.MARGIN_S))
        self.assertTrue(lg.wallet_needed(self.alice, "d2", now=expires - 60))
        self.assertTrue(lg.wallet_needed(self.bob, "d1", now=expires - 60))

    def test_no_header_or_a_refusal_means_the_wallet_is_asked(self):
        url = CS + "/deployments/d1/observations"
        self.assertIsNone(lg.observe(url, self.alice, None))
        self.assertTrue(lg.wallet_needed(self.alice, "d1", now=T0))
        expires = lg.observe(url, self.alice, "2026-11-19T12:05:00Z")
        lg.forget(self.alice, url)
        self.assertTrue(lg.wallet_needed(self.alice, "d1", now=expires - 60))

    def test_status_shows_the_wallet_prompt_only_while_a_licensed_read_waits_on_it(self):
        url = CS + "/deployments/d1/manifest"
        # Nothing licensed in flight (e.g. the ledger read of a verification): no prompt.
        self.assertEqual(lg.status_text(self.alice, "d1", WAIT, WALLET, now=T0), WAIT)
        handle = lg.begin(url, now=T0)
        self.assertEqual(lg.status_text(self.alice, "d1", WAIT, WALLET, now=T0 + 0.1), WALLET)
        lg.end(handle)
        self.assertEqual(lg.status_text(self.alice, "d1", WAIT, WALLET, now=T0 + 1), WAIT)

    def test_with_a_cached_grant_the_prompt_appears_only_if_the_read_is_slow(self):
        url = CS + "/deployments/d1/observations"
        expires = lg.observe(url, self.alice, "2026-11-19T12:05:00Z")
        start = expires - 200
        handle = lg.begin(url, now=start)
        self.assertEqual(lg.status_text(self.alice, "d1", WAIT, WALLET, now=start + 2), WAIT)
        self.assertEqual(lg.status_text(self.alice, "d1", WAIT, WALLET, now=start + lg.SLOW_S), WALLET)
        lg.end(handle)


class _Handler(BaseHTTPRequestHandler):
    status = 200
    header = "2026-11-19T12:05:00.000Z"

    def do_GET(self):
        body = json.dumps({"type": "FeatureCollection", "features": []}).encode()
        self.send_response(self.status)
        if self.status == 200 and self.header:
            self.send_header(lg.HEADER, self.header)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        return


class HttpHeaderTests(unittest.TestCase):
    def setUp(self):
        lg.clear()
        self.server = HTTPServer(("127.0.0.1", 0), _Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.base = "http://127.0.0.1:%d" % self.server.server_address[1]
        self.token = _jwt("alice")

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        _Handler.status = 200

    def test_a_licensed_read_records_the_header_and_a_403_drops_it(self):
        url = self.base + "/deployments/d1/observations?limit=1000"
        cs_api.http_get_json(url, self.token, 10)
        expires = lg.parse_time(_Handler.header)
        self.assertFalse(lg.wallet_needed(self.token, "d1", now=expires - 60))
        self.assertIsNone(lg.waiting_seconds("d1"), "the read is no longer in flight")
        _Handler.status = 403
        with self.assertRaises(cs_api.CsApiError):
            cs_api.http_get_json(url, self.token, 10)
        self.assertTrue(lg.wallet_needed(self.token, "d1", now=expires - 60))


if __name__ == "__main__":
    unittest.main()
