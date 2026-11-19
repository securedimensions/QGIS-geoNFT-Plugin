import base64
import json
import sys
import threading
import unittest
import urllib.request
from pathlib import Path
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent))
import auth


def _jwt(payload):
    header = base64.urlsafe_b64encode(json.dumps({"alg": "none"}).encode()).rstrip(b"=").decode()
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    return "%s.%s.sig" % (header, body)


class AuthTests(unittest.TestCase):
    def test_redirect_uri(self):
        self.assertEqual(auth.redirect_uri(), "http://localhost:7070/cs-review")

    def test_default_issuer_is_the_public_portal(self):
        self.assertEqual(auth.DEFAULT_ISSUER, "https://portal.geonft.eu/realms/customers")
        self.assertNotIn("8088", auth.DEFAULT_ISSUER)

    def test_issuer_strips_a_trailing_slash_and_rejects_the_keycloak_port(self):
        self.assertEqual(
            auth.normalize_issuer("https://portal.geonft.eu/realms/customers/"),
            "https://portal.geonft.eu/realms/customers",
        )
        with self.assertRaises(auth.AuthError):
            auth.normalize_issuer("http://localhost:8088/realms/customers")

    def test_oauth2_config_is_pkce_on_the_qgis_loopback(self):
        config = auth.oauth2_config_dict(auth.DEFAULT_ISSUER, "state-1")
        self.assertEqual(config["grantFlow"], 3)
        self.assertEqual(config["clientId"], "qgis-cs")
        self.assertEqual(config["redirectHost"], "localhost")
        self.assertEqual(config["redirectPort"], 7070)
        self.assertEqual(config["redirectUrl"], "cs-review")
        self.assertEqual(config["scope"], "openid email profile")
        self.assertEqual(config["queryPairs"], {"state": "state-1"})
        self.assertEqual(config["requestUrl"], "https://portal.geonft.eu/realms/customers/protocol/openid-connect/auth")
        self.assertEqual(config["tokenUrl"], "https://portal.geonft.eu/realms/customers/protocol/openid-connect/token")
        self.assertNotIn("clientSecret", config)
        self.assertNotIn("8088", json.dumps(config))

    def test_pkce_s256_matches_rfc7636(self):
        verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        self.assertEqual(auth.pkce_challenge(verifier), "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")

    def test_authorize_and_registration_share_the_redirect(self):
        authorize = urlparse(auth.authorize_url(auth.DEFAULT_ISSUER, "state-1", "challenge"))
        registration = urlparse(auth.registration_url(auth.DEFAULT_ISSUER, "state-1", "challenge"))
        self.assertEqual(authorize.path, "/realms/customers/protocol/openid-connect/auth")
        self.assertEqual(registration.path, "/realms/customers/protocol/openid-connect/registrations")
        auth_query = parse_qs(authorize.query)
        registration_query = parse_qs(registration.query)
        self.assertEqual(auth_query["redirect_uri"], ["http://localhost:7070/cs-review"])
        self.assertEqual(registration_query["redirect_uri"], ["http://localhost:7070/cs-review"])
        self.assertEqual(auth_query["client_id"], ["qgis-cs"])
        self.assertEqual(registration_query["client_id"], ["qgis-cs"])
        self.assertEqual(auth_query["code_challenge_method"], ["S256"])
        self.assertEqual(registration_query["code_challenge"], ["challenge"])
        self.assertNotIn("client_secret", authorize.query)
        self.assertNotIn("8088", registration.geturl())

    def test_logout_uses_the_same_redirect(self):
        parsed = urlparse(auth.logout_url(auth.DEFAULT_ISSUER, "id-token"))
        query = parse_qs(parsed.query)
        self.assertEqual(parsed.path, "/realms/customers/protocol/openid-connect/logout")
        self.assertEqual(query["client_id"], ["qgis-cs"])
        self.assertEqual(query["post_logout_redirect_uri"], ["http://localhost:7070/cs-review"])
        self.assertEqual(query["id_token_hint"], ["id-token"])
        self.assertNotIn("8088", parsed.geturl())
        without_hint = parse_qs(urlparse(auth.logout_url(auth.DEFAULT_ISSUER)).query)
        self.assertNotIn("id_token_hint", without_hint)
        self.assertEqual(auth.SESSION_KEYS, ("access_token", "id_token", "expires_at", "email", "sub"))

    def test_account_creation_signs_out_before_registration(self):
        logout, registration = auth.account_creation_urls(auth.DEFAULT_ISSUER, "state-1", "challenge", "id-token")
        logout_query = parse_qs(urlparse(logout).query)
        registration_query = parse_qs(urlparse(registration).query)
        self.assertTrue(urlparse(logout).path.endswith("/protocol/openid-connect/logout"))
        self.assertEqual(logout_query["post_logout_redirect_uri"], ["http://localhost:7070/cs-review"])
        self.assertEqual(logout_query["id_token_hint"], ["id-token"])
        self.assertTrue(urlparse(registration).path.endswith("/protocol/openid-connect/registrations"))
        self.assertEqual(registration_query["redirect_uri"], ["http://localhost:7070/cs-review"])
        self.assertEqual(registration_query["state"], ["state-1"])
        self.assertNotIn("registrations", logout)

    def test_cancel_stops_the_wait(self):
        auth.request_cancel()
        try:
            with self.assertRaises(auth.AuthError) as caught:
                auth._wait_for_callback({}, 30)
            self.assertEqual(str(caught.exception), "Cancelled.")
        finally:
            auth._cancel.clear()

    def test_token_form_is_a_public_pkce_exchange(self):
        form = auth.token_form("code-1", "verifier-1")
        self.assertEqual(
            set(form),
            {"grant_type", "code", "redirect_uri", "client_id", "code_verifier"},
        )
        self.assertEqual(form["grant_type"], "authorization_code")
        self.assertEqual(form["redirect_uri"], "http://localhost:7070/cs-review")
        self.assertEqual(form["client_id"], "qgis-cs")
        self.assertEqual(form["code_verifier"], "verifier-1")

    def test_callback_path_and_state(self):
        self.assertTrue(auth.redirect_path_ok("/cs-review"))
        self.assertTrue(auth.redirect_path_ok("/cs-review/"))
        self.assertFalse(auth.redirect_path_ok("/favicon.ico"))
        self.assertFalse(auth.redirect_path_ok("/cs-review/extra"))
        self.assertEqual(
            auth.authorization_code_from_callback({"done": True, "code": " abc ", "state": "s"}, "s"),
            "abc",
        )
        with self.assertRaises(auth.AuthError) as mismatch:
            auth.authorization_code_from_callback(
                {"done": True, "code": "abc", "state": "other"},
                "expected",
            )
        self.assertIn("state", str(mismatch.exception).lower())
        with self.assertRaises(auth.AuthError) as denied:
            auth.authorization_code_from_callback(
                {"done": True, "error": "access_denied", "error_description": "no", "state": "s"},
                "s",
            )
        self.assertIn("no", str(denied.exception))
        with self.assertRaises(auth.AuthError):
            auth.authorization_code_from_callback({"done": True, "code": "  ", "state": "s"}, "s")
        with self.assertRaises(auth.AuthError):
            auth.authorization_code_from_callback({"done": False}, "s")

    def test_access_token_email_and_sub(self):
        now = 1_700_000_000
        token = _jwt({"email": "person@example.com", "sub": "same-person", "exp": now + 300})
        claims = auth.jwt_payload(token)
        self.assertEqual(claims["email"], "person@example.com")
        self.assertEqual(claims["sub"], "same-person")
        session = auth.session_from_token_response(
            {"access_token": token, "expires_in": 300, "id_token": "id-token", "refresh_token": "ignored"},
            now=now,
        )
        self.assertEqual(session["email"], "person@example.com")
        self.assertEqual(session["sub"], "same-person")
        self.assertEqual(session["expires_at"], now + 300)
        self.assertEqual(session["id_token"], "id-token")
        self.assertNotIn("refresh_token", session)
        self.assertTrue(auth.token_usable(token, now + 61, now=now))
        self.assertFalse(auth.token_usable(token, now + 60, now=now))
        self.assertFalse(auth.token_usable("", now + 300, now=now))
        with self.assertRaises(auth.AuthError):
            auth.session_from_token_response({"access_token": _jwt({"email": "person@example.com"})}, now=now)

    def test_loopback_accepts_the_redirect_and_ignores_other_paths(self):
        result = {}
        server = auth._http_server("127.0.0.1", 0, auth._loopback_handler(result))
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        thread.start()
        try:
            port = server.server_address[1]
            favicon = urllib.request.urlopen("http://127.0.0.1:%s/favicon.ico" % port, timeout=2)
            self.assertEqual(favicon.status, 204)
            favicon.close()
            callback = urllib.request.urlopen(
                "http://127.0.0.1:%s/cs-review?code=abc&state=s" % port,
                timeout=2,
            )
            body = callback.read()
            self.assertEqual(callback.status, 200)
            callback.close()
            self.assertIn(b"return to QGIS", body)
            self.assertEqual(result["code"], "abc")
            self.assertEqual(result["state"], "s")
            self.assertTrue(result["done"])
        finally:
            server.shutdown()
            thread.join(2)
            server.server_close()

    def test_a_leftover_listener_can_be_reclaimed(self):
        handler = auth._loopback_handler({})
        abandoned = auth._http_server("127.0.0.1", 0, handler)
        port = abandoned.server_address[1]
        try:
            self.assertGreater(auth._release_http_servers(port), 0)
            rebound = auth._http_server("127.0.0.1", port, handler)
            rebound.server_close()
        finally:
            try:
                abandoned.server_close()
            except OSError:
                pass


class TokenLogTests(unittest.TestCase):
    def test_log_message_carries_the_whole_token_and_its_claims(self):
        token = _jwt({"sub": "user-1", "aud": ["cs-api", "account"], "azp": "qgis-cs", "exp": 0})
        message = auth.token_log_message({"access_token": token, "expires_at": 1800000000})
        self.assertIn("user-1", message)
        self.assertIn("aud=cs-api,account", message)
        self.assertIn("azp=qgis-cs", message)
        self.assertIn("2027-01-15 08:00:00 UTC", message)
        self.assertTrue(message.endswith("\n" + token))


if __name__ == "__main__":
    unittest.main()
