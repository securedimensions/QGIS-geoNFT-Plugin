"""geoNFT portal sign-in for the geoNFT QGIS plugin.

The OAuth2 client configuration is stored in the QGIS authentication database.
The plugin listens on http://localhost:7070/cs-review and exchanges the
authorization code itself. Do not call QgsAuthManager.updateNetworkRequest:
on Windows that path access-violates because QgsO2 runs off the UI thread.
A public client cannot refresh tokens. An expired access token means the
user signs in again.
"""

import base64
import hashlib
import json
import logging
import secrets
import socket
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlencode, urlparse

CLIENT_ID = "qgis-cs"
REDIRECT_HOST = "localhost"
REDIRECT_PORT = 7070
REDIRECT_PATH = "cs-review"
DEFAULT_ISSUER = "https://portal.geonft.eu/realms/customers"
SCOPE = "openid email profile"
SETTINGS_GROUP = "geonft"
LEGACY_SETTINGS_GROUP = "cs_review"  # before the geoNFT rebranding (plugin 0.6 and older)
SESSION_KEYS = ("access_token", "id_token", "expires_at", "email", "sub")
SKEW_SECONDS = 60
LOOPBACK_TIMEOUT_S = 300

_logger = logging.getLogger("geonft")
_loopback_servers = []
_loopback_threads = []
_loopback_lock = threading.Lock()
_cancel = threading.Event()

_CALLBACK_PAGE = """<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>geoNFT portal</title></head>
<body><p>You can close this window and return to QGIS.</p></body>
</html>
"""


class AuthError(RuntimeError):
    """Sign-in could not finish. The panel shows this message."""


def redirect_uri():
    return "http://%s:%s/%s" % (REDIRECT_HOST, REDIRECT_PORT, REDIRECT_PATH)


def normalize_issuer(value):
    text = str(value or "").strip().rstrip("/")
    if not text:
        text = DEFAULT_ISSUER
    if ":8088" in text:
        raise AuthError("Use the portal address. The browser cannot use the Keycloak port 8088.")
    return text


def _endpoint(issuer, leaf):
    return "%s/protocol/openid-connect/%s" % (normalize_issuer(issuer), leaf)


def pkce_verifier():
    return secrets.token_urlsafe(64)


def pkce_challenge(verifier):
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def jwt_payload(token):
    parts = (token or "").split(".")
    if len(parts) < 2:
        return {}
    payload = parts[1] + "=" * (-len(parts[1]) % 4)
    try:
        claims = json.loads(base64.urlsafe_b64decode(payload.encode("ascii")))
    except (json.JSONDecodeError, ValueError):
        return {}
    return claims if isinstance(claims, dict) else {}


def _text(value):
    if value is None:
        return ""
    return str(value).strip()


def oauth2_config_dict(issuer, state=None):
    """JSON stored on the QgsAuthMethodConfig. grantFlow 3 is PKCE."""
    issuer = normalize_issuer(issuer)
    if not state:
        state = secrets.token_urlsafe(24)
    return {
        "accessMethod": 0,
        "clientId": CLIENT_ID,
        "configType": 1,
        "grantFlow": 3,
        "persistToken": True,
        "queryPairs": {"state": state},
        "redirectHost": REDIRECT_HOST,
        "redirectPort": REDIRECT_PORT,
        "redirectUrl": REDIRECT_PATH,
        "requestTimeout": 60,
        "requestUrl": _endpoint(issuer, "auth"),
        "scope": SCOPE,
        "tokenUrl": _endpoint(issuer, "token"),
        "version": 1,
    }


def _auth_query(state, challenge):
    return {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": redirect_uri(),
        "scope": SCOPE,
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }


def authorize_url(issuer, state, challenge):
    return _endpoint(issuer, "auth") + "?" + urlencode(_auth_query(state, challenge))


def registration_url(issuer, state, challenge):
    return _endpoint(issuer, "registrations") + "?" + urlencode(_auth_query(state, challenge))


def logout_url(issuer, id_token=None):
    params = {
        "client_id": CLIENT_ID,
        "post_logout_redirect_uri": redirect_uri(),
    }
    hint = _text(id_token)
    if hint:
        params["id_token_hint"] = hint
    return _endpoint(issuer, "logout") + "?" + urlencode(params)


def account_creation_urls(issuer, state, challenge, id_token=None):
    """Sign out of the browser session before registration.

    Keycloak keeps the existing user, such as a portal sign-in, on the
    browser session. Opening registration directly then fails with
    "already authenticated as different user".
    """
    return [
        logout_url(issuer, id_token),
        registration_url(issuer, state, challenge),
    ]


def token_form(code, verifier):
    return {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri(),
        "client_id": CLIENT_ID,
        "code_verifier": verifier,
    }


def redirect_path_ok(path):
    expected = "/" + REDIRECT_PATH.strip("/")
    normalized = (path or "").split("?", 1)[0].rstrip("/") or "/"
    return normalized == expected


def authorization_code_from_callback(result, expected_state, registration=False):
    if result.get("error"):
        detail = result.get("error_description") or result.get("error")
        raise AuthError("The portal denied the request: %s" % detail)
    if not result.get("done"):
        action = "Account creation" if registration else "Sign-in"
        raise AuthError(
            "%s did not complete. Finish in the browser, keep port %s free, and use %s."
            % (action, REDIRECT_PORT, redirect_uri())
        )
    if (result.get("state") or "") != expected_state:
        raise AuthError("The callback state did not match this request. Start again.")
    code = (result.get("code") or "").strip()
    if not code:
        raise AuthError("The identity provider did not return an authorization code. Start again.")
    return code


def token_usable(access_token, expires_at=None, skew=SKEW_SECONDS, now=None):
    if not access_token:
        return False
    now = time.time() if now is None else float(now)
    exp = expires_at
    if not exp:
        exp = jwt_payload(access_token).get("exp")
    try:
        exp = float(exp or 0)
    except (TypeError, ValueError):
        exp = 0.0
    if exp <= 0:
        return False
    return now + skew < exp


def session_from_token_response(body, now=None):
    if not isinstance(body, dict):
        raise AuthError("The token response was not JSON.")
    now = time.time() if now is None else float(now)
    access = _text(body.get("access_token"))
    if not access:
        raise AuthError("The identity provider did not return an access token. Sign in again.")
    claims = jwt_payload(access)
    sub = _text(claims.get("sub"))
    if not sub:
        raise AuthError("The access token has no account id. Sign in again.")
    expires_at = 0.0
    if body.get("expires_in") is not None:
        try:
            expires_at = now + max(0, int(float(body.get("expires_in"))))
        except (TypeError, ValueError):
            expires_at = 0.0
    if expires_at <= now:
        try:
            expires_at = float(claims.get("exp") or 0)
        except (TypeError, ValueError):
            expires_at = 0.0
    session = {
        "access_token": access,
        "expires_at": expires_at,
        "email": _text(claims.get("email")),
        "sub": sub,
    }
    id_token = _text(body.get("id_token"))
    if id_token:
        session["id_token"] = id_token
    return session


def _settings():
    from qgis.core import QgsSettings
    return QgsSettings()


def _read_setting(key, default=None):
    settings = _settings()
    settings.beginGroup(SETTINGS_GROUP)
    try:
        return settings.value(key, default)
    finally:
        settings.endGroup()


def _write_setting(key, value):
    settings = _settings()
    settings.beginGroup(SETTINGS_GROUP)
    try:
        if value is None or value == "":
            settings.remove(key)
        else:
            settings.setValue(key, value)
    finally:
        settings.endGroup()


def read_setting(key, default=None):
    """A value from the plugin's QGIS settings group (geonft/<key>)."""
    return _read_setting(key, default)


def write_setting(key, value):
    """Store a value in the plugin's QGIS settings group; None or "" removes it."""
    _write_setting(key, value)


def migrate_legacy_settings():
    """Move settings written before the geoNFT rebranding (group cs_review) to the geonft group.

    Runs once: existing geonft values win, and the old group is removed afterwards.
    Returns the number of keys moved.
    """
    settings = _settings()
    settings.beginGroup(LEGACY_SETTINGS_GROUP)
    try:
        legacy = {key: settings.value(key) for key in settings.allKeys()}
    finally:
        settings.endGroup()
    if not legacy:
        return 0
    moved = 0
    settings.beginGroup(SETTINGS_GROUP)
    try:
        for key, value in legacy.items():
            if not settings.contains(key):
                settings.setValue(key, value)
                moved += 1
    finally:
        settings.endGroup()
    settings.remove(LEGACY_SETTINGS_GROUP)
    return moved


def issuer():
    return normalize_issuer(_read_setting("issuer", DEFAULT_ISSUER))


def cs_url_setting():
    """Connected Systems base URL from QGIS settings (geonft/cs_url), or None."""
    return _text(_read_setting("cs_url")) or None


def portal_url_setting():
    """Portal base URL from QGIS settings (geonft/portal_url), or None to derive it from the issuer."""
    return _text(_read_setting("portal_url")) or None


def ledger_url_setting():
    """Ledger API base URL from QGIS settings (geonft/ledger_url), or None for https://ledger.geonft.eu."""
    return _text(_read_setting("ledger_url")) or None


def indy_resolver_url_setting():
    """Indy resolver base URL from QGIS settings (geonft/indy_resolver_url), or None for https://resolver.geonft.eu."""
    return _text(_read_setting("indy_resolver_url")) or None


def stored_authcfg_id():
    return _text(_read_setting("authcfg_id")) or None


def load_session():
    access = _text(_read_setting("access_token"))
    if not access:
        return None
    try:
        expires_at = float(_read_setting("expires_at", 0) or 0)
    except (TypeError, ValueError):
        expires_at = 0.0
    session = {
        "access_token": access,
        "expires_at": expires_at,
        "email": _text(_read_setting("email")),
        "sub": _text(_read_setting("sub")),
    }
    id_token = _text(_read_setting("id_token"))
    if id_token:
        session["id_token"] = id_token
    authcfg_id = stored_authcfg_id()
    if authcfg_id:
        session["authcfg_id"] = authcfg_id
    return session


def save_session(session):
    _write_setting("access_token", session.get("access_token") or "")
    _write_setting("expires_at", float(session.get("expires_at") or 0))
    _write_setting("email", session.get("email") or "")
    _write_setting("sub", session.get("sub") or "")
    _write_setting("id_token", session.get("id_token") or "")
    _write_setting("authcfg_id", session.get("authcfg_id") or "")


def clear_session():
    """Drop the signed-in tokens. The OAuth2 configuration stays in QGIS."""
    for key in SESSION_KEYS:
        _write_setting(key, "")


def current_session(now=None):
    session = load_session()
    if not session or not session.get("sub"):
        return None
    if not token_usable(session.get("access_token"), session.get("expires_at"), now=now):
        return None
    return session


def _auth_manager():
    from qgis.core import QgsApplication
    manager = QgsApplication.authManager()
    if manager is None:
        raise AuthError("QGIS authentication is not available.")
    return manager


def _ensure_master_password(manager):
    if manager.masterPasswordIsSet():
        return
    prompt = getattr(manager, "setMasterPassword", None)
    if prompt is None:
        raise AuthError("A QGIS master password is required before the portal account can be stored.")
    try:
        ok = prompt(True)
    except TypeError:
        ok = prompt()
    if not ok:
        raise AuthError("A QGIS master password is required before the portal account can be stored.")


def _config_exists(manager, authcfg_id):
    if not authcfg_id:
        return False
    try:
        if authcfg_id in list(manager.configIds() or []):
            return True
    except Exception as err:
        _logger.debug("configIds() lookup failed: %s", err)
    try:
        return authcfg_id in (manager.availableAuthMethodConfigs() or {})
    except Exception:
        return False


def _load_auth_config(manager, authcfg_id):
    if not _config_exists(manager, authcfg_id):
        return None
    from qgis.core import QgsAuthMethodConfig
    config = QgsAuthMethodConfig()
    try:
        result = manager.loadAuthenticationConfig(authcfg_id, config, True)
    except TypeError:
        result = manager.loadAuthenticationConfig(authcfg_id, config)
    except Exception:
        return None
    if isinstance(result, tuple):
        if not result[0]:
            return None
        if len(result) > 1 and result[1]:
            return result[1]
        return config if config.id() else None
    return config if result and config.id() else None


def _store_auth_config(manager, config):
    try:
        result = manager.storeAuthenticationConfig(config, True)
    except TypeError:
        result = manager.storeAuthenticationConfig(config)
    ok = result[0] if isinstance(result, tuple) else bool(result)
    if ok:
        return True
    update = getattr(manager, "updateAuthenticationConfig", None)
    if update is None:
        return False
    try:
        result = update(config)
    except Exception:
        return False
    return result[0] if isinstance(result, tuple) else bool(result)


def ensure_auth_config(issuer_url):
    """Create or update the plugin OAuth2 configuration and return its id."""
    manager = _auth_manager()
    _ensure_master_password(manager)
    methods = []
    if hasattr(manager, "authMethodsKeys"):
        try:
            methods = list(manager.authMethodsKeys() or [])
        except Exception:
            methods = []
    if methods and "OAuth2" not in methods:
        raise AuthError("The QGIS OAuth2 authentication method is not available.")

    authcfg_id = stored_authcfg_id()
    config = _load_auth_config(manager, authcfg_id) if authcfg_id else None
    if config is None:
        from qgis.core import QgsAuthMethodConfig
        config = QgsAuthMethodConfig()
        authcfg_id = manager.uniqueConfigId()
        config.setId(authcfg_id)

    payload = oauth2_config_dict(issuer_url)
    config.setName("geoNFT portal")
    config.setMethod("OAuth2")
    config.setConfig("oauth2config", json.dumps(payload))
    config.setConfig("querypairs", json.dumps(payload["queryPairs"]))
    if not config.isValid():
        raise AuthError("The QGIS OAuth2 configuration is incomplete.")
    if not _store_auth_config(manager, config):
        config.setId(manager.uniqueConfigId())
        if not _store_auth_config(manager, config):
            raise AuthError("Could not store the QGIS OAuth2 configuration. Set a master password first.")
    authcfg_id = config.id() or authcfg_id
    _write_setting("authcfg_id", authcfg_id)
    if not _config_exists(manager, authcfg_id):
        raise AuthError(
            "QGIS did not keep the OAuth2 configuration %s. Check the master password and try again."
            % authcfg_id
        )
    _logger.info(
        "QGIS OAuth2 config %s ready (PKCE, %s:%s/%s)",
        authcfg_id,
        REDIRECT_HOST,
        REDIRECT_PORT,
        REDIRECT_PATH,
    )
    return authcfg_id


def _on_gui_thread():
    from qgis.PyQt.QtCore import QCoreApplication, QThread
    app = QCoreApplication.instance()
    if app is None:
        return False
    return QThread.currentThread() == app.thread()


def _open_browser(url):
    from qgis.PyQt.QtCore import QUrl
    from qgis.PyQt.QtGui import QDesktopServices
    return bool(QDesktopServices.openUrl(QUrl(url)))


def _loopback_handler(result):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            parsed = urlparse(self.path)
            if not redirect_path_ok(parsed.path):
                self.send_response(204)
                self.send_header("Connection", "close")
                self.end_headers()
                return
            query = parse_qs(parsed.query)
            result.update({
                "code": (query.get("code") or [""])[0],
                "state": (query.get("state") or [""])[0],
                "error": (query.get("error") or [""])[0],
                "error_description": (query.get("error_description") or [""])[0],
                "done": True,
            })
            body = _CALLBACK_PAGE.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            return

    return Handler


def _http_server(host, port, handler):
    family = socket.AF_INET6 if ":" in host else socket.AF_INET

    class Server(HTTPServer):
        address_family = family
        allow_reuse_address = True

        def server_bind(self):
            if family == socket.AF_INET6 and hasattr(socket, "IPPROTO_IPV6"):
                try:
                    self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                except OSError:
                    pass
            HTTPServer.server_bind(self)

    return Server((host, port), handler)


def _start_loopback_servers(handler):
    servers = []
    errors = []
    for host in ("127.0.0.1", "::1"):
        try:
            servers.append(_http_server(host, REDIRECT_PORT, handler))
        except OSError as err:
            errors.append("%s:%s (%s)" % (host, REDIRECT_PORT, err))
    if not servers:
        raise AuthError(
            "Could not listen on port %s (%s). Keep that port free for %s."
            % (REDIRECT_PORT, "; ".join(errors), redirect_uri())
        )
    return servers


def request_cancel():
    """Stop the browser wait. The panel calls this from Cancel."""
    _cancel.set()


def _wait_for_callback(result, timeout_s):
    if _cancel.is_set():
        raise AuthError("Cancelled.")
    try:
        from qgis.PyQt.QtCore import QCoreApplication
        app = QCoreApplication.instance()
    except Exception:
        app = None
    deadline = time.time() + timeout_s
    while not result.get("done") and time.time() < deadline:
        if _cancel.is_set():
            raise AuthError("Cancelled.")
        if app is not None:
            app.processEvents()
        time.sleep(0.05)


def _stop_loopback_servers(servers, threads):
    for server in servers:
        try:
            server.shutdown()
        except Exception as err:
            _logger.debug("Could not shut down the redirect server: %s", err)
    for thread in threads:
        thread.join(2)
    for server in servers:
        try:
            server.server_close()
        except Exception as err:
            _logger.debug("Could not close the redirect server: %s", err)


def _http_servers_on(port):
    """Plugin HTTP servers bound to port. Does not touch QGIS sockets."""
    import gc
    found = []
    for obj in gc.get_objects():
        if type(obj).__name__ not in {"HTTPServer", "Server"}:
            continue
        if not hasattr(obj, "server_close"):
            continue
        address = getattr(obj, "server_address", None)
        if isinstance(address, tuple) and len(address) >= 2 and address[1] == port:
            found.append(obj)
    return found


def _release_http_servers(port):
    released = 0
    for server in _http_servers_on(port):
        try:
            server.server_close()
            released += 1
        except Exception as err:
            _logger.debug("Could not close a leftover callback server: %s", err)
    return released


def stop_loopback():
    """Stop the callback listener and release port 7070."""
    with _loopback_lock:
        servers = list(_loopback_servers)
        threads = list(_loopback_threads)
        _loopback_servers.clear()
        _loopback_threads.clear()
    if servers or threads:
        _stop_loopback_servers(servers, threads)
    _release_http_servers(REDIRECT_PORT)


def exchange_authorization_code(issuer_url, code, verifier):
    data = urlencode(token_form(code, verifier)).encode("ascii")
    request = urllib.request.Request(
        _endpoint(issuer_url, "token"),
        data=data,
        headers={
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        method="POST",
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=30) as response:
            raw = response.read()
    except urllib.error.HTTPError as err:
        detail = err.read().decode("utf-8", "replace")[:200]
        raise AuthError("Token exchange failed (HTTP %s): %s" % (err.code, detail)) from err
    except urllib.error.URLError as err:
        raise AuthError("Token exchange failed: %s" % err.reason) from err
    try:
        body = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as err:
        raise AuthError("The token response was not JSON.") from err
    if not isinstance(body, dict):
        raise AuthError("The token response was not JSON.")
    if body.get("error"):
        detail = body.get("error_description") or body.get("error")
        raise AuthError("Token exchange failed: %s" % detail)
    return body


def _listen(urls):
    # The plugin owns this listener. QgsO2.updateNetworkRequest is not used.
    _cancel.clear()
    stop_loopback()
    result = {}
    servers = _start_loopback_servers(_loopback_handler(result))
    threads = []
    with _loopback_lock:
        _loopback_servers.extend(servers)
    try:
        for server in servers:
            thread = threading.Thread(
                target=server.serve_forever,
                kwargs={"poll_interval": 0.2},
                daemon=True,
            )
            thread.start()
            threads.append(thread)
            with _loopback_lock:
                _loopback_threads.append(thread)
        _logger.info("Listening for the portal redirect on %s", redirect_uri())
        for index, url in enumerate(urls):
            result.clear()
            if not _open_browser(url):
                raise AuthError("The system browser could not be opened.")
            _wait_for_callback(result, LOOPBACK_TIMEOUT_S)
            if not result.get("done") and index < len(urls) - 1:
                raise AuthError(
                    "Sign out of the current portal account in the browser. Registration opens after that."
                )
        return dict(result)
    finally:
        stop_loopback()


def _open_and_wait(url):
    return _listen([url])


def _browser_grant(issuer_url, registration=False, id_token=None):
    verifier = pkce_verifier()
    state = secrets.token_urlsafe(24)
    challenge = pkce_challenge(verifier)
    if registration:
        urls = account_creation_urls(issuer_url, state, challenge, id_token)
    else:
        urls = [authorize_url(issuer_url, state, challenge)]
    result = _listen(urls)
    code = authorization_code_from_callback(result, state, registration=registration)
    return exchange_authorization_code(issuer_url, code, verifier)


def acquire_session(registration=False, id_token=None):
    if not _on_gui_thread():
        raise AuthError("Sign in from the QGIS window so the browser can open.")
    issuer_url = issuer()
    authcfg_id = ensure_auth_config(issuer_url)
    body = _browser_grant(issuer_url, registration=registration, id_token=id_token)
    session = session_from_token_response(body)
    session["authcfg_id"] = authcfg_id
    save_session(session)
    _logger.info("Portal sign-in succeeded for %s", session["sub"])
    return session


LOG_TAG = "geoNFT"


def token_log_message(session):
    """Text written to the QGIS log so the access token can be copied for curl."""
    access = _text((session or {}).get("access_token"))
    claims = jwt_payload(access)
    aud = claims.get("aud")
    if isinstance(aud, list):
        aud = ",".join(str(item) for item in aud)
    exp = claims.get("exp") or (session or {}).get("expires_at")
    try:
        expires = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(float(exp)))
    except (TypeError, ValueError):
        expires = "unknown"
    return "Access token for %s (aud=%s, azp=%s, expires %s):\n%s" % (
        _text(claims.get("sub")) or _text((session or {}).get("sub")),
        _text(aud),
        _text(claims.get("azp")),
        expires,
        access,
    )


def log_token(session):
    """Write the access token to View > Panels > Log Messages, tab geoNFT."""
    message = token_log_message(session)
    try:
        from qgis.core import Qgis, QgsMessageLog
        QgsMessageLog.logMessage(message, LOG_TAG, Qgis.Info)
    except Exception:
        _logger.info("%s", message)


def sign_in():
    session = current_session()
    if session is None:
        session = acquire_session(False)
    log_token(session)
    return session


def create_account():
    if not _on_gui_thread():
        raise AuthError("Sign in from the QGIS window so the browser can open.")
    id_token = _text((load_session() or {}).get("id_token"))
    clear_session()
    return acquire_session(True, id_token=id_token)


def sign_out():
    """Clear the plugin session and end the Keycloak browser session."""
    if not _on_gui_thread():
        raise AuthError("Sign out from the QGIS window so the browser can open.")
    session = load_session() or {}
    id_token = _text(session.get("id_token"))
    clear_session()
    result = _open_and_wait(logout_url(issuer(), id_token))
    if not result.get("done"):
        raise AuthError(
            "Signed out of QGIS. Finish sign-out in the browser, or the portal may still be signed in."
        )
    _logger.info("Portal sign-out finished")
    return None
