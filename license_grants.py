"""Whether the next licensed read of a deployment will ask the user's wallet.

Connected Systems caches a proved license per user and deployment for a few
minutes and tells the client until when, in the License-Grant-Expires header of
a licensed read. The plugin remembers that moment per account (token sub) and
deployment, so the panel asks the user to approve in the wallet app only when
the server will actually ask.

The record lives in memory, like the server's cache. A 403 license_required
drops it. When in doubt (no header seen, too close to the end) the answer is
"the wallet will be asked".

This module has no QGIS imports so the tests run with plain Python.
"""

import base64
import datetime
import json
import re
import threading
import time
from urllib.parse import unquote, urlsplit

HEADER = "License-Grant-Expires"
# A grant that ends within this many seconds counts as ended: the request itself takes time.
MARGIN_S = 15

_DEPLOYMENT_PATH = re.compile(r"/deployments/([^/?#]+)/(?:observations|manifest|lineage)(?:/|$)")
_grants = {}
_inflight = {}  # request number -> (deployment id, start time)
_counter = [0]
_lock = threading.Lock()


def token_sub(token):
    """The sub claim of a JWT, without verifying it (the server does), or ""."""
    parts = str(token or "").split(".")
    if len(parts) < 2:
        return ""
    payload = parts[1] + "=" * (-len(parts[1]) % 4)
    try:
        claims = json.loads(base64.urlsafe_b64decode(payload.encode("ascii")))
    except (ValueError, UnicodeError):
        return ""
    return str(claims.get("sub") or "") if isinstance(claims, dict) else ""


def deployment_of(url):
    """The deployment id of a licensed Connected Systems read (observations, lineage or manifest), or None."""
    match = _DEPLOYMENT_PATH.search(urlsplit(str(url or "")).path)
    return unquote(match.group(1)) if match else None


def parse_time(value):
    """Epoch seconds of an RFC 3339 time such as 2026-11-19T12:05:00.000Z, or None."""
    text = str(value or "").strip()
    if not text:
        return None
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        moment = datetime.datetime.fromisoformat(text)
    except ValueError:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=datetime.timezone.utc)
    return moment.timestamp()


def observe(url, token, header_value):
    """Record the header of a successful licensed read. Returns the expiry it stored, or None."""
    deployment_id = deployment_of(url)
    sub = token_sub(token)
    expires = parse_time(header_value)
    if not deployment_id or not sub or expires is None:
        return None
    with _lock:
        _grants[(sub, deployment_id)] = expires
    return expires


def forget(token, url=None, deployment_id=None):
    """Drop the record after the server refused the license (403) or the token."""
    deployment_id = deployment_id or deployment_of(url)
    sub = token_sub(token)
    with _lock:
        if deployment_id and sub:
            _grants.pop((sub, deployment_id), None)
        elif sub:
            for key in [key for key in _grants if key[0] == sub]:
                del _grants[key]


def seconds_left(token, deployment_id, now=None):
    """Seconds until the server's cached grant for this account and deployment ends, or 0."""
    now = time.time() if now is None else now
    with _lock:
        expires = _grants.get((token_sub(token), str(deployment_id or "")))
    return max(0.0, expires - now) if expires is not None else 0.0


def wallet_needed(token, deployment_id, now=None):
    """True unless the server has a cached grant for this account and deployment for a while longer."""
    return seconds_left(token, deployment_id, now) <= MARGIN_S


def begin(url, now=None):
    """Mark a licensed read as started; returns a handle for end(), or None for other reads."""
    deployment_id = deployment_of(url)
    if not deployment_id:
        return None
    with _lock:
        _counter[0] += 1
        handle = _counter[0]
        _inflight[handle] = (deployment_id, time.time() if now is None else now)
    return handle


def end(handle):
    if handle is None:
        return
    with _lock:
        _inflight.pop(handle, None)


def waiting_seconds(deployment_id, now=None):
    """How long the oldest licensed read of this deployment has been waiting for its answer, or None."""
    now = time.time() if now is None else now
    with _lock:
        starts = [start for dep, start in _inflight.values() if dep == str(deployment_id or "")]
    return now - min(starts) if starts else None


# With a cached grant a licensed read answers in about a second. One that waits this long is most likely
# asking the wallet after all (server restarted, grant revoked), so the panel says so.
SLOW_S = 8.0


def status_text(token, deployment_id, waiting, wallet_prompt, now=None):
    """What the panel shows while reading: wallet_prompt only while a licensed read waits on the wallet."""
    waited = waiting_seconds(deployment_id, now)
    if waited is None:
        return waiting
    if wallet_needed(token, deployment_id, now) or waited >= SLOW_S:
        return wallet_prompt
    return waiting


def clear():
    with _lock:
        _grants.clear()
        _inflight.clear()
