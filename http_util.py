"""Reading HTTP bodies completely, and retrying a GET whose connection dropped mid-body.

A server or reverse proxy that closes the connection before the announced
Content-Length makes http.client raise IncompleteRead on read(), but read(n)
returns the short body silently. read_body() turns both into TruncatedBody, so a
cut picture is not mistaken for a picture with the wrong hash.

This module has no QGIS imports so the tests run with plain Python.
"""

import http.client
import time
import urllib.error

ATTEMPTS = 3
RETRY_DELAY_S = 1.0


class TruncatedBody(ConnectionError):
    """The connection closed before the whole body arrived."""

    def __init__(self, received, expected):
        self.received = received
        self.expected = expected
        super().__init__("connection closed after %s of %s bytes" % (received, expected if expected else "?"))


def _declared_length(response):
    try:
        value = response.headers.get("Content-Length")
    except AttributeError:
        return None
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def read_body(response, limit=None):
    """The response body, at most limit bytes when limit is set. Raises TruncatedBody on a short body."""
    declared = _declared_length(response)
    try:
        data = response.read() if limit is None else response.read(limit)
    except http.client.IncompleteRead as err:
        received = len(err.partial or b"")
        raise TruncatedBody(received, received + (err.expected or 0)) from err
    if declared is not None:
        wanted = declared if limit is None else min(declared, limit)
        if len(data) < wanted:
            raise TruncatedBody(len(data), declared)
    return data


def transient(err):
    """True for a dropped connection, which a GET may simply repeat."""
    if isinstance(err, (TruncatedBody, http.client.IncompleteRead, http.client.RemoteDisconnected,
                        ConnectionResetError, ConnectionAbortedError, BrokenPipeError)):
        return True
    if isinstance(err, urllib.error.URLError) and not isinstance(err, urllib.error.HTTPError):
        return isinstance(err.reason, (ConnectionResetError, ConnectionAbortedError, BrokenPipeError,
                                       http.client.RemoteDisconnected))
    return False


def with_retries(call, attempts=ATTEMPTS, delay=None, sleep=time.sleep, on_retry=None):
    """call() up to attempts times while it fails with a dropped connection; the last error is raised."""
    delay = RETRY_DELAY_S if delay is None else delay
    for attempt in range(1, attempts + 1):
        try:
            return call()
        except Exception as err:
            if attempt == attempts or not transient(err):
                raise
            if on_retry is not None:
                on_retry(attempt, err)
            sleep(delay * attempt)
    return None


def size_text(count):
    """Bytes as KB/MB for messages."""
    if count is None:
        return "?"
    if count >= 1024 * 1024:
        return "%.1f MB" % (count / (1024 * 1024))
    if count >= 1024:
        return "%d KB" % round(count / 1024)
    return "%d bytes" % count
