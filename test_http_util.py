import json
import socket
import sys
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import cs_api
import deployment_verify
import http_util


class ShortBodyServer:
    """Answers every request with Content-Length of the full body; the first `cut` requests send only part of it."""

    def __init__(self, body, cut, keep=100):
        self.body, self.cut, self.keep = body, cut, keep
        self.requests = 0
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.url = "http://127.0.0.1:%d/deployments/d1/observations" % self.sock.getsockname()[1]
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            with conn:
                data = b""
                while b"\r\n\r\n" not in data:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                self.requests += 1
                head = ("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\n"
                        "Connection: close\r\n\r\n" % len(self.body)).encode()
                payload = self.body[:self.keep] if self.requests <= self.cut else self.body
                conn.sendall(head + payload)

    def close(self):
        self.sock.close()


def _no_sleep(_seconds):
    return None


class HttpUtilTests(unittest.TestCase):
    def setUp(self):
        self.body = json.dumps({"type": "FeatureCollection", "features": [], "pad": "x" * 5000}).encode()

    def test_json_read_retries_a_cut_body(self):
        server = ShortBodyServer(self.body, cut=1)
        try:
            result = cs_api.http_get_json(server.url, "tok", 10, sleep=_no_sleep)
        finally:
            server.close()
        self.assertEqual(result["type"], "FeatureCollection")
        self.assertEqual(server.requests, 2)

    def test_json_read_reports_a_body_that_stays_cut(self):
        server = ShortBodyServer(self.body, cut=99)
        try:
            with self.assertRaises(cs_api.CsApiError) as caught:
                cs_api.http_get_json(server.url, "tok", 10, attempts=3, sleep=_no_sleep)
        finally:
            server.close()
        message = str(caught.exception)
        self.assertEqual(server.requests, 3)
        self.assertIn("closed the connection after 100 bytes of 5 KB", message)
        self.assertIn("/deployments/d1/observations", message)
        self.assertIn("connection closed after 100 of %d bytes" % len(self.body), caught.exception.detail)

    def test_picture_read_with_a_limit_does_not_return_a_cut_body(self):
        server = ShortBodyServer(b"\x89PNG" + b"\0" * 4000, cut=99)
        original = http_util.RETRY_DELAY_S
        http_util.RETRY_DELAY_S = 0
        try:
            with self.assertRaises(cs_api.CsApiError) as caught:
                deployment_verify.http_get_bytes(server.url.replace("/deployments/d1/observations", "/ipfs/x"))
        finally:
            http_util.RETRY_DELAY_S = original
            server.close()
        self.assertIn("closed the connection after 100 bytes", str(caught.exception))

    def test_with_retries_does_not_repeat_other_errors(self):
        calls = []

        def fail():
            calls.append(1)
            raise ValueError("no")

        with self.assertRaises(ValueError):
            http_util.with_retries(fail, sleep=_no_sleep)
        self.assertEqual(len(calls), 1)

    def test_size_text(self):
        self.assertEqual(http_util.size_text(179963), "176 KB")
        self.assertEqual(http_util.size_text(716267), "699 KB")
        self.assertEqual(http_util.size_text(3 * 1024 * 1024), "3.0 MB")
        self.assertEqual(http_util.size_text(None), "?")


if __name__ == "__main__":
    unittest.main()
