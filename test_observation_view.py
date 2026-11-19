import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import observation_view as view


class ObservationViewTests(unittest.TestCase):
    def test_declared_result_type_wins(self):
        self.assertEqual(view.kind_of({"resultType": "telemetry", "result": {"contentType": "x", "cid": "c"}}), "telemetry")
        self.assertEqual(view.kind_of({"resultType": "image", "result": {}}), "image")

    def test_shape_decides_without_result_type(self):
        self.assertEqual(view.kind_of({"result": {"contentType": "application/octet-stream", "cid": "bafy"}}), "image")
        self.assertEqual(view.kind_of({"result": {"contentType": "a", "url": "http://localhost:8091/ipfs/bafy"}}), "image")
        self.assertEqual(view.kind_of({"result": {"contentType": "a", "body": "AAE="}}), "image")
        self.assertEqual(view.kind_of({"result": {"url": "https://ipfs.geonft.eu/ipfs/bafy"}}), "telemetry")
        self.assertEqual(view.kind_of({"result": {"lat": 1, "lon": 2}}), "telemetry")
        self.assertEqual(view.kind_of({"result": '{"contentType": "a", "cid": "c"}'}), "telemetry")
        self.assertEqual(view.kind_of({}), "telemetry")

    def test_image_reference_gives_url_or_inline_bytes(self):
        self.assertEqual(view.image_reference({"url": "https://g/ipfs/c"}), {"url": "https://g/ipfs/c", "data": None})
        self.assertEqual(view.image_reference({"body": "AAE="}), {"url": None, "data": b"\x00\x01"})
        self.assertEqual(view.image_reference({"body": "not base64!"}), {"url": None, "data": None})
        self.assertEqual(view.image_reference(None), {"url": None, "data": None})

    def test_telemetry_html_renders_nested_json_escaped(self):
        page = view.telemetry_html({
            "phenomenonTime": "2026-11-16T10:20:30Z",
            "observation_id": "7",
            "result": '{"lat": 51.2, "gps": {"fix": 3, "sats": [1, 2]}, "note": "<b>x</b>", "ok": true, "v": null}',
        })
        self.assertIn("<th align='left'>Time</th><td>2026-11-16T10:20:30Z</td>", page)
        self.assertIn("<th align='left' valign='top'>fix</th><td>3</td>", page)
        self.assertIn("<td>1, 2</td>", page)
        self.assertIn("&lt;b&gt;x&lt;/b&gt;", page)
        self.assertNotIn("<b>x</b>", page)
        self.assertIn("<td>true</td>", page)
        self.assertIn("<td>null</td>", page)

    def test_tab_title(self):
        self.assertEqual(view.tab_title("image", {"phenomenonTime": "2026-11-16T10:20:30.5Z"}), "Image 10:20:30")
        self.assertEqual(view.tab_title("telemetry", {}), "Telemetry")


if __name__ == "__main__":
    unittest.main()
