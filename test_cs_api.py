import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import cs_api


def _deployment(dep_id, label, valid_from):
    return {
        "id": dep_id,
        "type": "Deployment",
        "properties": {"label": label, "validFrom": valid_from, "validTo": "2026-11-03T07:31:16.100Z", "systemId": "sys-1"},
        "geometry": None,
    }


class FakeFetch:
    def __init__(self, pages):
        self.pages = pages
        self.calls = []

    def __call__(self, url, token, timeout):
        self.calls.append((url, token, timeout))
        return self.pages[url]


class CsApiTests(unittest.TestCase):
    def test_base_defaults_to_live_cs_and_strips_slash(self):
        self.assertEqual(cs_api.normalize_base(None), "https://cs.geonft.eu")
        self.assertEqual(cs_api.normalize_base("https://cs.example/ "), "https://cs.example")

    def test_portal_base_is_the_issuer_prefix_unless_set(self):
        self.assertEqual(cs_api.portal_base("https://portal.geonft.eu/realms/customers"), "https://portal.geonft.eu")
        self.assertEqual(cs_api.portal_base("https://x/realms/customers", "https://other/ "), "https://other")
        with self.assertRaises(cs_api.CsApiError):
            cs_api.portal_base("https://portal.geonft.eu")

    def test_lists_licensed_deployments_from_the_portal_newest_first_across_pages(self):
        fetch = FakeFetch({
            "https://portal.geonft.eu/licensed-deployments": {
                "type": "Collection",
                "items": [_deployment("dep-1", "flight-1", "2026-11-01T10:00:00Z")],
                "links": [{"rel": "next", "href": "/licensed-deployments?offset=1"}],
            },
            "https://portal.geonft.eu/licensed-deployments?offset=1": {
                "type": "Collection",
                "items": [_deployment("dep-2", "flight-2", "2026-11-02T10:00:00Z")],
                "links": [{"rel": "self", "href": "/licensed-deployments?offset=1"}],
            },
        })
        deployments = cs_api.list_deployments("https://portal.geonft.eu/", "tok", fetch=fetch)
        self.assertEqual([d["id"] for d in deployments], ["dep-2", "dep-1"])
        self.assertEqual(deployments[0]["label"], "flight-2")
        self.assertEqual(deployments[0]["systemId"], "sys-1")
        self.assertEqual([call[1] for call in fetch.calls], ["tok", "tok"])

    def test_a_next_link_loop_stops(self):
        url = "https://portal.geonft.eu/licensed-deployments"
        fetch = FakeFetch({url: {"items": [], "links": [{"rel": "next", "href": url}]}})
        self.assertEqual(cs_api.list_deployments("https://portal.geonft.eu", "tok", fetch=fetch), [])
        self.assertEqual(len(fetch.calls), 1)

    def test_observations_merge_feature_pages_and_quote_the_id(self):
        first = "https://cs.geonft.eu/deployments/dep%2Fx/observations?limit=1000"
        second = "https://cs.geonft.eu/deployments/dep%2Fx/observations?page=2"
        point = {"type": "Feature", "id": "obs-1", "geometry": {"type": "Point", "coordinates": [7.1, 51.2]}, "properties": {}}
        fetch = FakeFetch({
            first: {"type": "FeatureCollection", "features": [point], "links": [{"rel": "next", "href": second}]},
            second: {"type": "FeatureCollection", "features": [dict(point, id="obs-2")]},
        })
        collection = cs_api.deployment_observations(None, "tok", "dep/x", fetch=fetch)
        self.assertEqual(collection["type"], "FeatureCollection")
        self.assertEqual([f["id"] for f in collection["features"]], ["obs-1", "obs-2"])
        self.assertEqual(fetch.calls[0][2], cs_api.OBSERVATIONS_TIMEOUT_S)

    def test_observations_follow_every_next_link_and_skip_repeats(self):
        base = "https://cs.geonft.eu/deployments/dep-1/observations"
        first = base + "?limit=1000"
        second = base + "?limit=1000&offset=2"
        third = base + "?limit=1000&offset=4"
        page = lambda ids, links: {"type": "Collection", "numberMatched": 5, "links": links,
                                   "items": [{"id": i, "type": "Observation"} for i in ids]}
        fetch = FakeFetch({
            first: page([5, 4], [{"rel": "self", "href": first}, {"rel": "next", "href": second}]),
            # a new observation arrived meanwhile, so 4 shows up again
            second: page([4, 3], [{"rel": "prev", "href": first}, {"rel": "next", "href": third}]),
            third: page([2, 1], [{"rel": "prev", "href": second}]),
        })
        collection = cs_api.deployment_observations(None, "tok", "dep-1", fetch=fetch)
        self.assertEqual([f["id"] for f in collection["features"]], [5, 4, 3, 2, 1])
        self.assertEqual(collection["numberMatched"], 5)
        self.assertEqual([call[0] for call in fetch.calls], [first, second, third])

    def test_observations_without_a_next_link_report_what_matched(self):
        url = "https://cs.geonft.eu/deployments/dep-1/observations?limit=1000"
        fetch = FakeFetch({url: {"numberMatched": 3000, "items": [{"id": 1}], "links": [{"rel": "self", "href": url}]}})
        collection = cs_api.deployment_observations(None, "tok", "dep-1", fetch=fetch)
        self.assertEqual(len(collection["features"]), 1)
        self.assertEqual(collection["numberMatched"], 3000)

    def test_observation_items_become_features_at_their_feature_of_interest(self):
        url = "https://cs.geonft.eu/deployments/dep-1/observations?limit=1000"
        fetch = FakeFetch({url: {"numberMatched": 3, "items": [
            {"id": 1, "type": "Observation", "phenomenonTime": "t1", "result": {"sha256": "ab"},
             "featureOfInterest": {"type": "Feature", "geometry": {"type": "Point", "coordinates": [7.1, 51.2]}, "properties": {}}},
            {"id": 2, "type": "Observation", "featureOfInterest": {"type": "Point", "coordinates": [7.2, 51.3]}},
            {"id": 3, "type": "Observation", "featureOfInterest": None},
        ]}})
        features = cs_api.deployment_observations(None, "tok", "dep-1", fetch=fetch)["features"]
        self.assertEqual([f["id"] for f in features], [1, 2, 3])
        self.assertEqual(features[0]["geometry"], {"type": "Point", "coordinates": [7.1, 51.2]})
        self.assertEqual(features[1]["geometry"]["coordinates"], [7.2, 51.3])
        self.assertIsNone(features[2]["geometry"])
        self.assertEqual(features[0]["properties"]["phenomenonTime"], "t1")
        self.assertNotIn("featureOfInterest", features[0]["properties"])

    def test_observations_that_are_not_a_feature_collection_fail_with_the_body(self):
        url = "https://cs.geonft.eu/deployments/dep-1/observations?limit=1000"
        fetch = FakeFetch({url: {"type": "Collection", "members": []}})
        with self.assertRaises(cs_api.CsApiError) as caught:
            cs_api.deployment_observations(None, "tok", "dep-1", fetch=fetch)
        self.assertIn('"members"', caught.exception.detail)

    def test_observations_are_marked_image_or_telemetry(self):
        url = "https://cs.geonft.eu/deployments/dep-1/observations?limit=1000"
        ipfs = {"contentType": "application/octet-stream", "cid": "bafy1", "url": "https://ipfs.geonft.eu/ipfs/bafy1", "sha256": "ab"}
        fetch = FakeFetch({url: {"items": [
            {"id": 1, "resultType": "image", "result": ipfs},
            {"id": 2, "resultType": "telemetry", "result": {"lat": 51.2, "lon": 7.1}},
            {"id": 3, "result": ipfs},
            {"id": 4, "result": {"contentType": "application/octet-stream", "body": "AAE="}},
            {"id": 5, "result": {"lat": 51.2, "lon": 7.1}},
        ]}})
        features = cs_api.deployment_observations(None, "tok", "dep-1", fetch=fetch)["features"]
        kinds = [f["properties"]["kind"] for f in features]
        self.assertEqual(kinds, ["image", "telemetry", "image", "image", "telemetry"])
        urls = [f["properties"]["image_url"] for f in features]
        self.assertEqual(urls, [ipfs["url"], None, ipfs["url"], None, None])

    def test_flatten_keeps_scalars_and_turns_nested_values_into_json(self):
        collection = {"type": "FeatureCollection", "features": [{
            "type": "Feature",
            "id": 42,
            "geometry": {"type": "Point", "coordinates": [7.1, 51.2]},
            "properties": {"phenomenonTime": "2026-11-02T18:20:00Z", "result": {"sha256": "ab"}, "tags": [1, 2]},
        }]}
        flat = cs_api.flatten_feature_collection(collection)
        properties = flat["features"][0]["properties"]
        self.assertEqual(properties["observation_id"], "42")
        self.assertEqual(properties["phenomenonTime"], "2026-11-02T18:20:00Z")
        self.assertEqual(json.loads(properties["result"]), {"sha256": "ab"})
        self.assertEqual(properties["tags"], "[1, 2]")
        self.assertEqual(flat["features"][0]["geometry"], collection["features"][0]["geometry"])

    def test_status_messages_name_the_cause(self):
        self.assertIn("Sign in again", cs_api._status_message(401, "x"))
        self.assertIn("license", cs_api._status_message(403, "https://cs/deployments/d/observations"))
        self.assertIn("email", cs_api._status_message(403, "https://portal/licensed-deployments"))
        self.assertTrue(cs_api._status_message(401, "https://portal/licensed-deployments").startswith("The portal"))

    def test_deployment_title_shows_label_and_times(self):
        deployment = cs_api.deployment_from_item(_deployment("dep-1", "flight-1", "2026-11-01T10:00:00Z"))
        self.assertEqual(cs_api.deployment_title(deployment), "flight-1  (2026-11-01 10:00 → 2026-11-03 07:31)")


if __name__ == "__main__":
    unittest.main()
