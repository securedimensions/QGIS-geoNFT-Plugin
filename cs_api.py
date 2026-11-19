"""Portal and Connected Systems reads for the geoNFT plugin.

The portal's GET /licensed-deployments lists the flights this account holds a
valid license for. Connected Systems lists deployments only to service accounts,
so the plugin does not ask it. GET {cs}/deployments/{id}/observations answers a
GeoJSON FeatureCollection, or a collection of Observation items whose
featureOfInterest carries the geometry; Connected Systems first asks the portal
to prove the license, which can prompt the wallet.
This module has no QGIS imports so the tests run with plain Python.
"""

import json
import urllib.error
import urllib.request
from urllib.parse import quote, urljoin, urlsplit

try:
    from . import http_util, license_grants, observation_view
except ImportError:  # the tests import this module as top level
    import http_util
    import license_grants
    import observation_view

DEFAULT_CS_URL = "https://cs.geonft.eu"
LIST_TIMEOUT_S = 30
OBSERVATIONS_TIMEOUT_S = 180
MAX_PAGES = 100
# Pages of LIMIT observations each; a guard against a server that never stops
# sending next, not a cap a real flight should reach.
OBSERVATION_MAX_PAGES = 100
LIMIT = 1000


class CsApiError(RuntimeError):
    """A Connected Systems call failed. detail holds the response body for the log."""

    def __init__(self, message, status=None, detail=""):
        super().__init__(message)
        self.status = status
        self.detail = detail


def normalize_base(value, default=DEFAULT_CS_URL):
    text = str(value or "").strip().rstrip("/")
    return text or default


def portal_base(issuer, override=None):
    """The portal serves Keycloak under /realms, so the portal is the issuer's prefix."""
    if override:
        return normalize_base(override)
    text = normalize_base(issuer, "")
    index = text.find("/realms/")
    if index <= 0:
        raise CsApiError("The portal address cannot be derived from the issuer %s." % issuer)
    return text[:index]


def _service(url):
    return "The portal" if url.split("?", 1)[0].endswith("/licensed-deployments") else "Connected Systems"


def _status_message(status, what):
    service = _service(what)
    if status == 401:
        return "%s rejected the sign-in (401). Sign in again." % service
    if status == 403:
        if service == "The portal":
            return "The portal refused the list (403). Verify the account's email address first."
        return "Connected Systems refused %s (403). The license was not proved for this account." % what
    if status == 404:
        return "%s does not know %s (404)." % (service, what)
    return "%s answered %s for %s." % (service, status, what)


def http_get_json(url, token, timeout, attempts=http_util.ATTEMPTS, sleep=None):
    """GET url with the bearer token and return the decoded JSON body.

    A connection that drops before the whole body arrived is tried again (attempts in all).
    Connected Systems caches a granted license for a few minutes, so a retry does not ask the wallet again.
    """
    try:
        raw = http_util.with_retries(
            lambda: _get_once(url, token, timeout),
            attempts=attempts,
            **({"sleep": sleep} if sleep is not None else {}),
        )
    except http_util.TruncatedBody as err:
        raise CsApiError(
            "%s closed the connection after %s of %s of %s (%d attempts). Try again; if it keeps happening, "
            "the proxy in front of the server is cutting large responses." % (
                _service(url), http_util.size_text(err.received), http_util.size_text(err.expected),
                urlsplit(url).path, attempts),
            None,
            "GET %s: %s" % (url, err),
        ) from err
    except OSError as err:  # a dropped connection (or URLError wrapping one) that outlasted the retries
        raise CsApiError("%s dropped the connection: %s" % (_service(url), err), None, "GET %s: %r" % (url, err)) from err
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as err:
        snippet = raw[:2000].decode("utf-8", "replace")
        raise CsApiError("%s did not answer with JSON." % _service(url), None, snippet) from err


def _get_once(url, token, timeout):
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/geo+json, application/json",
            "Authorization": "Bearer %s" % token,
        },
        method="GET",
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    handle = license_grants.begin(url)  # the panel watches how long a licensed read waits (wallet)
    try:
        with opener.open(request, timeout=timeout) as response:
            body = http_util.read_body(response)
            # Until when Connected Systems will not ask the wallet again for this deployment.
            license_grants.observe(url, token, response.headers.get(license_grants.HEADER))
            return body
    except urllib.error.HTTPError as err:
        detail = err.read().decode("utf-8", "replace")[:2000]
        if err.code in (401, 403):
            license_grants.forget(token, url)
        raise CsApiError(_status_message(err.code, url), err.code, detail) from err
    except urllib.error.URLError as err:
        if http_util.transient(err):
            raise
        raise CsApiError("%s is unavailable: %s" % (_service(url), err.reason)) from err
    except TimeoutError as err:
        raise CsApiError("%s did not answer within %s s." % (_service(url), timeout)) from err
    finally:
        license_grants.end(handle)


def next_link(body, current_url):
    for link in (body or {}).get("links") or []:
        if isinstance(link, dict) and link.get("rel") == "next" and link.get("href"):
            return urljoin(current_url, link["href"])
    return None


def _pages(url, token, timeout, fetch, max_pages=MAX_PAGES):
    seen = set()
    while url and url not in seen and len(seen) < max_pages:
        seen.add(url)
        body = fetch(url, token, timeout)
        if not isinstance(body, dict):
            raise CsApiError("Connected Systems answered with an unexpected document.", None, json.dumps(body)[:2000])
        yield body
        url = next_link(body, url)


def deployment_from_item(item):
    properties = item.get("properties") or {}
    deployment_id = str(item.get("id") or "")
    return {
        "id": deployment_id,
        "label": properties.get("label") or properties.get("name") or deployment_id,
        "validFrom": properties.get("validFrom"),
        "validTo": properties.get("validTo"),
        "systemId": properties.get("systemId"),
    }


def _short_time(value):
    text = str(value or "")
    return text[:16].replace("T", " ") if text else "…"


def deployment_title(deployment):
    return "%s  (%s → %s)" % (
        deployment["label"],
        _short_time(deployment.get("validFrom")),
        _short_time(deployment.get("validTo")),
    )


def list_deployments(portal, token, fetch=http_get_json):
    """Deployments the account holds a valid license for, newest first."""
    url = "%s/licensed-deployments" % normalize_base(portal, "")
    deployments = []
    for body in _pages(url, token, LIST_TIMEOUT_S, fetch):
        for item in body.get("items") or body.get("features") or []:
            if isinstance(item, dict) and item.get("id"):
                deployments.append(deployment_from_item(item))
    deployments.sort(key=lambda d: str(d.get("validFrom") or ""), reverse=True)
    return deployments


def deployment_observations(base, token, deployment_id, fetch=http_get_json):
    """All pages of the deployment's observations as one FeatureCollection.

    Follows rel=next until Connected Systems stops sending it. An observation
    seen on an earlier page is skipped: during a live flight new observations
    push older ones onto the next page. numberMatched is the server's count
    from the first page (None if it sent none), so a caller can tell when
    fewer were loaded.
    """
    url = "%s/deployments/%s/observations?limit=%s" % (normalize_base(base), quote(str(deployment_id), safe=""), str(LIMIT))
    features = []
    seen_ids = set()
    number_matched = None
    for body in _pages(url, token, OBSERVATIONS_TIMEOUT_S, fetch, OBSERVATION_MAX_PAGES):
        if number_matched is None and isinstance(body.get("numberMatched"), int):
            number_matched = body["numberMatched"]
        if isinstance(body.get("features"), list):
            members = body["features"]
        elif isinstance(body.get("items"), list):
            members = body["items"]
        else:
            raise CsApiError(
                "Connected Systems did not answer with a FeatureCollection.", None, json.dumps(body)[:2000]
            )
        for member in members:
            if not isinstance(member, dict):
                continue
            member_id = member.get("id")
            if member_id is not None:
                if member_id in seen_ids:
                    continue
                seen_ids.add(member_id)
            features.append(feature_from_observation(member))
    return {"type": "FeatureCollection", "features": features, "numberMatched": number_matched}


GEOMETRY_TYPES = {
    "Point", "MultiPoint", "LineString", "MultiLineString", "Polygon", "MultiPolygon", "GeometryCollection",
}


def _geometry_of(value):
    """A GeoJSON geometry from a geometry, a Feature, or the first located Feature of a collection."""
    if not isinstance(value, dict):
        return None
    kind = value.get("type")
    if kind in GEOMETRY_TYPES:
        return value
    if kind == "Feature" or "geometry" in value:
        return _geometry_of(value.get("geometry"))
    if kind == "FeatureCollection":
        for feature in value.get("features") or []:
            geometry = _geometry_of(feature)
            if geometry:
                return geometry
    return None


def _with_kind(properties):
    """Add kind (image or telemetry) and image_url, present on every feature so QGIS makes the columns."""
    kind = observation_view.kind_of(properties)
    properties["kind"] = kind
    properties["image_url"] = (
        observation_view.image_reference(observation_view.parse_result(properties.get("result")))["url"]
        if kind == observation_view.IMAGE else None
    )
    return properties


def feature_from_observation(observation):
    """A Connected Systems Observation as a GeoJSON Feature located at its featureOfInterest."""
    if observation.get("type") == "Feature":
        return dict(observation, properties=_with_kind(dict(observation.get("properties") or {})))
    properties = _with_kind({k: v for k, v in observation.items() if k not in ("id", "featureOfInterest")})
    return {
        "type": "Feature",
        "id": observation.get("id"),
        "geometry": _geometry_of(observation.get("featureOfInterest")),
        "properties": properties,
    }


def _flat_value(value):
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return value


def flatten_feature_collection(collection):
    """Copy with scalar properties only, so QGIS gets plain attribute columns.

    Nested objects and arrays become JSON text. The feature id is kept as the
    attribute observation_id.
    """
    features = []
    for feature in collection.get("features") or []:
        properties = {"observation_id": None if feature.get("id") is None else str(feature.get("id"))}
        for key, value in (feature.get("properties") or {}).items():
            properties[str(key)] = _flat_value(value)
        features.append({
            "type": "Feature",
            "id": feature.get("id"),
            "geometry": feature.get("geometry"),
            "properties": properties,
        })
    return {"type": "FeatureCollection", "features": features}
