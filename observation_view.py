"""What an observation is (image or telemetry) and how its details read.

Connected Systems marks each observation with resultType "image" or
"telemetry". Older servers do not, so the result's shape decides then, by the
same rule the server uses: an image result is { contentType, cid, url, sha256 }
(IPFS) or { contentType, body } (base64 bytes on a server without IPFS).
This module has no QGIS imports so the tests run with plain Python.
"""

import base64
import binascii
import html
import json
import re

IMAGE = "image"
TELEMETRY = "telemetry"
KINDS = (IMAGE, TELEMETRY)

_IPFS_PATH = re.compile(r"/ipfs/[^/?#]+$")

# Shown above the result, in this order, when present.
METADATA = (
    ("phenomenonTime", "Time"),
    ("datastreamId", "Datastream"),
    ("observation_id", "Observation"),
    ("droneDid", "Drone"),
    ("receivedVia", "Received via"),
    ("anchorHash", "Anchor hash"),
)


def result_kind(result):
    if not isinstance(result, dict) or not isinstance(result.get("contentType"), str):
        return TELEMETRY
    cid = result.get("cid")
    url = result.get("url")
    ipfs = (isinstance(cid, str) and cid != "") or (isinstance(url, str) and bool(_IPFS_PATH.search(url)))
    return IMAGE if ipfs or isinstance(result.get("body"), str) else TELEMETRY


def kind_of(observation):
    """IMAGE or TELEMETRY for an Observation (or Feature properties) dict."""
    declared = observation.get("resultType")
    if declared in KINDS:
        return declared
    return result_kind(observation.get("result"))


def parse_result(value):
    """The result as JSON again; flattened layers keep it as JSON text."""
    if isinstance(value, str):
        try:
            return json.loads(value)
        except ValueError:
            return value
    return value


def image_reference(result):
    """{"url": gateway link or None, "data": inline bytes or None} of an image result."""
    result = result if isinstance(result, dict) else {}
    url = result.get("url") if isinstance(result.get("url"), str) and result.get("url") else None
    data = None
    if isinstance(result.get("body"), str):
        try:
            data = base64.b64decode(result["body"], validate=True)
        except (binascii.Error, ValueError):
            data = None
    return {"url": url, "data": data}


def short_time(value):
    text = str(value or "")
    return text[11:19] if len(text) >= 19 and text[10] in "T " else text


def tab_title(kind, properties):
    time = short_time(properties.get("phenomenonTime"))
    name = "Image" if kind == IMAGE else "Telemetry"
    return "%s %s" % (name, time) if time else name


def _value_html(value):
    if isinstance(value, dict):
        if not value:
            return "<i>{}</i>"
        rows = "".join(
            "<tr><th align='left' valign='top'>%s</th><td>%s</td></tr>" % (html.escape(str(k)), _value_html(v))
            for k, v in value.items()
        )
        return "<table border='0' cellspacing='0' cellpadding='3'>%s</table>" % rows
    if isinstance(value, list):
        if not value:
            return "<i>[]</i>"
        if all(not isinstance(v, (dict, list)) for v in value):
            return html.escape(", ".join(_scalar_text(v) for v in value))
        rows = "".join(
            "<tr><th align='left' valign='top'>%d</th><td>%s</td></tr>" % (i, _value_html(v))
            for i, v in enumerate(value)
        )
        return "<table border='0' cellspacing='0' cellpadding='3'>%s</table>" % rows
    return html.escape(_scalar_text(value))


def _scalar_text(value):
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    return str(value)


def metadata_html(properties):
    rows = []
    for key, label in METADATA:
        value = properties.get(key)
        if value in (None, ""):
            continue
        rows.append("<tr><th align='left'>%s</th><td>%s</td></tr>" % (label, html.escape(str(value))))
    if not rows:
        return ""
    return "<table border='0' cellspacing='0' cellpadding='3'>%s</table>" % "".join(rows)


def telemetry_html(properties):
    """The observation's details with its JSON result rendered as nested tables."""
    result = parse_result(properties.get("result"))
    return (
        "<html><body>"
        "%s"
        "<h3>Result</h3>%s"
        "</body></html>"
    ) % (metadata_html(properties), _value_html(result))
