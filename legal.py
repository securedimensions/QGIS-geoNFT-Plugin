"""Privacy statement, terms of use and cookie statement of the geoNFT plugin.

The documents are HTML files in docs/. Operator details come from docs/operator.ini
and replace the {{operator_*}} placeholders. The user accepts the terms once per
LEGAL_VERSION before the plugin contacts any online service; raising LEGAL_VERSION
asks again.

This module has no QGIS imports so the tests run with plain Python.
"""

import configparser
import datetime
import html
import os
import re

LEGAL_VERSION = "2026-11-19"
DOCS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "docs")

PRIVACY = "privacy.html"
TERMS = "terms.html"
COOKIES = "cookies.html"
DOCUMENTS = {
    PRIVACY: "Privacy statement",
    TERMS: "Terms of use",
    COOKIES: "Cookie statement",
}

ACCEPTED_KEY = "terms_accepted_version"
ACCEPTED_AT_KEY = "terms_accepted_at"
OPERATOR_FIELDS = ("name", "address", "email", "website", "dpo", "jurisdiction")
PLACEHOLDER = "CHANGE_ME"

_TOKEN = re.compile(r"\{\{([a-z_]+)\}\}")


def load_operator(docs_dir=DOCS_DIR):
    """{field: value} from docs/operator.ini; missing fields are empty strings."""
    parser = configparser.ConfigParser(interpolation=None)
    parser.read(os.path.join(docs_dir, "operator.ini"), encoding="utf-8")
    section = parser["operator"] if parser.has_section("operator") else {}
    return {field: str(section.get(field, "") or "").strip() for field in OPERATOR_FIELDS}


def unfinished_operator_fields(operator):
    """Fields that still hold the CHANGE_ME placeholder or are empty but required."""
    required = ("name", "address", "email", "jurisdiction")
    return [field for field in OPERATOR_FIELDS
            if PLACEHOLDER in operator.get(field, "") or (field in required and not operator.get(field))]


def _values(operator):
    values = {"legal_version": LEGAL_VERSION}
    for field in OPERATOR_FIELDS:
        values["operator_" + field] = html.escape(operator.get(field, ""))
    dpo = operator.get("dpo", "")
    values["operator_dpo_block"] = (
        "<p>Data protection officer: %s</p>" % html.escape(dpo) if dpo else ""
    )
    return values


def render(name, docs_dir=DOCS_DIR, operator=None):
    """The HTML of one document with the operator details filled in."""
    if name not in DOCUMENTS:
        raise KeyError(name)
    with open(os.path.join(docs_dir, name), encoding="utf-8") as handle:
        text = handle.read()
    values = _values(load_operator(docs_dir) if operator is None else operator)
    return _TOKEN.sub(lambda match: values.get(match.group(1), match.group(0)), text)


def document_name(link):
    """The document a link inside a document points to (privacy.html, …), or None for an outside link."""
    text = str(link or "").strip()
    if text.startswith("file:"):
        text = text[len("file:"):]
    elif "://" in text or text.startswith("mailto:"):
        return None
    text = text.split("#", 1)[0].split("?", 1)[0]
    text = text.rsplit("/", 1)[-1]
    return text if text in DOCUMENTS else None


def accepted(read_setting):
    """True when the user accepted the current LEGAL_VERSION. read_setting(key) reads the plugin settings."""
    return str(read_setting(ACCEPTED_KEY) or "") == LEGAL_VERSION


def record_acceptance(write_setting, now=None):
    now = now or datetime.datetime.now(datetime.timezone.utc)
    write_setting(ACCEPTED_KEY, LEGAL_VERSION)
    write_setting(ACCEPTED_AT_KEY, now.replace(microsecond=0).isoformat())


def withdraw_acceptance(write_setting):
    write_setting(ACCEPTED_KEY, "")
    write_setting(ACCEPTED_AT_KEY, "")
