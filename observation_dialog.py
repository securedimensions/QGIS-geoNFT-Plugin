"""Details window for the observations under a click.

Telemetry shows its JSON result as HTML tables. An image shows its IPFS link
and the picture itself, fetched through QGIS's network manager (so the QGIS
proxy settings apply), and says whether the bytes match the stored sha256.
"""

import hashlib
import html

from qgis.core import QgsNetworkAccessManager
from qgis.PyQt.QtCore import Qt, QUrl
from qgis.PyQt.QtGui import QPixmap
from qgis.PyQt.QtNetwork import QNetworkReply, QNetworkRequest
from qgis.PyQt.QtWidgets import (
    QDialog,
    QLabel,
    QScrollArea,
    QTabWidget,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from . import observation_view as view

MAX_IMAGE_SIZE = (900, 640)


def _telemetry_page(properties, parent):
    browser = QTextBrowser(parent)
    browser.setOpenExternalLinks(True)
    browser.setHtml(view.telemetry_html(properties))
    return browser


class _ImagePage(QWidget):
    def __init__(self, properties, parent):
        super().__init__(parent)
        self._reply = None
        self._closed = False
        result = view.parse_result(properties.get("result"))
        self._sha256 = result.get("sha256") if isinstance(result, dict) else None
        reference = view.image_reference(result)
        url = properties.get("image_url") or reference["url"]

        layout = QVBoxLayout(self)
        link = QLabel(self)
        link.setTextFormat(Qt.TextFormat.RichText)
        link.setOpenExternalLinks(True)
        link.setTextInteractionFlags(Qt.TextInteractionFlag.TextBrowserInteraction)
        link.setWordWrap(True)
        if url:
            link.setText("<a href='%s'>%s</a>" % (html.escape(url, quote=True), html.escape(url)))
        else:
            link.setText("Stored inline (Connected Systems without IPFS).")
        layout.addWidget(link)

        self._picture = QLabel("Loading the image…", self)
        self._picture.setAlignment(Qt.AlignmentFlag.AlignCenter)
        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        scroll.setWidget(self._picture)
        layout.addWidget(scroll, 1)

        self._integrity = QLabel("", self)
        layout.addWidget(self._integrity)

        details = QTextBrowser(self)
        details.setHtml("<html><body>%s</body></html>" % view.metadata_html(properties))
        details.setMaximumHeight(130)
        layout.addWidget(details)

        if reference["data"] is not None:
            self._show(reference["data"])
        elif url:
            self._fetch(url)
        else:
            self._picture.setText("This observation names no image.")

    def _fetch(self, url):
        request = QNetworkRequest(QUrl(url))
        try:
            request.setAttribute(
                QNetworkRequest.Attribute.RedirectPolicyAttribute,
                QNetworkRequest.RedirectPolicy.NoLessSafeRedirectPolicy,
            )
        except AttributeError:
            pass
        self._reply = QgsNetworkAccessManager.instance().get(request)
        self._reply.finished.connect(self._fetched)

    def _fetched(self):
        reply, self._reply = self._reply, None
        if reply is None:
            return
        reply.deleteLater()
        if self._closed:
            return
        if reply.error() != QNetworkReply.NetworkError.NoError:
            self._picture.setText("The image could not be loaded: %s" % reply.errorString())
            return
        self._show(bytes(reply.readAll()))

    def _show(self, data):
        if self._sha256:
            if hashlib.sha256(data).hexdigest() == str(self._sha256).lower():
                self._integrity.setText("✔ The bytes match the sha256 recorded with the observation.")
            else:
                self._integrity.setText("✘ The bytes do NOT match the sha256 recorded with the observation.")
        pixmap = QPixmap()
        if not pixmap.loadFromData(data):
            self._picture.setText("%d bytes, not a picture format QGIS can show. Use the link." % len(data))
            return
        width, height = MAX_IMAGE_SIZE
        if pixmap.width() > width or pixmap.height() > height:
            pixmap = pixmap.scaled(
                width, height, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation
            )
        self._picture.setPixmap(pixmap)

    def close_page(self):
        self._closed = True
        if self._reply is not None:
            self._reply.abort()


class ObservationDialog(QDialog):
    """One page per observation; tabs when the click hit several."""

    def __init__(self, hits, parent=None):
        super().__init__(parent)
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        self.setWindowTitle("Observation" if len(hits) == 1 else "%d observations here" % len(hits))
        self._pages = []
        layout = QVBoxLayout(self)
        container = QTabWidget(self) if len(hits) > 1 else None
        for properties in hits:
            kind = properties.get("kind") or view.kind_of(properties)
            owner = container or self
            if kind == view.IMAGE:
                page = _ImagePage(properties, owner)
                self._pages.append(page)
            else:
                page = _telemetry_page(properties, owner)
            if container is not None:
                container.addTab(page, view.tab_title(kind, properties))
            else:
                layout.addWidget(page)
        if container is not None:
            layout.addWidget(container)
        self.finished.connect(self._close_pages)
        self.resize(640, 640 if any(isinstance(p, _ImagePage) for p in self._pages) else 480)

    def _close_pages(self, _result=None):
        for page in self._pages:
            page.close_page()
