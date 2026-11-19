"""Windows that show the geoNFT legal documents and ask for acceptance of the terms."""

from qgis.PyQt.QtGui import QDesktopServices, QIcon
from qgis.PyQt.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTextBrowser,
    QVBoxLayout,
)

from . import legal


class _DocumentBrowser(QTextBrowser):
    """Shows one rendered document; links to the other documents stay inside, the rest open in the browser."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setOpenLinks(False)
        self.setSearchPaths([legal.DOCS_DIR])
        self.anchorClicked.connect(self._follow)
        self.current = None

    def show_document(self, name):
        self.current = name
        self.setHtml(legal.render(name))
        self.verticalScrollBar().setValue(0)

    def _follow(self, url):
        name = legal.document_name(url.toString())
        if name is not None:
            self.show_document(name)
            return
        if url.scheme() in ("http", "https", "mailto"):
            QDesktopServices.openUrl(url)


def _document_buttons(browser, parent):
    row = QHBoxLayout()
    for name, title in legal.DOCUMENTS.items():
        button = QPushButton(title, parent)
        button.clicked.connect(lambda _checked=False, n=name: browser.show_document(n))
        row.addWidget(button)
    row.addStretch(1)
    return row


class LegalDialog(QDialog):
    """Read-only view of the privacy statement, terms of use and cookie statement."""

    def __init__(self, name, icon_path=None, parent=None):
        super().__init__(parent)
        self.setWindowTitle("geoNFT plugin – " + legal.DOCUMENTS[name])
        if icon_path:
            self.setWindowIcon(QIcon(icon_path))
        self.resize(760, 680)
        layout = QVBoxLayout(self)
        self.browser = _DocumentBrowser(self)
        layout.addLayout(_document_buttons(self.browser, self))
        layout.addWidget(self.browser)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close, self)
        buttons.rejected.connect(self.close)
        layout.addWidget(buttons)
        self.browser.show_document(name)


class AcceptTermsDialog(QDialog):
    """Asked once per legal.LEGAL_VERSION, before the plugin first contacts an online service."""

    def __init__(self, icon_path=None, parent=None):
        super().__init__(parent)
        self.setWindowTitle("geoNFT plugin – Terms of use")
        if icon_path:
            self.setWindowIcon(QIcon(icon_path))
        self.resize(760, 720)
        layout = QVBoxLayout(self)
        intro = QLabel(
            "The geoNFT plugin is about to connect to the geoNFT online services. "
            "Please read the terms of use, the privacy statement and the cookie statement. "
            "The plugin connects only after you accept.",
            self,
        )
        intro.setWordWrap(True)
        layout.addWidget(intro)
        self.browser = _DocumentBrowser(self)
        layout.addLayout(_document_buttons(self.browser, self))
        layout.addWidget(self.browser)
        notice = QLabel(
            "By pressing Accept you agree to the terms of use and confirm that you have read the privacy "
            "statement and the cookie statement (version %s). You can read them again in "
            "Plugins › geoNFT plugin." % legal.LEGAL_VERSION,
            self,
        )
        notice.setWordWrap(True)
        layout.addWidget(notice)
        buttons = QDialogButtonBox(self)
        accept = buttons.addButton("Accept", QDialogButtonBox.ButtonRole.AcceptRole)
        decline = buttons.addButton("Decline", QDialogButtonBox.ButtonRole.RejectRole)
        accept.clicked.connect(self.accept)
        decline.clicked.connect(self.reject)
        layout.addWidget(buttons)
        self.browser.show_document(legal.TERMS)
