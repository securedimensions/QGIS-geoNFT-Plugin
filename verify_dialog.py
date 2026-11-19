"""Window with the result of verifying a deployment against its NFT on the ledger."""

from qgis.PyQt.QtWidgets import QDialog, QDialogButtonBox, QTextBrowser, QVBoxLayout

from . import deployment_verify


class VerifyDialog(QDialog):
    def __init__(self, report, title, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Deployment verification: %s" % title)
        self.resize(760, 640)
        layout = QVBoxLayout(self)
        browser = QTextBrowser(self)
        browser.setOpenExternalLinks(True)
        browser.setHtml(deployment_verify.report_html(report, title))
        layout.addWidget(browser)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close, self)
        buttons.rejected.connect(self.close)
        buttons.accepted.connect(self.close)
        layout.addWidget(buttons)
