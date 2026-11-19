"""geoNFT plugin: dock that signs QGIS in to the geoNFT portal and maps deployment observations."""

import os
import threading
import time

from qgis.PyQt.QtCore import QCoreApplication, Qt
from qgis.PyQt.QtGui import QAction, QIcon
from qgis.PyQt.QtWidgets import (
    QComboBox,
    QDockWidget,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QMenu,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

try:
    from qgis.PyQt.QtGui import QActionGroup
except ImportError:  # Qt5 builds
    from qgis.PyQt.QtWidgets import QActionGroup

from . import auth, cs_api, deployment_verify, indy_identity, legal, license_grants

MENU = "geoNFT plugin"
ICON_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "icon.png")
TERMS_DECLINED = "The plugin connects to the geoNFT services only after you accept the terms of use."
OBSERVATIONS_WAIT = "Reading the observations from Connected Systems…"
VERIFY_WAIT = ("Reading the NFT from the ledger, the lineage and observations from Connected Systems and the pictures "
               "from IPFS…")
# Shown only while Connected Systems is asking the wallet (license_grants.status_text).
WALLET_PROMPT = ("Authorize with your wallet app on your iPhone (or other phone). "
                 "Connected Systems is waiting for you to approve the license request.")


class GeoNftPlugin:
    def __init__(self, iface):
        self.iface = iface
        self.action = None
        self.legal_actions = []
        self.deployments_menu = None
        self.deployments_group = None
        self.dock = None
        self.sign_in_button = None
        self.sign_out_button = None
        self.create_button = None
        self.cancel_button = None
        self.email_value = None
        self.sub_value = None
        self.deployment_combo = None
        self.refresh_button = None
        self.show_button = None
        self.verify_button = None
        self.inspect_button = None
        self.inspect_tool = None
        self._dialogs = []
        self.status = None
        self.deployments = []
        self._busy = False
        self._cancel = threading.Event()

    def initGui(self):
        try:
            auth.migrate_legacy_settings()
        except Exception as err:
            auth_log("Settings from the Certificate review plugin could not be moved: %r" % err, warning=True)
        icon = QIcon(ICON_PATH)
        self.action = QAction(icon, MENU, self.iface.mainWindow())
        self.action.setToolTip("Open the geoNFT panel")
        self.action.triggered.connect(self.show_dock)
        self.iface.addPluginToMenu(MENU, self.action)
        self.iface.addToolBarIcon(self.action)

        self.deployments_menu = QMenu("Deployments", self.iface.mainWindow())
        self.iface.addPluginToMenu(MENU, self.deployments_menu.menuAction())

        for name, title in legal.DOCUMENTS.items():
            action = QAction(title, self.iface.mainWindow())
            action.triggered.connect(lambda _checked=False, n=name: self.show_legal(n))
            self.iface.addPluginToMenu(MENU, action)
            self.legal_actions.append(action)

        self.dock = QDockWidget(MENU, self.iface.mainWindow())
        self.dock.setObjectName("GeoNftPluginDock")
        self.dock.setWindowIcon(icon)
        panel = QWidget(self.dock)
        layout = QVBoxLayout(panel)

        self.sign_in_button = QPushButton("Sign in", panel)
        self.sign_out_button = QPushButton("Sign out", panel)
        self.create_button = QPushButton("Create account", panel)
        self.cancel_button = QPushButton("Cancel", panel)
        self.cancel_button.setEnabled(False)
        self.sign_in_button.clicked.connect(self.sign_in)
        self.sign_out_button.clicked.connect(self.sign_out)
        self.create_button.clicked.connect(self.create_account)
        self.cancel_button.clicked.connect(self.cancel)

        self.email_value = QLabel("—", panel)
        self.sub_value = QLabel("—", panel)
        selectable = Qt.TextInteractionFlag.TextSelectableByMouse
        for label in (self.email_value, self.sub_value):
            label.setTextInteractionFlags(selectable)
            label.setWordWrap(True)

        form = QFormLayout()
        form.addRow("Email", self.email_value)
        form.addRow("sub", self.sub_value)

        self.deployment_combo = QComboBox(panel)
        self.deployment_combo.currentIndexChanged.connect(self._combo_changed)
        self.refresh_button = QPushButton("Refresh", panel)
        self.show_button = QPushButton("Show observations", panel)
        self.refresh_button.clicked.connect(self.refresh_deployments)
        self.show_button.clicked.connect(self.show_selected)
        buttons = QHBoxLayout()
        buttons.addWidget(self.refresh_button)
        buttons.addWidget(self.show_button)

        self.verify_button = QPushButton("Verify against ledger", panel)
        self.verify_button.setToolTip(
            "Read the deployment's NFT from the Fabric ledger and recompute its hash, the server chain and the "
            "drone's signed chain from Connected Systems' lineage, and hash the pictures against what the drone "
            "signed. Results go into the chain_check column of the observations."
        )
        self.verify_button.clicked.connect(self.verify_selected)

        self.inspect_button = QPushButton("Inspect observations (click a dot)", panel)
        self.inspect_button.setCheckable(True)
        self.inspect_button.setToolTip(
            "Click a dot on the map. Blue squares are images (IPFS link and picture), "
            "red circles are telemetry (JSON result)."
        )
        self.inspect_button.toggled.connect(self._inspect_toggled)
        from .inspect_tool import InspectObservationsTool
        self.inspect_tool = InspectObservationsTool(self.iface.mapCanvas(), self.show_hits)
        self.inspect_tool.deactivated.connect(lambda: self.inspect_button and self.inspect_button.setChecked(False))

        self.status = QLabel("", panel)
        self.status.setWordWrap(True)

        legal_links = QLabel(" · ".join(
            '<a href="%s">%s</a>' % (name, title) for name, title in legal.DOCUMENTS.items()
        ), panel)
        legal_links.setTextFormat(Qt.TextFormat.RichText)
        legal_links.setWordWrap(True)
        legal_links.linkActivated.connect(self.show_legal)

        layout.addWidget(self.sign_in_button)
        layout.addWidget(self.sign_out_button)
        layout.addWidget(self.create_button)
        layout.addWidget(self.cancel_button)
        layout.addLayout(form)
        layout.addWidget(QLabel("Deployment", panel))
        layout.addWidget(self.deployment_combo)
        layout.addLayout(buttons)
        layout.addWidget(self.verify_button)
        layout.addWidget(self.inspect_button)
        layout.addWidget(self.status)
        layout.addStretch(1)
        layout.addWidget(legal_links)
        self.dock.setWidget(panel)
        self.iface.addDockWidget(Qt.DockWidgetArea.RightDockWidgetArea, self.dock)
        self._set_deployments([])
        self.show_session(self._stored_session())

    def unload(self):
        self.cancel()
        auth.stop_loopback()
        for dialog in list(self._dialogs):
            dialog.close()
        if self.inspect_tool is not None:
            canvas = self.iface.mapCanvas()
            if canvas.mapTool() is self.inspect_tool:
                canvas.unsetMapTool(self.inspect_tool)
            self.inspect_tool = None
        if self.action is not None:
            self.iface.removePluginMenu(MENU, self.action)
            self.iface.removeToolBarIcon(self.action)
            self.action = None
        for action in self.legal_actions:
            self.iface.removePluginMenu(MENU, action)
        self.legal_actions = []
        if self.deployments_menu is not None:
            self.iface.removePluginMenu(MENU, self.deployments_menu.menuAction())
            self.deployments_menu.deleteLater()
            self.deployments_menu = None
        if self.dock is not None:
            self.iface.removeDockWidget(self.dock)
            self.dock.deleteLater()
            self.dock = None

    def show_dock(self):
        if self.dock is None:
            return
        self.dock.show()
        self.dock.raise_()

    def cancel(self):
        auth.request_cancel()
        self._cancel.set()

    # Privacy statement, terms of use, cookie statement

    def show_legal(self, name):
        name = legal.document_name(name) or legal.TERMS
        from .legal_dialog import LegalDialog
        dialog = LegalDialog(name, ICON_PATH, self.iface.mainWindow())
        self._dialogs.append(dialog)
        dialog.finished.connect(lambda _result, d=dialog: self._dialogs.remove(d) if d in self._dialogs else None)
        dialog.show()
        dialog.raise_()

    def _terms_accepted(self):
        """True once the user accepted the current terms; asks with a modal window otherwise."""
        if legal.accepted(auth.read_setting):
            return True
        from .legal_dialog import AcceptTermsDialog
        dialog = AcceptTermsDialog(ICON_PATH, self.iface.mainWindow())
        if dialog.exec() != AcceptTermsDialog.DialogCode.Accepted:
            self._set_status(TERMS_DECLINED)
            return False
        legal.record_acceptance(auth.write_setting)
        auth_log("Terms of use version %s accepted." % legal.LEGAL_VERSION)
        return True

    # Sign-in

    def sign_in(self):
        session = self._stored_session()
        if session is not None:
            self.show_session(session)
            self._set_status("")
            return
        self._run(auth.sign_in, "Waiting for the browser…")

    def sign_out(self):
        self._run(auth.sign_out, "Waiting for the browser…", needs_terms=False)

    def create_account(self):
        self._run(auth.create_account, "Sign out in the browser, then create the account…")

    def _stored_session(self):
        try:
            return auth.current_session()
        except auth.AuthError as err:
            self._show_error(str(err))
            return None

    def show_session(self, session):
        if self.email_value is None:
            return
        if not session:
            self.email_value.setText("—")
            self.sub_value.setText("—")
            return
        self.email_value.setText(session.get("email") or "—")
        self.sub_value.setText(session.get("sub") or "—")

    # Deployments

    def refresh_deployments(self):
        try:
            portal = cs_api.portal_base(auth.issuer(), auth.portal_url_setting())
        except (auth.AuthError, cs_api.CsApiError) as err:
            self._show_error(str(err))
            return
        deployments = self._run_cs(
            lambda token: cs_api.list_deployments(portal, token),
            "Reading your licensed deployments…",
        )
        if deployments is None:
            return
        self._set_deployments(deployments)
        if deployments:
            self._set_status("%d licensed deployment(s)." % len(deployments))
        else:
            self._set_status("No licensed deployments. Buy or request one in the portal.")

    def select_deployment(self, deployment_id):
        index = self._deployment_index(deployment_id)
        if index < 0:
            return
        if self.deployment_combo is not None:
            self.deployment_combo.setCurrentIndex(index)
        self.show_observations(deployment_id)

    def show_selected(self):
        if self.deployment_combo is None or self.deployment_combo.currentIndex() < 0:
            self._show_error("Refresh the list and select a deployment first.")
            return
        self.show_observations(self.deployment_combo.currentData())

    def show_observations(self, deployment_id):
        index = self._deployment_index(deployment_id)
        if index < 0:
            return
        deployment = self.deployments[index]
        base = cs_api.normalize_base(auth.cs_url_setting())
        collection = self._run_cs(
            lambda token: cs_api.deployment_observations(base, token, deployment["id"]),
            OBSERVATIONS_WAIT,
            deployment_id=deployment["id"],
        )
        if collection is None:
            return
        count = len(collection["features"])
        matched = collection.get("numberMatched")
        auth_log("Deployment %s (%s): %d observation(s)%s." % (
            deployment["label"], deployment["id"], count,
            "" if matched is None else " of %d matched" % matched,
        ))
        missing = matched - count if isinstance(matched, int) and matched > count else 0
        if missing:
            auth_log("Connected Systems sent no next link for the last %d observation(s)." % missing)
        if count == 0:
            self._set_status("%s has no observations." % deployment["label"])
            return
        try:
            from . import map_layers
            summary = map_layers.add_observations(
                collection, deployment["label"], self.iface.mapCanvas(), deployment_id=deployment["id"],
            )
        except Exception as err:
            self._show_error("The observations could not be drawn: %s" % err)
            return
        message = "%s: %d observation(s) on the map" % (deployment["label"], summary["total"])
        message += ", %d image(s)." % summary["images"] if summary.get("images") else "."
        if summary["without_geometry"]:
            message += " %d without geometry (attribute table only)." % summary["without_geometry"]
        if missing:
            message += " Only %d of %d loaded: Connected Systems did not page the rest." % (count, matched)
        self._set_status(message + " Click a dot to see its details.")
        if self.inspect_button is not None:
            self.inspect_button.setChecked(True)

    # Verify

    def verify_selected(self):
        if self.deployment_combo is None or self.deployment_combo.currentIndex() < 0:
            self._show_error("Refresh the list and select a deployment first.")
            return
        index = self._deployment_index(self.deployment_combo.currentData())
        if index < 0:
            return
        deployment = self.deployments[index]
        deployment_id = deployment["id"]
        base = cs_api.normalize_base(auth.cs_url_setting())
        ledger = cs_api.normalize_base(auth.ledger_url_setting(), deployment_verify.DEFAULT_LEDGER_URL)
        resolver = cs_api.normalize_base(auth.indy_resolver_url_setting(), indy_identity.DEFAULT_RESOLVER_URL)
        try:
            from . import map_layers
            observations = map_layers.observation_hashes(deployment_id)
        except Exception as err:
            auth_log("The observations on the map could not be read: %r" % err, warning=True)
            observations = {}

        def read(token):
            # The ledger first: without an NFT there is nothing to compare, and the wallet is not asked.
            ledger_doc = deployment_verify.ledger_deployment(ledger, token, deployment_id)
            lineage = deployment_verify.deployment_lineage(base, token, deployment_id)
            manifest, note = deployment_verify.deployment_manifest(base, token, deployment_id)
            # The observations carry the picture results; the pictures come from their public gateway.
            try:
                collection = cs_api.deployment_observations(base, token, deployment_id)
                members, members_note = collection["features"], None
            except cs_api.CsApiError as err:
                if err.status == 401:
                    raise
                members, members_note = None, "The observations could not be read: %s" % err
            images = deployment_verify.read_images(members) if members is not None else None
            # The drone's did:indy and its cnf ATTRIB, from the public resolver (no bearer token).
            drone_did = ((ledger_doc.get("record") or {}).get("manifest") or {}).get("droneDid")
            indy, indy_note = None, None
            if isinstance(drone_did, str) and drone_did.startswith("did:indy:"):
                try:
                    indy = indy_identity.read_drone_identity(resolver, drone_did)
                except indy_identity.ResolverError as err:
                    indy_note = "The Indy resolver %s could not be read: %s" % (resolver, err)
            return ledger_doc, lineage, manifest, note, members, members_note, images, indy, indy_note

        result = self._run_cs(read, VERIFY_WAIT, deployment_id=deployment_id)
        if result is None:
            return
        ledger_doc, lineage, manifest, note, members, members_note, images, indy, indy_note = result
        report = deployment_verify.verify_deployment(
            deployment_id, ledger_doc, lineage, manifest, note, observations,
            cs_observations=members, cs_observations_note=members_note, images=images,
            indy=indy, indy_note=indy_note,
        )
        for check in report["checks"]:
            auth_log("Verify %s [%s] %s: %s %s" % (
                deployment_id, check["status"], check["key"], check["title"], check["detail"],
            ), warning=check["status"] == deployment_verify.FAIL)

        summary = deployment_verify.summary_line(report)
        if observations:
            try:
                written = map_layers.mark_chain_results(deployment_id, report["observations"])
                summary += " Results are in the %s column." % map_layers.CHAIN_FIELD if written else ""
            except Exception as err:
                auth_log("The results could not be written to the layer: %r" % err, warning=True)
        else:
            summary += " Show the observations first to get a result per observation."
        if report["verdict"] == deployment_verify.VERIFIED:
            self._set_status(summary)
        else:
            self._show_error(summary)

        from .verify_dialog import VerifyDialog
        dialog = VerifyDialog(report, deployment["label"], self.iface.mainWindow())
        self._dialogs.append(dialog)
        dialog.finished.connect(lambda _result, d=dialog: self._dialogs.remove(d) if d in self._dialogs else None)
        dialog.show()
        dialog.raise_()

    # Inspect

    def _inspect_toggled(self, checked):
        canvas = self.iface.mapCanvas()
        if self.inspect_tool is None:
            return
        if checked:
            canvas.setMapTool(self.inspect_tool)
        elif canvas.mapTool() is self.inspect_tool:
            canvas.unsetMapTool(self.inspect_tool)

    def show_hits(self, hits):
        if not hits:
            self._set_status("No observation at that spot. Zoom in or click closer to a dot.")
            return
        from .observation_dialog import ObservationDialog
        dialog = ObservationDialog(hits, self.iface.mainWindow())
        self._dialogs.append(dialog)
        dialog.finished.connect(lambda _result, d=dialog: self._dialogs.remove(d) if d in self._dialogs else None)
        dialog.show()
        dialog.raise_()

    def _deployment_index(self, deployment_id):
        for index, deployment in enumerate(self.deployments):
            if deployment["id"] == deployment_id:
                return index
        return -1

    def _set_deployments(self, deployments):
        selected = self.deployment_combo.currentData() if self.deployment_combo is not None else None
        self.deployments = list(deployments)
        if self.deployment_combo is not None:
            self.deployment_combo.blockSignals(True)
            self.deployment_combo.clear()
            for deployment in self.deployments:
                self.deployment_combo.addItem(cs_api.deployment_title(deployment), deployment["id"])
            index = self._deployment_index(selected)
            self.deployment_combo.setCurrentIndex(index if index >= 0 else (0 if self.deployments else -1))
            self.deployment_combo.blockSignals(False)
        self._rebuild_menu()
        self._set_busy(self._busy)

    def _rebuild_menu(self):
        menu = self.deployments_menu
        if menu is None:
            return
        menu.clear()
        refresh = menu.addAction("Refresh list")
        refresh.triggered.connect(self.refresh_deployments)
        menu.addSeparator()
        self.deployments_group = QActionGroup(menu)
        self.deployments_group.setExclusive(True)
        if not self.deployments:
            placeholder = menu.addAction("Sign in, then Refresh list")
            placeholder.setEnabled(False)
            return
        current = self.deployment_combo.currentData() if self.deployment_combo is not None else None
        for deployment in self.deployments:
            action = menu.addAction(cs_api.deployment_title(deployment))
            action.setCheckable(True)
            action.setChecked(deployment["id"] == current)
            action.setData(deployment["id"])
            self.deployments_group.addAction(action)
            action.triggered.connect(lambda _checked=False, d=deployment["id"]: self.select_deployment(d))

    def _combo_changed(self, _index):
        if self.deployments_group is None or self.deployment_combo is None:
            return
        current = self.deployment_combo.currentData()
        for action in self.deployments_group.actions():
            action.setChecked(action.data() == current)

    # Helpers

    def _set_status(self, message):
        if self.status is not None:
            self.status.setText(message)

    def _show_error(self, message):
        self._set_status(message)
        bar = self.iface.messageBar()
        if bar is not None:
            bar.pushWarning(MENU, message)

    def _set_busy(self, busy):
        self._busy = busy
        for widget in (self.sign_in_button, self.sign_out_button, self.create_button, self.refresh_button):
            if widget is not None:
                widget.setEnabled(not busy)
        if self.deployment_combo is not None:
            self.deployment_combo.setEnabled(not busy and bool(self.deployments))
        if self.show_button is not None:
            self.show_button.setEnabled(not busy and bool(self.deployments))
        if self.verify_button is not None:
            self.verify_button.setEnabled(not busy and bool(self.deployments))
        if self.deployments_menu is not None:
            self.deployments_menu.setEnabled(not busy)
        if self.cancel_button is not None:
            self.cancel_button.setEnabled(busy)

    def _run(self, action, waiting, needs_terms=True):
        if self._busy:
            return
        if needs_terms and not self._terms_accepted():
            return
        self._set_busy(True)
        self._set_status(waiting)
        try:
            session = action()
            self.show_session(session)
            self._set_status("" if session else "Signed out")
        except auth.AuthError as err:
            self.show_session(self._stored_session())
            if str(err) == "Cancelled.":
                self._set_status("Cancelled.")
            else:
                self._show_error(str(err))
        except Exception as err:
            self.show_session(self._stored_session())
            self._show_error("The geoNFT portal account could not be opened: %s" % err)
        finally:
            self._set_busy(False)

    def _run_cs(self, call, waiting, deployment_id=None):
        """Run call(token) off the UI thread. Returns None after an error.

        Without a usable token the browser sign-in starts first. A 401 means the
        token was rejected before it expired (for example the Keycloak session
        ended), so the plugin drops it, signs in again and retries once.

        With deployment_id the status asks the user to authorize in the wallet app
        only while a licensed read of that deployment waits on the wallet: not
        while Connected Systems still holds the previous approval
        (License-Grant-Expires, see license_grants).
        """
        if self._busy:
            return None
        if not self._terms_accepted():
            return None
        self._set_busy(True)
        try:
            for attempt in (1, 2):
                session = self._signed_in_session()
                self._set_status(waiting)
                token = session["access_token"]
                status = None if deployment_id is None else (
                    lambda: license_grants.status_text(token, deployment_id, waiting, WALLET_PROMPT))
                try:
                    return self._in_background(lambda: call(token), status)
                except cs_api.CsApiError as err:
                    if err.status != 401 or attempt == 2:
                        raise
                    auth_log("%s Signing in again." % err, warning=True)
                    auth.clear_session()
                    self.show_session(None)
        except auth.AuthError as err:
            self.show_session(self._stored_session())
            if str(err) == "Cancelled.":
                self._set_status("Cancelled.")
            else:
                self._show_error(str(err))
        except cs_api.CsApiError as err:
            auth_log("%s\n%s" % (err, err.detail) if err.detail else str(err), warning=True)
            self._show_error("%s See Log Messages › geoNFT." % err if err.detail else str(err))
        except Exception as err:
            auth_log("Request failed: %r" % err, warning=True)
            self._show_error("Request failed: %s" % err)
        finally:
            self._set_busy(False)
        return None

    def _signed_in_session(self):
        """The stored session, or a new one from the browser sign-in. Raises AuthError."""
        session = auth.current_session()
        if session is not None:
            return session
        self._set_status("Your sign-in has expired. Finish signing in in the browser…")
        session = auth.sign_in()
        self.show_session(session)
        return session

    def _in_background(self, fn, status=None):
        """Wait for fn on a worker thread while QGIS keeps painting. Cancel stops the wait.

        status() is polled while waiting; the status line follows what it returns.
        """
        result = {}

        def work():
            try:
                result["value"] = fn()
            except BaseException as err:
                result["error"] = err
            finally:
                result["done"] = True

        self._cancel.clear()
        threading.Thread(target=work, daemon=True).start()
        app = QCoreApplication.instance()
        shown = None
        while not result.get("done"):
            if self._cancel.is_set():
                raise auth.AuthError("Cancelled.")
            if status is not None:
                text = status()
                if text != shown:
                    self._set_status(text)
                    shown = text
            if app is not None:
                app.processEvents()
            time.sleep(0.05)
        if "error" in result:
            raise result["error"]
        return result.get("value")


def auth_log(message, warning=False):
    """Write to View › Panels › Log Messages, tab geoNFT."""
    try:
        from qgis.core import Qgis, QgsMessageLog
        level = Qgis.MessageLevel.Warning if warning else Qgis.MessageLevel.Info
        QgsMessageLog.logMessage(message, auth.LOG_TAG, level)
    except Exception:
        auth._logger.info("%s", message)
