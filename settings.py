from __future__ import annotations

import hashlib
import json
import shutil
from datetime import datetime
from copy import deepcopy
from pathlib import Path
from typing import Any

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)


DEFAULT_SETTINGS: dict[str, Any] = {
    "homepage": "https://google.com",
    "idle_lock_minutes": 15,
    "brave_executable": "",
}

DEFAULT_STATE: dict[str, Any] = {
    "password_hash": "",
    "kdf_salt": "",
    "settings": deepcopy(DEFAULT_SETTINGS),
    "extensions": [],
    "bookmarks": [],
}


class AppStateStore:
    def __init__(self, base_dir: Path) -> None:
        self.base_dir = Path(base_dir)
        self.state_path = self.base_dir / "app_state.json"
        self.state_backup_path = self.base_dir / "app_state.json.bak"

    def load_state(self) -> dict[str, Any]:
        if not self.state_path.exists():
            backup = self._read_state_dict(self.state_backup_path)
            if backup is not None:
                return self._normalize_state(backup)
            return deepcopy(DEFAULT_STATE)

        current = self._read_state_dict(self.state_path)
        if current is not None:
            return self._normalize_state(current)

        self._preserve_corrupt_state_file()
        backup = self._read_state_dict(self.state_backup_path)
        if backup is not None:
            return self._normalize_state(backup)
        return deepcopy(DEFAULT_STATE)

    def save_state(self, state: dict[str, Any]) -> None:
        normalized = self._normalize_state(state)
        self.base_dir.mkdir(parents=True, exist_ok=True)

        payload = json.dumps(normalized, indent=2) + "\n"
        temp_path = self.base_dir / f"{self.state_path.name}.tmp"
        temp_path.write_text(payload, encoding="utf-8")

        if self.state_path.exists():
            try:
                shutil.copy2(self.state_path, self.state_backup_path)
            except OSError:
                pass
        temp_path.replace(self.state_path)
        try:
            shutil.copy2(self.state_path, self.state_backup_path)
        except OSError:
            pass

    def _normalize_state(self, state: dict[str, Any]) -> dict[str, Any]:
        merged = deepcopy(DEFAULT_STATE)
        merged.update(state)
        merged_settings = deepcopy(DEFAULT_SETTINGS)
        state_settings = merged.get("settings", {})
        if isinstance(state_settings, dict):
            merged_settings.update(state_settings)
        merged["settings"] = merged_settings

        if not isinstance(merged.get("extensions"), list):
            merged["extensions"] = []
        if not isinstance(merged.get("bookmarks"), list):
            merged["bookmarks"] = []
        if not isinstance(merged.get("password_hash"), str):
            merged["password_hash"] = ""
        if not isinstance(merged.get("kdf_salt"), str):
            merged["kdf_salt"] = ""
        return merged

    def _read_state_dict(self, path: Path) -> dict[str, Any] | None:
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None
        if not isinstance(raw, dict):
            return None
        return raw

    def _preserve_corrupt_state_file(self) -> None:
        if not self.state_path.exists():
            return
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        destination = self.base_dir / f"app_state.corrupt.{timestamp}.json"
        try:
            shutil.copy2(self.state_path, destination)
        except OSError:
            pass


def validate_extension_manifest(extension_dir: Path) -> tuple[bool, str, dict[str, Any] | None]:
    manifest_path = extension_dir / "manifest.json"
    if not extension_dir.exists() or not extension_dir.is_dir():
        return False, "Selected path is not a valid folder.", None
    if not manifest_path.exists():
        return False, "manifest.json was not found in that folder.", None

    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return False, "manifest.json is not valid JSON.", None

    required = ["name", "version", "manifest_version"]
    missing = [field for field in required if field not in manifest]
    if missing:
        return False, f"manifest.json missing required fields: {', '.join(missing)}", None

    if manifest["manifest_version"] not in (2, 3):
        return False, "Only Manifest V2/V3 extensions are supported.", None
    return True, "Valid extension.", manifest


def extension_paths_from_state(state: dict[str, Any], profile_dir: Path) -> list[str]:
    root = profile_dir / "extensions"
    enabled: list[str] = []
    for item in state.get("extensions", []):
        if not item.get("enabled", False):
            continue
        folder = root / item.get("id", "")
        if folder.exists():
            enabled.append(str(folder.resolve()))
    return enabled


def _slugify(text: str) -> str:
    cleaned = "".join(ch.lower() if ch.isalnum() else "-" for ch in text)
    compact = "-".join(part for part in cleaned.split("-") if part)
    return compact[:40] or "extension"


class ExtensionManagerDialog(QDialog):
    def __init__(
        self,
        state: dict[str, Any],
        state_store: AppStateStore,
        profile_dir: Path,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Manage Extensions")
        self.setMinimumWidth(760)
        self.state = state
        self.state_store = state_store
        self.profile_dir = Path(profile_dir)
        self.extensions_dir = self.profile_dir / "extensions"
        self.extensions_dir.mkdir(parents=True, exist_ok=True)
        self.archived_extensions_dir = self.profile_dir / "extensions-archive"
        self.archived_extensions_dir.mkdir(parents=True, exist_ok=True)

        self.extensions: list[dict[str, Any]] = [dict(item) for item in self.state.get("extensions", [])]
        self.removed_ids: set[str] = set()

        self.table = QTableWidget(0, 4, self)
        self.table.setHorizontalHeaderLabels(["Enabled", "Name", "Version", "ID"])
        self.table.horizontalHeader().setStretchLastSection(True)

        add_btn = QPushButton("Add Extension Folder")
        add_btn.clicked.connect(self._add_extension)
        remove_btn = QPushButton("Remove Selected")
        remove_btn.clicked.connect(self._remove_selected)

        button_row = QHBoxLayout()
        button_row.addWidget(add_btn)
        button_row.addWidget(remove_btn)
        button_row.addStretch(1)

        buttons = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self._save_and_close)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("Changes to extension loading take effect on full app restart."))
        layout.addWidget(self.table)
        layout.addLayout(button_row)
        layout.addWidget(buttons)

        self._refresh_table()

    def _refresh_table(self) -> None:
        self.table.setRowCount(len(self.extensions))
        for row, entry in enumerate(self.extensions):
            enabled_item = QTableWidgetItem()
            enabled_item.setFlags(Qt.ItemIsEnabled | Qt.ItemIsUserCheckable | Qt.ItemIsSelectable)
            enabled_item.setCheckState(Qt.Checked if entry.get("enabled", True) else Qt.Unchecked)
            self.table.setItem(row, 0, enabled_item)
            self.table.setItem(row, 1, QTableWidgetItem(str(entry.get("name", "Unknown"))))
            self.table.setItem(row, 2, QTableWidgetItem(str(entry.get("version", "n/a"))))
            id_item = QTableWidgetItem(str(entry.get("id", "")))
            id_item.setFlags(Qt.ItemIsSelectable | Qt.ItemIsEnabled)
            self.table.setItem(row, 3, id_item)

    def _add_extension(self) -> None:
        selected = QFileDialog.getExistingDirectory(self, "Select Extension Folder")
        if not selected:
            return

        source = Path(selected)
        is_valid, message, manifest = validate_extension_manifest(source)
        if not is_valid:
            QMessageBox.warning(self, "Invalid Extension", message)
            return

        ext_name = str(manifest.get("name", source.name))
        digest = hashlib.sha1(str(source.resolve()).encode("utf-8")).hexdigest()[:10]
        ext_id = f"{_slugify(ext_name)}-{digest}"
        destination = self.extensions_dir / ext_id

        try:
            if destination.exists():
                self._archive_extension_folder(destination)
            shutil.copytree(source, destination)
        except OSError as exc:
            QMessageBox.critical(self, "Copy Failed", f"Could not copy extension folder:\n{exc}")
            return

        for idx, entry in enumerate(self.extensions):
            if entry.get("id") == ext_id:
                self.extensions.pop(idx)
                break

        self.extensions.append(
            {
                "id": ext_id,
                "name": ext_name,
                "version": str(manifest.get("version", "n/a")),
                "enabled": True,
            }
        )
        self._refresh_table()

    def _remove_selected(self) -> None:
        rows = sorted({item.row() for item in self.table.selectedItems()}, reverse=True)
        if not rows:
            return
        for row in rows:
            extension_id = str(self.table.item(row, 3).text())
            self.removed_ids.add(extension_id)
            self.extensions.pop(row)
        self._refresh_table()

    def _save_and_close(self) -> None:
        for row, entry in enumerate(self.extensions):
            enabled_item = self.table.item(row, 0)
            entry["enabled"] = bool(enabled_item and enabled_item.checkState() == Qt.Checked)

        for extension_id in self.removed_ids:
            target = self.extensions_dir / extension_id
            if target.exists():
                try:
                    self._archive_extension_folder(target)
                except OSError as exc:
                    QMessageBox.critical(
                        self,
                        "Archive Failed",
                        f"Could not archive removed extension data:\n{exc}",
                    )
                    return

        self.state["extensions"] = self.extensions
        self.state_store.save_state(self.state)
        self.accept()

    def _archive_extension_folder(self, source: Path) -> None:
        if not source.exists():
            return
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        destination = self.archived_extensions_dir / f"{source.name}-{timestamp}"
        counter = 1
        while destination.exists():
            destination = self.archived_extensions_dir / f"{source.name}-{timestamp}-{counter}"
            counter += 1
        shutil.move(str(source), str(destination))


class SettingsDialog(QDialog):
    def __init__(
        self,
        state: dict[str, Any],
        state_store: AppStateStore,
        profile_dir: Path,
        on_change_password,
        on_clear_data,
        on_open_extensions=None,
        on_open_bookmarks=None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Settings")
        self.setMinimumWidth(620)
        self.state = state
        self.state_store = state_store
        self.profile_dir = Path(profile_dir)
        self.on_change_password = on_change_password
        self.on_clear_data = on_clear_data
        self.on_open_extensions = on_open_extensions
        self.on_open_bookmarks = on_open_bookmarks

        current = self.state.get("settings", {})

        self.homepage_edit = QLineEdit(str(current.get("homepage", DEFAULT_SETTINGS["homepage"])))
        self.brave_path_edit = QLineEdit(str(current.get("brave_executable", "")))
        self.brave_path_edit.setPlaceholderText("Path to brave.exe (optional)")
        self.idle_spin = QSpinBox()
        self.idle_spin.setRange(1, 240)
        self.idle_spin.setValue(int(current.get("idle_lock_minutes", 15)))
        self.idle_spin.setSuffix(" min")

        self.old_password_edit = QLineEdit()
        self.old_password_edit.setEchoMode(QLineEdit.Password)
        self.new_password_edit = QLineEdit()
        self.new_password_edit.setEchoMode(QLineEdit.Password)
        self.confirm_password_edit = QLineEdit()
        self.confirm_password_edit.setEchoMode(QLineEdit.Password)

        tabs = QTabWidget()
        tabs.addTab(self._build_general_tab(), "General")
        tabs.addTab(self._build_security_tab(), "Security")
        tabs.addTab(self._build_data_tab(), "Data")

        buttons = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self._save_settings)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addWidget(tabs)
        layout.addWidget(buttons)

    def _build_general_tab(self) -> QWidget:
        widget = QWidget()
        form = QFormLayout(widget)
        brave_path_row = QWidget()
        brave_layout = QHBoxLayout(brave_path_row)
        brave_layout.setContentsMargins(0, 0, 0, 0)
        brave_layout.addWidget(self.brave_path_edit)
        browse_btn = QPushButton("Browse")
        browse_btn.clicked.connect(self._browse_brave_path)
        brave_layout.addWidget(browse_btn)

        form.addRow("Homepage:", self.homepage_edit)
        form.addRow("Brave executable:", brave_path_row)
        form.addRow("Idle auto-lock timeout:", self.idle_spin)
        return widget

    def _build_security_tab(self) -> QWidget:
        widget = QWidget()
        form = QFormLayout(widget)
        form.addRow("Current password:", self.old_password_edit)
        form.addRow("New password:", self.new_password_edit)
        form.addRow("Confirm new password:", self.confirm_password_edit)

        change_btn = QPushButton("Change Password")
        change_btn.clicked.connect(self._change_password)
        form.addRow("", change_btn)
        return widget

    def _build_data_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)

        clear_btn = QPushButton("Clear Browsing Data")
        clear_btn.clicked.connect(self._clear_data)
        manage_ext_btn = QPushButton("Open Extensions Page")
        manage_ext_btn.clicked.connect(self._manage_extensions)
        export_btn = QPushButton("Open Bookmarks Manager")
        export_btn.clicked.connect(self._export_bookmarks)

        layout.addWidget(clear_btn)
        layout.addWidget(manage_ext_btn)
        layout.addWidget(export_btn)
        layout.addStretch(1)
        return widget

    def _save_settings(self) -> None:
        settings = self.state.setdefault("settings", {})
        settings["homepage"] = self.homepage_edit.text().strip() or DEFAULT_SETTINGS["homepage"]
        settings["brave_executable"] = self.brave_path_edit.text().strip()
        settings["idle_lock_minutes"] = self.idle_spin.value()
        self.state_store.save_state(self.state)
        self.accept()

    def _browse_brave_path(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Brave Executable",
            "",
            "Executables (*.exe)",
        )
        if path:
            self.brave_path_edit.setText(path)

    def _change_password(self) -> None:
        old_password = self.old_password_edit.text()
        new_password = self.new_password_edit.text()
        confirm = self.confirm_password_edit.text()
        if not old_password or not new_password:
            QMessageBox.warning(self, "Missing Input", "Enter both current and new password.")
            return
        if len(new_password) < 8:
            QMessageBox.warning(self, "Weak Password", "Use at least 8 characters.")
            return
        if new_password != confirm:
            QMessageBox.warning(self, "Mismatch", "New password and confirmation do not match.")
            return

        ok, message = self.on_change_password(old_password, new_password)
        if ok:
            QMessageBox.information(self, "Password Updated", message)
            self.old_password_edit.clear()
            self.new_password_edit.clear()
            self.confirm_password_edit.clear()
            return
        QMessageBox.critical(self, "Password Change Failed", message)

    def _clear_data(self) -> None:
        choice = QMessageBox.question(
            self,
            "Clear Data",
            "Clear cookies, cache, history, sessions, and downloads?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if choice != QMessageBox.Yes:
            return

        ok, message = self.on_clear_data()
        if ok:
            QMessageBox.information(self, "Data Cleared", message)
            return
        QMessageBox.critical(self, "Clear Failed", message)

    def _manage_extensions(self) -> None:
        if self.on_open_extensions is not None:
            self.on_open_extensions()
            return
        dialog = ExtensionManagerDialog(
            state=self.state,
            state_store=self.state_store,
            profile_dir=self.profile_dir,
            parent=self,
        )
        dialog.exec()

    def _export_bookmarks(self) -> None:
        if self.on_open_bookmarks is not None:
            self.on_open_bookmarks()
            return
        destination, _ = QFileDialog.getSaveFileName(
            self,
            "Export Bookmarks",
            "bookmarks.html",
            "HTML Files (*.html)",
        )
        if not destination:
            return

        bookmarks = self.state.get("bookmarks", [])
        lines = [
            "<!DOCTYPE NETSCAPE-Bookmark-file-1>",
            "<META HTTP-EQUIV=\"Content-Type\" CONTENT=\"text/html; charset=UTF-8\">",
            "<TITLE>Bookmarks</TITLE>",
            "<H1>Bookmarks</H1>",
            "<DL><p>",
        ]
        for item in bookmarks:
            title = str(item.get("title", item.get("url", "")))
            url = str(item.get("url", ""))
            if not url:
                continue
            lines.append(f'  <DT><A HREF="{url}">{title}</A>')
        lines.append("</DL><p>")

        try:
            Path(destination).write_text("\n".join(lines), encoding="utf-8")
        except OSError as exc:
            QMessageBox.critical(self, "Export Failed", f"Could not write file:\n{exc}")
            return
        QMessageBox.information(self, "Export Complete", "Bookmarks exported successfully.")
