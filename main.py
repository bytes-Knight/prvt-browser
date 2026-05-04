from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from PySide6.QtCore import QEvent, QLockFile, QObject, QTimer, Qt
from PySide6.QtGui import QAction, QColor, QIcon, QPainter, QPen, QPixmap
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QFileDialog,
    QMenu,
    QMessageBox,
    QSystemTrayIcon,
)

from auth import LoginDialog, PasswordSetupDialog
from encryption import AuthenticationError, CryptoManager, CryptoError
from settings import AppStateStore, SettingsDialog

try:
    import psutil
except Exception:  # pragma: no cover - runtime fallback for packaged builds
    psutil = None


def apply_dark_theme(app: QApplication) -> None:
    app.setStyleSheet(
        """
        QWidget {
            background-color: #0b1020;
            color: #e7edf7;
            font-family: "Segoe UI";
            font-size: 10.5pt;
        }
        QDialog {
            background-color: #0b1020;
        }
        QLabel {
            color: #e7edf7;
        }
        QLineEdit {
            background-color: #121a2e;
            color: #eef3ff;
            border: 1px solid #2b3d66;
            border-radius: 8px;
            padding: 8px 10px;
            selection-background-color: #2f6df6;
        }
        QPushButton {
            background-color: #2f6df6;
            color: #ffffff;
            border: 1px solid #2f6df6;
            border-radius: 8px;
            padding: 7px 14px;
            min-width: 88px;
            font-weight: 600;
        }
        QPushButton:hover {
            background-color: #3f7dff;
            border-color: #3f7dff;
        }
        QPushButton:pressed {
            background-color: #245ad3;
            border-color: #245ad3;
        }
        QPushButton#secondaryButton {
            background-color: #141f39;
            border: 1px solid #2b3d66;
            color: #d3ddef;
        }
        QPushButton#secondaryButton:hover {
            background-color: #1a2748;
        }
        QMenuBar, QMenu {
            background-color: #11192f;
            color: #e7edf7;
        }
        QMessageBox {
            background-color: #0b1020;
        }
        """
    )


def _build_fallback_icon() -> QIcon:
    sizes = [16, 24, 32, 48, 64, 128, 256]
    icon = QIcon()
    for size in sizes:
        pixmap = QPixmap(size, size)
        pixmap.fill(QColor("#00000000"))

        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.Antialiasing, True)

        pad = max(1, int(size * 0.06))
        radius = max(3, int(size * 0.2))
        bg_rect = pixmap.rect().adjusted(pad, pad, -pad, -pad)
        painter.setPen(Qt.NoPen)
        painter.setBrush(QColor("#1b3fa3"))
        painter.drawRoundedRect(bg_rect, radius, radius)

        body_w = int(size * 0.52)
        body_h = int(size * 0.34)
        body_x = (size - body_w) // 2
        body_y = int(size * 0.48)
        body_rect = bg_rect.adjusted(
            body_x - bg_rect.x(),
            body_y - bg_rect.y(),
            (body_x + body_w) - bg_rect.right() - 1,
            (body_y + body_h) - bg_rect.bottom() - 1,
        )
        painter.setBrush(QColor("#ffffff"))
        painter.drawRoundedRect(body_rect, max(2, int(size * 0.05)), max(2, int(size * 0.05)))

        shackle_w = int(size * 0.34)
        shackle_h = int(size * 0.25)
        shackle_x = (size - shackle_w) // 2
        shackle_y = int(size * 0.26)
        pen = QPen(QColor("#ffffff"))
        pen.setWidth(max(2, int(size * 0.07)))
        pen.setCapStyle(Qt.RoundCap)
        painter.setPen(pen)
        painter.setBrush(Qt.NoBrush)
        painter.drawArc(shackle_x, shackle_y, shackle_w, shackle_h, 0, 180 * 16)

        dot_r = max(1, int(size * 0.045))
        painter.setPen(Qt.NoPen)
        painter.setBrush(QColor("#1b3fa3"))
        painter.drawEllipse(
            body_rect.center().x() - dot_r,
            body_rect.center().y() - dot_r,
            dot_r * 2,
            dot_r * 2,
        )

        painter.end()
        icon.addPixmap(pixmap)
    return icon


class SecureBrowserController(QObject):
    def __init__(self, app: QApplication) -> None:
        super().__init__()
        self.app = app
        self.app.installEventFilter(self)
        self.app.aboutToQuit.connect(self._on_about_to_quit)
        self.app.setQuitOnLastWindowClosed(False)

        if getattr(sys, "frozen", False):
            self.base_dir = Path(sys.executable).resolve().parent
        else:
            self.base_dir = Path(__file__).resolve().parent
        self.base_dir.mkdir(parents=True, exist_ok=True)

        self.state_store = AppStateStore(self.base_dir)
        self.state = self.state_store.load_state()
        self.crypto = CryptoManager(self.base_dir)

        self.session_key: bytes | None = None
        self.brave_process: subprocess.Popen[str] | None = None
        self.instance_lock: QLockFile | None = None
        self.tray_icon: QSystemTrayIcon | None = None
        self.is_locked_out = False
        self.is_locking = False
        self.last_activity = time.monotonic()
        self.launch_grace_until = 0.0

        self.idle_timer = QTimer(self)
        self.idle_timer.setInterval(5000)
        self.idle_timer.timeout.connect(self._check_idle_timeout)

        self.process_timer = QTimer(self)
        self.process_timer.setInterval(2500)
        self.process_timer.timeout.connect(self._check_brave_process)

    def initialize(self) -> bool:
        self._set_app_icon()
        apply_dark_theme(self.app)

        if not self._acquire_single_instance_lock():
            return False

        self._setup_tray()
        self.idle_timer.start()
        self.process_timer.start()

        if not self._bootstrap_authentication():
            return False

        if not self._launch_brave():
            self._lock_browser()
            return False
        return True

    def _set_app_icon(self) -> None:
        icon_file = self.base_dir / "icon.ico"
        if icon_file.exists():
            self.app.setWindowIcon(QIcon(str(icon_file)))
            return
        self.app.setWindowIcon(_build_fallback_icon())

    def _acquire_single_instance_lock(self) -> bool:
        lock = QLockFile(str(self.base_dir / ".instance.lock"))
        lock.setStaleLockTime(30_000)
        if not lock.tryLock(100):
            lock.removeStaleLockFile()
            if not lock.tryLock(100):
                QMessageBox.warning(
                    None,
                    "Already Running",
                    (
                        "Secure launcher is already running.\n\n"
                        "If you closed Brave, wait a moment or exit the tray app first."
                    ),
                )
                return False
        self.instance_lock = lock
        return True

    def _bootstrap_authentication(self) -> bool:
        first_run = not bool(self.state.get("password_hash"))
        if first_run:
            dialog = PasswordSetupDialog()
            if dialog.exec() != QDialog.Accepted or not dialog.password:
                return False
            self.crypto.initialize_master_password(dialog.password, self.state)
            self.state_store.save_state(self.state)
            success, _ = self._verify_and_unlock(dialog.password)
            return success
        return self._prompt_unlock_dialog(allow_cancel=False)

    def _prompt_unlock_dialog(self, allow_cancel: bool) -> bool:
        if self.is_locked_out:
            QMessageBox.critical(None, "Locked", "Too many failed login attempts in this run.")
            return False

        dialog = LoginDialog(verify_callback=self._verify_and_unlock)
        if dialog.exec() == QDialog.Accepted:
            return True

        if dialog.hard_locked:
            self.is_locked_out = True
        return False

    def _verify_and_unlock(self, password: str) -> tuple[bool, str]:
        try:
            self.session_key = self.crypto.unlock_profile(password, self.state)
            self.last_activity = time.monotonic()
            return True, "Unlocked"
        except AuthenticationError as exc:
            self.session_key = None
            return False, str(exc)
        except CryptoError as exc:
            self.session_key = None
            return False, f"Unlock failed: {exc}"
        except OSError as exc:
            self.session_key = None
            return False, f"Profile error: {exc}"
        except Exception as exc:
            self.session_key = None
            return False, f"Unlock failed: {exc}"

    def _remember_brave_executable(self, executable: Path) -> None:
        normalized = str(executable.resolve())
        settings = self.state.setdefault("settings", {})
        if settings.get("brave_executable") != normalized:
            settings["brave_executable"] = normalized
            self.state_store.save_state(self.state)

    def _candidate_brave_paths(self) -> list[Path]:
        candidates: list[Path] = []
        seen: set[str] = set()

        def add_candidate(candidate: Path) -> None:
            try:
                resolved = candidate.resolve()
            except OSError:
                return
            key = str(resolved).lower()
            if key in seen:
                return
            if not resolved.exists() or not resolved.is_file():
                return
            seen.add(key)
            candidates.append(resolved)

        configured = str(self.state.get("settings", {}).get("brave_executable", "")).strip().strip('"')
        if configured:
            add_candidate(Path(configured))

        default_locations = [
            Path(r"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe"),
            Path(r"C:\Program Files (x86)\BraveSoftware\Brave-Browser\Application\brave.exe"),
            Path.home() / r"AppData\Local\BraveSoftware\Brave-Browser\Application\brave.exe",
        ]
        for path in default_locations:
            add_candidate(path)

        for env_name in ("PROGRAMFILES", "PROGRAMFILES(X86)", "LOCALAPPDATA"):
            root = os.environ.get(env_name, "").strip()
            if not root:
                continue
            add_candidate(Path(root) / "BraveSoftware" / "Brave-Browser" / "Application" / "brave.exe")

        for lookup_name in ("brave.exe", "brave"):
            result = subprocess.run(
                ["where", lookup_name],
                capture_output=True,
                text=True,
                check=False,
                **self._no_window_kwargs(),
            )
            if result.returncode != 0:
                continue
            for line in result.stdout.splitlines():
                line = line.strip()
                if line:
                    add_candidate(Path(line))
        return candidates

    def _prompt_brave_executable(self) -> Path | None:
        selected, _ = QFileDialog.getOpenFileName(
            None,
            "Select Brave Executable",
            "",
            "Executables (*.exe)",
        )
        if not selected:
            return None
        chosen = Path(selected)
        if not chosen.exists() or not chosen.is_file():
            QMessageBox.critical(None, "Invalid Path", "Selected executable does not exist.")
            return None
        return chosen.resolve()

    def _filtered_env_for_brave(self) -> dict[str, str]:
        env = dict(os.environ)
        env.pop("QTWEBENGINE_REMOTE_DEBUGGING", None)

        raw_flags = env.get("QTWEBENGINE_CHROMIUM_FLAGS", "")
        if not raw_flags:
            return env

        safe_flags: list[str] = []
        for token in raw_flags.split():
            if token.startswith("--remote-debugging-port"):
                continue
            if token.startswith("--remote-debugging-address"):
                continue
            safe_flags.append(token)

        if safe_flags:
            env["QTWEBENGINE_CHROMIUM_FLAGS"] = " ".join(safe_flags)
        else:
            env.pop("QTWEBENGINE_CHROMIUM_FLAGS", None)
        return env

    @staticmethod
    def _no_window_kwargs() -> dict[str, Any]:
        if os.name != "nt":
            return {}
        kwargs: dict[str, Any] = {}
        create_no_window = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        if create_no_window:
            kwargs["creationflags"] = create_no_window
        startup = subprocess.STARTUPINFO()
        startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startup.wShowWindow = 0
        kwargs["startupinfo"] = startup
        return kwargs

    def _managed_brave_pids(self) -> list[int]:
        marker = str(self._brave_user_data_dir().resolve()).replace("/", "\\").lower()

        if psutil is None:
            if self.brave_process is not None and self.brave_process.poll() is None:
                return [int(self.brave_process.pid)]
            return []

        pids: list[int] = []
        for process in psutil.process_iter(["pid", "name", "cmdline"]):
            try:
                name = str(process.info.get("name") or "").lower()
                if name != "brave.exe":
                    continue
                cmdline_list = process.info.get("cmdline") or []
                if not cmdline_list:
                    continue
                cmdline = " ".join(str(part) for part in cmdline_list).replace("/", "\\").lower()
                if "--user-data-dir=" not in cmdline:
                    continue
                if marker not in cmdline:
                    continue
                pid = int(process.info.get("pid") or 0)
                if pid > 0:
                    pids.append(pid)
            except Exception:
                continue
        return pids

    def _has_active_browser(self) -> bool:
        if self.brave_process is not None and self.brave_process.poll() is None:
            return True
        return bool(self._managed_brave_pids())

    def _launch_brave(self, open_url: str | None = None) -> bool:
        if self.session_key is None:
            return False

        if self._has_active_browser():
            self.launch_grace_until = time.monotonic() + 8
            if open_url:
                user_data = self._brave_user_data_dir()
                self.crypto.ensure_directory(self.crypto.profile_dir)
                self.crypto.ensure_directory(user_data)
                for exe in self._candidate_brave_paths():
                    try:
                        subprocess.Popen(
                            [str(exe), f"--user-data-dir={user_data}", open_url],
                            cwd=str(exe.parent),
                            env=self._filtered_env_for_brave(),
                            **self._no_window_kwargs(),
                        )
                        self._remember_brave_executable(exe)
                        self.launch_grace_until = time.monotonic() + 10
                        return True
                    except OSError:
                        continue
            return True

        user_data = self._brave_user_data_dir()
        self.crypto.ensure_profile_structure()
        self.crypto.ensure_directory(user_data)

        candidates = self._candidate_brave_paths()
        last_error: OSError | None = None
        manual_prompted = False

        while True:
            if not candidates:
                chosen = self._prompt_brave_executable()
                if chosen is None:
                    break
                candidates = [chosen]
                manual_prompted = True

            for exe in candidates:
                command = [
                    str(exe),
                    f"--user-data-dir={user_data}",
                    "--restore-last-session",
                    "--no-first-run",
                    "--no-default-browser-check",
                    "--disable-sync",
                    "--disable-background-mode",
                    "--disable-features=BackgroundMode",
                    "--new-window",
                ]
                if open_url:
                    command.append(open_url)
                else:
                    homepage = str(
                        self.state.get("settings", {}).get("homepage", "https://google.com")
                    ).strip()
                    if homepage:
                        command.append(homepage)

                try:
                    self.brave_process = subprocess.Popen(
                        command,
                        cwd=str(exe.parent),
                        env=self._filtered_env_for_brave(),
                        **self._no_window_kwargs(),
                    )
                    self._remember_brave_executable(exe)
                    self.launch_grace_until = time.monotonic() + 20
                    return True
                except OSError as exc:
                    last_error = exc
                    continue

            if manual_prompted:
                break
            candidates = []
            manual_prompted = True
            continue

        if manual_prompted and last_error is None:
            QMessageBox.critical(
                None,
                "Brave Not Found",
                "No launchable Brave executable was selected.",
            )
            return False

        if last_error is not None:
            QMessageBox.critical(
                None,
                "Launch Failed",
                f"Could not launch Brave from any available path.\n\nLast error: {last_error}",
            )
        else:
            QMessageBox.critical(None, "Launch Failed", "Could not launch Brave.")
        return False

    def _brave_user_data_dir(self) -> Path:
        return self.crypto.profile_dir / "brave-user-data"

    def _check_brave_process(self) -> None:
        if self.is_locking or self.session_key is None:
            return
        if time.monotonic() < self.launch_grace_until:
            return
        if self._has_active_browser():
            return

        self.brave_process = None
        if self._lock_browser():
            self._quit_app()

    def _terminate_brave(self) -> None:
        managed = self._managed_brave_pids()
        for pid in managed:
            subprocess.run(
                ["taskkill", "/PID", str(pid), "/T", "/F"],
                capture_output=True,
                check=False,
                **self._no_window_kwargs(),
            )

        if self.brave_process is not None and self.brave_process.poll() is None:
            self.brave_process.terminate()
            try:
                self.brave_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.brave_process.kill()
                self.brave_process.wait(timeout=3)
        self.brave_process = None

    def _lock_browser(self, automatic: bool = False) -> bool:
        if self.is_locking or self.session_key is None:
            return self.session_key is None

        self.is_locking = True
        try:
            try:
                self._terminate_brave()
            except OSError as exc:
                QMessageBox.critical(None, "Lock Failed", f"Could not close Brave cleanly.\n\n{exc}")
                return False

            try:
                self.crypto.lock_profile(self.session_key)
            except (CryptoError, OSError) as exc:
                QMessageBox.critical(None, "Lock Failed", f"Could not encrypt profile.\n\n{exc}")
                return False

            self.session_key = None
            if automatic and self.tray_icon:
                self.tray_icon.showMessage(
                    "Browser Locked",
                    "Locked due to inactivity.",
                    QSystemTrayIcon.Information,
                    3000,
                )
            return True
        finally:
            self.is_locking = False

    def _unlock_and_launch(self) -> None:
        if self.session_key is None:
            if not self._prompt_unlock_dialog(allow_cancel=True):
                return
        if not self._launch_brave():
            self._lock_browser()

    def _open_extensions_page(self) -> None:
        if self.session_key is None:
            if not self._prompt_unlock_dialog(allow_cancel=True):
                return
        if not self._launch_brave("brave://extensions"):
            QMessageBox.warning(None, "Unavailable", "Could not open Brave extensions page.")

    def _open_bookmarks_page(self) -> None:
        if self.session_key is None:
            if not self._prompt_unlock_dialog(allow_cancel=True):
                return
        if not self._launch_brave("brave://bookmarks"):
            QMessageBox.warning(None, "Unavailable", "Could not open Brave bookmarks page.")

    def _open_settings(self) -> None:
        if self.session_key is None:
            if not self._prompt_unlock_dialog(allow_cancel=True):
                return

        dialog = SettingsDialog(
            state=self.state,
            state_store=self.state_store,
            profile_dir=self.crypto.profile_dir,
            on_change_password=self._change_password,
            on_clear_data=self._clear_data,
            on_open_extensions=self._open_extensions_page,
            on_open_bookmarks=self._open_bookmarks_page,
            parent=None,
        )
        dialog.exec()

    def _change_password(self, old_password: str, new_password: str) -> tuple[bool, str]:
        try:
            self.session_key = self.crypto.change_password(old_password, new_password, self.state)
            self.state_store.save_state(self.state)
            return True, "Password updated."
        except AuthenticationError as exc:
            return False, str(exc)
        except CryptoError as exc:
            return False, f"Failed to rotate password: {exc}"

    def _clear_data(self) -> tuple[bool, str]:
        try:
            self._terminate_brave()
            backup = self.crypto.clear_browsing_data()
            return True, f"Browsing data cleared. Backup saved to: {backup}"
        except Exception as exc:
            return False, f"Clear failed: {exc}"

    def _show_or_unlock(self) -> None:
        if self._has_active_browser():
            return
        self._unlock_and_launch()

    def _setup_tray(self) -> None:
        if not QSystemTrayIcon.isSystemTrayAvailable():
            return

        tray_icon = QSystemTrayIcon(self.app.windowIcon(), self.app)
        tray_menu = QMenu()

        open_action = QAction("Open / Unlock", tray_menu)
        open_action.triggered.connect(self._show_or_unlock)
        tray_menu.addAction(open_action)

        extensions_action = QAction("Extensions", tray_menu)
        extensions_action.triggered.connect(self._open_extensions_page)
        tray_menu.addAction(extensions_action)

        settings_action = QAction("Settings", tray_menu)
        settings_action.triggered.connect(self._open_settings)
        tray_menu.addAction(settings_action)

        lock_action = QAction("Lock Browser", tray_menu)
        lock_action.triggered.connect(lambda: self._lock_browser(automatic=False))
        tray_menu.addAction(lock_action)

        quit_action = QAction("Quit", tray_menu)
        quit_action.triggered.connect(self._quit_app)
        tray_menu.addAction(quit_action)

        tray_icon.setContextMenu(tray_menu)
        try:
            double_click_reason = QSystemTrayIcon.ActivationReason.DoubleClick
        except AttributeError:
            double_click_reason = QSystemTrayIcon.DoubleClick
        tray_icon.activated.connect(
            lambda reason: self._show_or_unlock() if reason == double_click_reason else None
        )
        tray_icon.show()
        self.tray_icon = tray_icon

    def _check_idle_timeout(self) -> None:
        if self.session_key is None or self.is_locking:
            return
        if self._has_active_browser():
            return

        timeout_min = int(self.state.get("settings", {}).get("idle_lock_minutes", 15))
        timeout_seconds = max(1, timeout_min) * 60
        idle_for = time.monotonic() - self.last_activity
        if idle_for >= timeout_seconds:
            self._lock_browser(automatic=True)

    def eventFilter(self, watched, event) -> bool:
        if event.type() in (
            QEvent.KeyPress,
            QEvent.MouseButtonPress,
            QEvent.MouseMove,
            QEvent.Wheel,
        ):
            self.last_activity = time.monotonic()
        return super().eventFilter(watched, event)

    def _quit_app(self) -> None:
        self.app.quit()

    def _on_about_to_quit(self) -> None:
        self.idle_timer.stop()
        self.process_timer.stop()
        try:
            self._terminate_brave()
        except Exception:
            pass

        if self.session_key is not None:
            try:
                self.crypto.lock_profile(self.session_key)
            except (CryptoError, OSError):
                pass
            self.session_key = None

        if self.tray_icon is not None:
            self.tray_icon.hide()

        if self.instance_lock and self.instance_lock.isLocked():
            self.instance_lock.unlock()


def main() -> int:
    app = QApplication(sys.argv)
    controller = SecureBrowserController(app)
    if not controller.initialize():
        return 0
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
