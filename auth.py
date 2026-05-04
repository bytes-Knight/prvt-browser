from __future__ import annotations

from typing import Callable

from PySide6.QtCore import QObject, QThread, Qt, Signal
from PySide6.QtGui import QCloseEvent, QFont
from PySide6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QFormLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
)


MAX_LOGIN_ATTEMPTS = 5


class _VerifyWorker(QObject):
    finished = Signal(bool, str, str)

    def __init__(self, verify_callback: Callable[[str], tuple[bool, str]], password: str) -> None:
        super().__init__()
        self.verify_callback = verify_callback
        self.password = password

    def run(self) -> None:
        try:
            ok, message = self.verify_callback(self.password)
        except Exception as exc:
            ok, message = False, f"Unlock failed: {exc}"
        self.finished.emit(ok, message, self.password)


class PasswordSetupDialog(QDialog):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Create Master Password")
        self.setModal(True)
        self.setMinimumWidth(440)
        self.setWindowFlag(Qt.WindowContextHelpButtonHint, False)
        self.password: str | None = None

        title = QLabel("Secure Brave Profile")
        title_font = QFont()
        title_font.setPointSize(12)
        title_font.setBold(True)
        title.setFont(title_font)

        heading = QLabel("First run detected. Create a master password to encrypt all browser data.")
        heading.setWordWrap(True)

        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.Password)
        self.password_edit.setPlaceholderText("At least 8 characters")
        self.confirm_edit = QLineEdit()
        self.confirm_edit.setEchoMode(QLineEdit.Password)
        self.confirm_edit.setPlaceholderText("Re-enter password")
        self.confirm_edit.returnPressed.connect(self._accept_if_valid)

        form = QFormLayout()
        form.setVerticalSpacing(10)
        form.setHorizontalSpacing(12)
        form.addRow("Master password:", self.password_edit)
        form.addRow("Confirm password:", self.confirm_edit)

        self.ok_btn = QPushButton("Create")
        self.ok_btn.clicked.connect(self._accept_if_valid)
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setObjectName("secondaryButton")
        self.cancel_btn.clicked.connect(self.reject)

        button_row = QHBoxLayout()
        button_row.addStretch(1)
        button_row.addWidget(self.cancel_btn)
        button_row.addWidget(self.ok_btn)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(12)
        layout.addWidget(title)
        layout.addWidget(heading)
        layout.addLayout(form)
        layout.addLayout(button_row)

    def _accept_if_valid(self) -> None:
        password = self.password_edit.text()
        confirm = self.confirm_edit.text()
        if len(password) < 8:
            QMessageBox.warning(self, "Weak Password", "Use at least 8 characters.")
            return
        if password != confirm:
            QMessageBox.warning(self, "Mismatch", "Password and confirmation do not match.")
            return
        self.password = password
        self.accept()


class LoginDialog(QDialog):
    def __init__(
        self,
        verify_callback: Callable[[str], tuple[bool, str]],
        parent=None,
    ) -> None:
        super().__init__(parent)
        self.verify_callback = verify_callback
        self.password: str | None = None
        self.failed_attempts = 0
        self.hard_locked = False
        self._verify_thread: QThread | None = None
        self._verify_worker: _VerifyWorker | None = None

        self.setWindowTitle("Unlock Browser")
        self.setModal(True)
        self.setMinimumWidth(440)
        self.setWindowFlag(Qt.WindowContextHelpButtonHint, False)

        title = QLabel("Unlock Secure Browser")
        title_font = QFont()
        title_font.setPointSize(12)
        title_font.setBold(True)
        title.setFont(title_font)

        self.message = QLabel("Enter your master password to unlock your encrypted profile.")
        self.message.setWordWrap(True)
        self.message.setObjectName("loginMessage")

        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.Password)
        self.password_edit.setPlaceholderText("Master password")
        self.password_edit.returnPressed.connect(self._try_login)

        form = QFormLayout()
        form.setVerticalSpacing(10)
        form.setHorizontalSpacing(12)
        form.addRow("Password:", self.password_edit)

        self.unlock_btn = QPushButton("Unlock")
        self.unlock_btn.clicked.connect(self._try_login)
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setObjectName("secondaryButton")
        self.cancel_btn.clicked.connect(self.reject)

        button_row = QHBoxLayout()
        button_row.addStretch(1)
        button_row.addWidget(self.cancel_btn)
        button_row.addWidget(self.unlock_btn)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(12)
        layout.addWidget(title)
        layout.addWidget(self.message)
        layout.addLayout(form)
        layout.addLayout(button_row)

    def _set_busy(self, busy: bool) -> None:
        self.unlock_btn.setDisabled(busy)
        self.cancel_btn.setDisabled(busy)
        self.password_edit.setDisabled(busy)
        if busy:
            self.message.setText("Unlocking encrypted profile. Please wait...")

    def _try_login(self) -> None:
        if self._verify_thread is not None and self._verify_thread.isRunning():
            return

        candidate = self.password_edit.text()
        if not candidate:
            self.message.setText("Enter your password to continue.")
            return

        self._set_busy(True)
        self._verify_thread = QThread(self)
        self._verify_worker = _VerifyWorker(self.verify_callback, candidate)
        self._verify_worker.moveToThread(self._verify_thread)

        self._verify_thread.started.connect(self._verify_worker.run)
        self._verify_worker.finished.connect(self._on_verify_finished)
        self._verify_worker.finished.connect(self._verify_thread.quit)
        self._verify_thread.finished.connect(self._verify_thread.deleteLater)
        self._verify_thread.finished.connect(self._cleanup_worker)
        self._verify_thread.start()

    def _on_verify_finished(self, ok: bool, message: str, candidate: str) -> None:
        self._set_busy(False)
        if ok:
            self.password = candidate
            self.accept()
            return

        self.failed_attempts += 1
        remaining = MAX_LOGIN_ATTEMPTS - self.failed_attempts
        self.password_edit.clear()

        if remaining <= 0:
            self.hard_locked = True
            QMessageBox.critical(
                self,
                "Locked",
                "Too many failed attempts. The app is locked for this run.",
            )
            self.reject()
            return

        self.message.setText(f"{message} Attempts remaining: {remaining}")

    def _cleanup_worker(self) -> None:
        if self._verify_worker is not None:
            self._verify_worker.deleteLater()
        self._verify_worker = None
        self._verify_thread = None

    def closeEvent(self, event: QCloseEvent) -> None:
        if self._verify_thread is not None and self._verify_thread.isRunning():
            event.ignore()
            return
        super().closeEvent(event)
