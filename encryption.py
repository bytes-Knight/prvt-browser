from __future__ import annotations

import base64
import io
import os
import shutil
import subprocess
import tarfile
from datetime import datetime
from pathlib import Path
from typing import Any

import bcrypt
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class CryptoError(Exception):
    pass


class AuthenticationError(CryptoError):
    pass


class CryptoManager:
    def __init__(self, base_dir: Path) -> None:
        self.base_dir = Path(base_dir)
        self.profile_dir = self.base_dir / "profile"
        self.encrypted_profile = self.base_dir / "profile.enc"
        self.backup_encrypted_profile = self.base_dir / "profile.enc.bak"
        self.unlock_marker = self.base_dir / ".profile.unlocked"
        self.profile_restore_backup = self.base_dir / "profile.restore.bak"
        self.backups_dir = self.base_dir / "backups"

    @staticmethod
    def hash_password(password: str) -> str:
        return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")

    @staticmethod
    def verify_password(password: str, password_hash: str) -> bool:
        if not password_hash:
            return False
        try:
            return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
        except ValueError:
            return False

    def initialize_master_password(self, password: str, state: dict[str, Any]) -> None:
        salt = self._new_salt()
        key = self._derive_fernet_key(password, salt)
        state["password_hash"] = self.hash_password(password)
        state["kdf_salt"] = salt
        self.ensure_profile_structure()
        self.lock_profile(key)

    def unlock_profile(self, password: str, state: dict[str, Any]) -> bytes:
        password_hash = state.get("password_hash", "")
        salt = state.get("kdf_salt", "")
        if not self.verify_password(password, password_hash):
            raise AuthenticationError("Invalid password.")
        if not salt:
            raise AuthenticationError("Key-derivation salt is missing.")

        key = self._derive_fernet_key(password, salt)
        has_plain_profile = self.profile_dir.exists()
        has_encrypted_profile = self.encrypted_profile.exists()

        if has_plain_profile and has_encrypted_profile:
            # Crash-recovery path: keep live profile only if app previously marked it as unlocked.
            if self.unlock_marker.exists():
                self.ensure_profile_structure()
            else:
                try:
                    self._decrypt_profile(key)
                except AuthenticationError:
                    # Preserve readable plaintext profile if encrypted payload is damaged.
                    self.ensure_profile_structure()
        elif has_plain_profile:
            self.ensure_profile_structure()
        elif has_encrypted_profile:
            self._decrypt_profile(key)
        else:
            self.ensure_profile_structure()

        self.harden_profile_permissions(self.profile_dir)
        self._write_unlock_marker()
        return key

    def lock_profile(self, key: bytes) -> None:
        if not self.profile_dir.exists():
            self._clear_unlock_marker()
            return
        self._encrypt_profile(key)
        self._clear_unlock_marker()

    def change_password(self, old_password: str, new_password: str, state: dict[str, Any]) -> bytes:
        if not self.verify_password(old_password, state.get("password_hash", "")):
            raise AuthenticationError("Old password is incorrect.")

        new_salt = self._new_salt()
        new_key = self._derive_fernet_key(new_password, new_salt)
        state["password_hash"] = self.hash_password(new_password)
        state["kdf_salt"] = new_salt
        return new_key

    def clear_browsing_data(self) -> Path:
        targets = ["cookies", "cache", "history", "sessions", "downloads", "brave-user-data"]
        backup_path = self._prepare_data_backup_dir()
        if backup_path is None:
            raise OSError("Could not create browsing-data backup folder.")

        moved_targets: list[tuple[Path, Path]] = []
        for directory in targets:
            target = self.profile_dir / directory
            moved = backup_path / directory
            try:
                if target.exists():
                    if moved.exists():
                        shutil.rmtree(moved, ignore_errors=True)
                    shutil.move(str(target), str(moved))
                    moved_targets.append((target, moved))
                target.mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                for original, archived in reversed(moved_targets):
                    try:
                        if original.exists():
                            shutil.rmtree(original, ignore_errors=True)
                        if archived.exists():
                            shutil.move(str(archived), str(original))
                    except OSError:
                        pass
                raise OSError("Failed to clear browsing data safely.") from exc
        self.ensure_profile_structure()
        return backup_path

    def ensure_profile_structure(self) -> None:
        self._ensure_profile_structure_at(self.profile_dir)

    def _ensure_profile_structure_at(self, root: Path) -> None:
        if root.exists() and not root.is_dir():
            self._replace_conflicting_file(root)
        root.mkdir(parents=True, exist_ok=True)
        required = ["cookies", "cache", "history", "sessions", "extensions", "downloads"]
        for name in required:
            target = root / name
            if target.exists() and not target.is_dir():
                self._replace_conflicting_file(target)
            target.mkdir(parents=True, exist_ok=True)

    def _replace_conflicting_file(self, path: Path) -> None:
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        backup_name = f"{path.name}.conflict-{timestamp}.bak"
        backup_path = path.with_name(backup_name)
        counter = 1
        while backup_path.exists():
            backup_path = path.with_name(f"{backup_name}.{counter}")
            counter += 1
        try:
            path.rename(backup_path)
        except OSError:
            path.unlink(missing_ok=True)

    def harden_profile_permissions(self, profile_path: Path) -> None:
        if not profile_path.exists():
            return
        if os.name == "nt":
            username = os.environ.get("USERNAME")
            if not username:
                return
            subprocess.run(
                ["icacls", str(profile_path), "/inheritance:r"],
                capture_output=True,
                check=False,
            )
            subprocess.run(
                ["icacls", str(profile_path), "/grant:r", f"{username}:(OI)(CI)F"],
                capture_output=True,
                check=False,
            )
            return

        for root, dirs, files in os.walk(profile_path):
            os.chmod(root, 0o700)
            for name in dirs:
                os.chmod(Path(root) / name, 0o700)
            for name in files:
                os.chmod(Path(root) / name, 0o600)

    def _encrypt_profile(self, key: bytes) -> None:
        payload = self._pack_profile_directory()
        cipher = Fernet(key).encrypt(payload)
        temp_file = self.encrypted_profile.with_suffix(".enc.tmp")
        if self.encrypted_profile.exists():
            try:
                shutil.copy2(self.encrypted_profile, self.backup_encrypted_profile)
            except OSError:
                pass
        temp_file.write_bytes(cipher)
        temp_file.replace(self.encrypted_profile)
        shutil.rmtree(self.profile_dir, ignore_errors=True)

    def _decrypt_profile(self, key: bytes) -> None:
        candidates = [self.encrypted_profile, self.backup_encrypted_profile]
        errors: list[Exception] = []

        for source in candidates:
            if not source.exists():
                continue
            try:
                self._decrypt_profile_from_source(source, key)
                if source != self.encrypted_profile:
                    try:
                        shutil.copy2(source, self.encrypted_profile)
                    except OSError:
                        pass
                return
            except (AuthenticationError, CryptoError, OSError) as exc:
                errors.append(exc)

        if errors:
            raise errors[0]
        self.ensure_profile_structure()

    def _decrypt_profile_from_source(self, source: Path, key: bytes) -> None:
        encrypted_data = source.read_bytes()
        try:
            payload = Fernet(key).decrypt(encrypted_data)
        except InvalidToken as exc:
            raise AuthenticationError("Unable to decrypt profile with this password.") from exc

        temp_profile = self.base_dir / "profile.restore.tmp"
        if temp_profile.exists():
            shutil.rmtree(temp_profile, ignore_errors=True)
        temp_profile.mkdir(parents=True, exist_ok=True)

        try:
            with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as tar:
                self._safe_extract(tar, temp_profile)
            self._ensure_profile_structure_at(temp_profile)
            self._swap_in_profile_directory(temp_profile)
        finally:
            if temp_profile.exists():
                shutil.rmtree(temp_profile, ignore_errors=True)

    def _swap_in_profile_directory(self, replacement: Path) -> None:
        if self.profile_restore_backup.exists():
            shutil.rmtree(self.profile_restore_backup, ignore_errors=True)

        moved_old_profile = False
        if self.profile_dir.exists():
            shutil.move(str(self.profile_dir), str(self.profile_restore_backup))
            moved_old_profile = True

        try:
            shutil.move(str(replacement), str(self.profile_dir))
            if moved_old_profile and self.profile_restore_backup.exists():
                shutil.rmtree(self.profile_restore_backup, ignore_errors=True)
        except OSError:
            if self.profile_dir.exists():
                shutil.rmtree(self.profile_dir, ignore_errors=True)
            if moved_old_profile and self.profile_restore_backup.exists():
                shutil.move(str(self.profile_restore_backup), str(self.profile_dir))
            raise

    def _write_unlock_marker(self) -> None:
        try:
            self.unlock_marker.write_text("1", encoding="ascii")
        except OSError:
            pass

    def _clear_unlock_marker(self) -> None:
        if self.unlock_marker.exists():
            try:
                self.unlock_marker.unlink()
            except OSError:
                pass

    def _pack_profile_directory(self) -> bytes:
        self.ensure_profile_structure()
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w:gz") as tar:
            for item in sorted(self.profile_dir.iterdir()):
                tar.add(item, arcname=item.name, recursive=True)
        return stream.getvalue()

    @staticmethod
    def _safe_extract(tar: tarfile.TarFile, destination: Path) -> None:
        base = destination.resolve()
        for member in tar.getmembers():
            member_path = Path(member.name)
            if member_path.is_absolute():
                raise CryptoError("Blocked absolute archive path during profile restore.")
            if member.issym() or member.islnk():
                raise CryptoError("Blocked link entry during profile restore.")
            resolved = (destination / member.name).resolve()
            if resolved != base and base not in resolved.parents:
                raise CryptoError("Blocked unsafe archive path during profile restore.")
        tar.extractall(path=destination)

    @staticmethod
    def _new_salt() -> str:
        return base64.urlsafe_b64encode(os.urandom(16)).decode("ascii")

    @staticmethod
    def _derive_fernet_key(password: str, salt_b64: str) -> bytes:
        try:
            salt = base64.urlsafe_b64decode(salt_b64.encode("ascii"))
        except Exception as exc:
            raise CryptoError("Stored key-derivation salt is invalid.") from exc
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=390000,
        )
        raw_key = kdf.derive(password.encode("utf-8"))
        return base64.urlsafe_b64encode(raw_key)

    def _prepare_data_backup_dir(self) -> Path | None:
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        for counter in range(100):
            suffix = "" if counter == 0 else f"-{counter}"
            backup_path = self.backups_dir / f"browsing-data-{timestamp}{suffix}"
            try:
                backup_path.mkdir(parents=True, exist_ok=False)
                return backup_path
            except OSError:
                continue
        return None
