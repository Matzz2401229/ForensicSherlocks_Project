"""Bounded, descriptor-relative best-effort deletion for explicitly selected trees.

This is not a guarantee of forensic erasure. Live deletion requires Linux /proc.
Incomplete operations retain a private quarantine directory and report its path.
"""
from dataclasses import dataclass, field
import os
from pathlib import Path
import secrets
import stat
import sys

CHUNK_BYTES = 1024 * 1024
MAX_DEPTH = 128
FORBIDDEN_TREES = ("/bin", "/boot", "/dev", "/etc", "/lib", "/lib32", "/lib64", "/libx32",
                   "/proc", "/run", "/sbin", "/snap", "/sys", "/usr", "/var")


class DeleteError(ValueError):
    pass


def within(path, root):
    return path == root or root in path.parents


def validate_root(value, what, allow_final_symlink=False):
    if not isinstance(value, str) or not value or any(ord(c) < 32 for c in value):
        raise DeleteError(f"{what} must be a non-empty path string without control characters")
    path = Path(os.path.normpath(value))
    if not path.is_absolute():
        raise DeleteError(f"{what} must be an absolute path: {value!r}")
    if len(path.parts) < 3:
        raise DeleteError(f"{what} is too broad (needs at least two levels): {value!r}")
    for tree in FORBIDDEN_TREES:
        if within(path, Path(tree)):
            raise DeleteError(f"{what} is inside protected system tree {tree}: {value!r}")
    # Runtime traversal independently refuses aliases, including changes after validation.
    resolved = Path(os.path.realpath(path.parent)) / path.name if allow_final_symlink else Path(os.path.realpath(path))
    if resolved != path:
        raise DeleteError(f"{what} cannot use symbolic-link aliases: {value!r}")
    return path


@dataclass
class DeleteReport:
    files: int = 0
    others: int = 0
    dirs: int = 0
    bytes: int = 0
    absent: list = field(default_factory=list)
    errors: list = field(default_factory=list)
    planned: list = field(default_factory=list)
    retained: list = field(default_factory=list)

    def as_dict(self, apply):
        out = {"files": self.files, "other_entries": self.others, "dirs": self.dirs, "bytes": self.bytes,
               "absent": self.absent, "errors": self.errors, "retained_paths": self.retained}
        if not apply:
            out.update(would_delete=self.planned[:200], would_delete_truncated=len(self.planned) > 200)
        return out


def _mount_id(fd):
    for line in Path(f"/proc/self/fdinfo/{fd}").read_text().splitlines():
        if line.startswith("mnt_id:"):
            return int(line.split()[1])
    raise DeleteError("Cannot establish filesystem mount identity")


def _identity(info):
    return info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode)


def _open_root(root):
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open("/", flags)
    try:
        for component in root.parts[1:]:
            child = os.open(component, flags, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def _open_parent(root_fd, relative, mount_id):
    fd = os.dup(root_fd)
    try:
        for component in relative.parts[:-1]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=fd)
            try:
                if _mount_id(child) != mount_id:
                    raise DeleteError("Refusing a nested mount in a deletion target")
            except BaseException:
                os.close(child)
                raise
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def _pin(parent, name, mount_id):
    fd = os.open(name, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
    try:
        if _mount_id(fd) != mount_id:
            raise DeleteError("Refusing a nested or bind mount")
        return fd, os.fstat(fd)
    except BaseException:
        os.close(fd)
        raise


def _single_link(fd):
    if os.fstat(fd).st_nlink != 1:
        raise DeleteError("Refusing an unlinked or multiply linked regular file")


def _overwrite_pinned(pin, passes, randbytes):
    # Reopen our own held O_PATH reference, rather than resolving a mutable pathname.
    fd = os.open(f"/proc/self/fd/{pin}", os.O_WRONLY | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or _identity(info) != _identity(os.fstat(pin)):
            raise DeleteError("File identity changed before overwrite")
        _single_link(fd)
        size = info.st_size
        for _ in range(passes):
            os.lseek(fd, 0, os.SEEK_SET)
            remaining = size
            while remaining:
                _single_link(fd)
                wanted = min(CHUNK_BYTES, remaining)
                data = randbytes(wanted)
                if len(data) != wanted:
                    raise DeleteError("Random source returned an incomplete overwrite block")
                view = memoryview(data)
                while view:
                    _single_link(fd)
                    written = os.write(fd, view)
                    if written <= 0:
                        raise DeleteError("Overwrite made no progress")
                    view = view[written:]
                remaining -= len(data)
            os.fsync(fd)
        _single_link(fd)
        os.ftruncate(fd, 0)
        os.fsync(fd)
        return size
    finally:
        os.close(fd)


def _remove(parent, name, display, mount_id, passes, apply, report, randbytes, depth=0):
    pin = directory = -1
    try:
        if depth > MAX_DEPTH:
            raise DeleteError("Deletion tree exceeds the supported depth")
        pin, info = _pin(parent, name, mount_id)
        if stat.S_ISREG(info.st_mode):
            _single_link(pin)
            size = _overwrite_pinned(pin, passes, randbytes) if apply else info.st_size
            if apply:
                if _identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) != _identity(info):
                    raise DeleteError("Name changed; replacement was not unlinked")
                os.unlink(name, dir_fd=parent)
            else:
                report.planned.append(str(display))
            report.files += 1
            report.bytes += size
        elif stat.S_ISDIR(info.st_mode):
            directory = os.open(f"/proc/self/fd/{pin}", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            with os.scandir(directory) as entries:
                for entry in entries:
                    _remove(directory, entry.name, display / entry.name, mount_id, passes, apply,
                            report, randbytes, depth + 1)
            if apply:
                if _identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) != _identity(info):
                    raise DeleteError("Directory name changed; replacement was not removed")
                os.rmdir(name, dir_fd=parent)
            else:
                report.planned.append(str(display) + "/")
            report.dirs += 1
        else:
            # O_PATH never opens a FIFO/device for I/O; links are unlinked without following them.
            if apply:
                if _identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) != _identity(info):
                    raise DeleteError("Entry identity changed")
                os.unlink(name, dir_fd=parent)
            else:
                report.planned.append(str(display))
            report.others += 1
    except FileNotFoundError:
        return
    except (OSError, DeleteError) as error:
        report.errors.append({"path": str(display), "error": str(error)})
    finally:
        if directory >= 0:
            os.close(directory)
        if pin >= 0:
            os.close(pin)


def secure_delete(target, roots, passes, apply, randbytes=os.urandom, report=None):
    report = report if report is not None else DeleteReport()
    root_fd = parent = pin = quarantine = -1
    quarantine_name = None
    root = None
    try:
        if sys.platform != "linux" or not hasattr(os, "O_PATH"):
            raise DeleteError("Filesystem deletion inspection requires Linux O_PATH and /proc")
        if type(passes) is not int or not 1 <= passes <= 7:
            raise DeleteError("Overwrite passes must be an integer from 1 to 7")
        target = Path(os.path.normpath(target))
        checked = [validate_root(str(r), "allowed root") for r in roots]
        choices = [r for r in checked if within(target, r) and target != r]
        if not choices:
            raise DeleteError("Target is outside allowed roots or is a root itself")
        root = max(choices, key=lambda r: len(r.parts))
        root_fd = _open_root(root)
        mount_id = _mount_id(root_fd)
        parent = _open_parent(root_fd, target.relative_to(root), mount_id)
        pin, before = _pin(parent, target.name, mount_id)
        if stat.S_ISREG(before.st_mode):
            _single_link(pin)  # Reject existing hard links before moving or modifying the target.
        if not apply:
            _remove(parent, target.name, target, mount_id, passes, False, report, randbytes)
            return report
        # Capture the chosen entry under a private directory before recursive mutation.
        # If a source is replaced during capture, retain it without overwriting its data.
        for _ in range(10):
            candidate = ".portwatchman-delete-" + secrets.token_hex(12)
            try:
                os.mkdir(candidate, 0o700, dir_fd=root_fd)
                quarantine_name = candidate
                break
            except FileExistsError:
                continue
        if quarantine_name is None:
            raise DeleteError("Cannot reserve a private deletion directory")
        quarantine = os.open(quarantine_name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                             dir_fd=root_fd)
        owner = os.fstat(quarantine)
        if owner.st_uid != os.geteuid() or stat.S_IMODE(owner.st_mode) != 0o700 or os.listdir(quarantine):
            raise DeleteError("Deletion directory ownership or permissions changed")
        if _identity(os.stat(quarantine_name, dir_fd=root_fd, follow_symlinks=False)) != _identity(owner):
            raise DeleteError("Deletion directory was replaced")
        os.rename(target.name, "target", src_dir_fd=parent, dst_dir_fd=quarantine)
        if _identity(os.stat("target", dir_fd=quarantine, follow_symlinks=False)) != _identity(before):
            raise DeleteError("Target changed during capture; captured entry was retained without overwrite")
        _remove(quarantine, "target", target, mount_id, passes, True, report, randbytes)
    except FileNotFoundError:
        report.absent.append(str(target))
    except (OSError, DeleteError) as error:
        report.errors.append({"path": str(target), "error": "outside allowed roots or unsafe filesystem state: " + str(error)})
    finally:
        if quarantine >= 0:
            # Only remove the directory name if it still denotes our captured directory.
            try:
                owner = os.fstat(quarantine)
                current = os.stat(quarantine_name, dir_fd=root_fd, follow_symlinks=False)
                if _identity(current) != _identity(owner):
                    raise DeleteError("Deletion directory moved; inspect retained data")
                os.rmdir(quarantine_name, dir_fd=root_fd)
            except (OSError, DeleteError) as error:
                retained = str(root / quarantine_name)
                report.retained.append(retained)
                report.errors.append({"path": retained, "error": str(error)})
        elif quarantine_name is not None:
            report.retained.append(str(root / quarantine_name))
        for descriptor in (quarantine, pin, parent, root_fd):
            if descriptor >= 0:
                os.close(descriptor)
    return report
