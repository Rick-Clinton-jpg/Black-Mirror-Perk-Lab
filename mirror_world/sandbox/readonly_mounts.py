"""Trusted pre-drop step: make every mount in this namespace read-only.

The namespace launcher runs this as root inside the agent's private mount
namespace, after ``mount --make-rprivate /`` and before privileges are
dropped. It must never run in the host's own mount namespace.

A plain ``mount -o remount,bind,ro /`` changes only the root mount. Separate
mounts such as /dev/shm, /proc, or a tmpfs /tmp stay writable (confirmed live
in 0.9.7: uid 65534 could write /dev/shm; util-linux's ``ro=recursive`` and
``X-mount.recursive`` did not help on remount). mount_setattr(2) with
AT_RECURSIVE applies MOUNT_ATTR_RDONLY to the whole tree at once. It requires
Linux 5.12 or newer; any failure exits non-zero, so the launch fails closed.
"""

from __future__ import annotations

import ctypes
import os
import sys

# mount_setattr was added in 5.12 with one syscall number on every
# architecture that uses the common table (x86_64, arm64, ...).
_SYS_MOUNT_SETATTR = 442
_AT_FDCWD = -100
_AT_RECURSIVE = 0x8000
_MOUNT_ATTR_RDONLY = 0x00000001


class _MountAttr(ctypes.Structure):
    _fields_ = [
        ("attr_set", ctypes.c_uint64),
        ("attr_clr", ctypes.c_uint64),
        ("propagation", ctypes.c_uint64),
        ("userns_fd", ctypes.c_uint64),
    ]


def make_all_mounts_read_only() -> None:
    """Set every mount below / read-only, or raise OSError."""
    libc = ctypes.CDLL(None, use_errno=True)
    attr = _MountAttr(_MOUNT_ATTR_RDONLY, 0, 0, 0)
    result = libc.syscall(
        ctypes.c_long(_SYS_MOUNT_SETATTR), ctypes.c_int(_AT_FDCWD), b"/",
        ctypes.c_uint(_AT_RECURSIVE), ctypes.byref(attr), ctypes.c_size_t(ctypes.sizeof(attr)),
    )
    if result != 0:
        err = ctypes.get_errno()
        raise OSError(err, f"mount_setattr: {os.strerror(err)}")


if __name__ == "__main__":
    try:
        make_all_mounts_read_only()
    except OSError as exc:
        sys.stderr.write(f"read-only mount setup failed: {exc}\n")
        sys.exit(1)
