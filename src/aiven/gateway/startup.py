"""What the gateway checks and makes at startup (plan Task 3.5; M3 flag #4).

The gateway verifies signatures with `/usr/bin/ssh-keygen`, a path fixed in its code, never taken
from a request or a file. Before it trusts the binary, `check_ssh_keygen` makes sure that it is a
regular file (not a link), owned by root, writable by nobody but root (so not by group or others,
and not by the service user, which must not be root), in a folder that only root can write. If any
of that fails, the gateway loads no policy and alerts (policies.py).

`private_tmpdir` makes the folder for signatures and the trust anchor: 0700, the service user's
only. `minimal_path` gives the process a PATH of the system's own folders.
"""

import os
import stat
import tempfile
from pathlib import Path

SSH_KEYGEN = "/usr/bin/ssh-keygen"
MINIMAL_PATH = "/usr/bin:/bin"


class UnsafeSshKeygen(Exception):
    """The ssh-keygen at the pinned path cannot be trusted. The message says why, in words."""


def _root_only(info: os.stat_result) -> bool:
    return info.st_uid == 0 and not info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)


def check_ssh_keygen(path: str = SSH_KEYGEN) -> None:
    """Raise UnsafeSshKeygen unless `path` is safe to run. See the module docstring."""
    try:
        info = os.lstat(path)
        folder = os.lstat(os.path.dirname(path) or ".")
    except OSError as error:
        raise UnsafeSshKeygen(f"it cannot be found ({type(error).__name__})") from error
    if not stat.S_ISREG(info.st_mode):
        raise UnsafeSshKeygen("it is not a regular file")
    if not _root_only(info):
        raise UnsafeSshKeygen("it is not owned by root, or others can write it")
    if not _root_only(folder):
        raise UnsafeSshKeygen("its folder is not root's alone")
    if os.access(path, os.W_OK):
        raise UnsafeSshKeygen("the service user can write it (the gateway must not run as root)")


def private_tmpdir(path: Path | None = None) -> Path:
    """A folder that only the service user can open: `path`, made 0700, or a new temporary one."""
    if path is None:
        return Path(tempfile.mkdtemp(prefix="aiven-gateway-"))
    path.mkdir(mode=0o700, parents=True, exist_ok=False)
    path.chmod(0o700)
    return path


def minimal_path() -> None:
    """Give the process the system's own PATH only."""
    os.environ["PATH"] = MINIMAL_PATH
