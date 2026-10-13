"""Throwaway keys and real signatures for the tests of `verify` (validator-spec section 2).

`make_signer(folder)` makes an ed25519 key in `folder` with `ssh-keygen -t ed25519 -N ""`, and the
`allowed_signers` file that trusts it. A test signs bytes with `Signer.sign` and gives the signature
and the file to `verify`. Every key lives in the `tmp_path` of one test, so no key is stored
anywhere. Nothing here skips when ssh-keygen is missing: `make_signer` fails, loudly.

`work_in_a_temporary_folder` is the autouse fixture for the test modules that run ssh-keygen, or run
the code that does. ssh-keygen that is called wrongly (with a shell, say, and no arguments) reads
its answers from its input, which is a policy file, and makes a key in the current folder named
after the first line of it. That must not be the repository, so such a test module imports the
fixture: importing it, under its own name, is what makes pytest use it there.
"""

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest


@dataclass(frozen=True)
class Signer:
    """A throwaway ed25519 key, and the `allowed_signers` file that trusts it."""

    key: Path
    allowed_signers: Path

    def sign(self, data: bytes, namespace: str = "aiven-policy-v1") -> bytes:
        """The detached signature of `data`, as `ssh-keygen -Y sign` writes it."""
        done = subprocess.run(
            ["ssh-keygen", "-Y", "sign", "-f", str(self.key), "-n", namespace],
            input=data,
            capture_output=True,
            check=True,
        )
        return done.stdout


def make_signer(
    folder: Path, name: str = "matthijs", namespaces: str | None = "aiven-policy-v1"
) -> Signer:
    """A new key in `folder`, trusted as `name` for `namespaces` (None: for every namespace).

    With the defaults the file of allowed signers has the one line of validator-spec section 2.
    """
    assert shutil.which("ssh-keygen"), "ssh-keygen is needed for the signing tests (OpenSSH)"
    folder.mkdir()
    key = folder / "key"
    command = ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "", "-f", str(key)]
    subprocess.run(command, capture_output=True, check=True)
    public = (folder / "key.pub").read_text().split()[:2]  # the type and the key, no comment
    options = "" if namespaces is None else f' namespaces="{namespaces}"'
    allowed = folder / "allowed_signers"
    allowed.write_text(f"{name}{options} {' '.join(public)}\n")
    return Signer(key, allowed)


@pytest.fixture(autouse=True)
def work_in_a_temporary_folder(tmp_path, monkeypatch):
    """Run the test in a folder of its own. See the module docstring."""
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.chdir(work)
