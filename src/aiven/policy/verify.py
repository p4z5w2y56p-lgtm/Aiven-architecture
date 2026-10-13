"""Load-time verification of one policy file (validator-spec sections 2 and 3.10).

`verify` is what the gateway runs every time it loads a policy. It gives the policy only for a file
that the one signer signed, that is valid, and that may be loaded now. It works in this order and
stops at the first step that fails (rulings R43 and R56):

1. A file over 64 KiB is E-FILE-SIZE. A file that was signed was validated before it was signed, so
   it cannot be this large.
2. No signature is E-SIG-MISSING.
3. `ssh-keygen -Y verify` must accept the signature, or it is E-SIG-INVALID. A signature file over
   16 KiB is refused first, before it is written anywhere (ruling R80). The file of allowed signers
   must be a readable regular file; if it is not, that is a fault of the setup and not of the
   policy, and it is E-INTERNAL (ruling R82).
4. The file is validated, once (`validate_policy`).
5. The checks that are only possible at load run (3.10): the version against the active one
   (E-VERSION-ORDER), the wrappers (E-TOOL-NOT-LIVE) and the Drive folder (E-SCOPE-NOT-IN-SANDBOX).
   They run when step 4 gave a policy, also when it has errors, so that a report names everything.
6. The policy is returned when no finding is an error. Warnings are fine. (A step 4 that gave no
   policy and no error cannot be, and is E-INTERNAL if it ever happens.)

The file is not decoded, parsed or checked before step 4: until then its bytes go to ssh-keygen and
nowhere else. The gateway never parses what is not correctly signed, so a hostile file in the
control bucket costs it no more than a size check and a signature check. A file with a wrong
signature gets only E-SIG-INVALID, not the list of its other problems; it is refused either way.

The signature is checked by ssh-keygen with the arguments of section 2: the file of allowed signers
that the caller gives, the signer and the namespace of `constants`, and the signature in a file of
a temporary folder that only this user can open and that is removed afterwards. The file goes in
on stdin. No shell is used and nothing in the arguments comes from the file. What ssh-keygen prints
is never kept: an exit status of 0 is a valid signature, and anything else is not.

At load W-TOOL-NOT-LIVE does not exist: it is E-TOOL-NOT-LIVE (section 3.4). A tool is live when
its wrapper is built in the catalog and the caller says the wrapper is switched on for the agent
(`wrapper_live`). Only a tool that passed its own rules is judged (`tool_problem`), at the line of
its entry. The Drive folder is checked by the caller as well (`folder_check`): the validator cannot
see ancestry, which only Drive knows (section 8). Both callbacks are plain functions, not
coroutines, and answer `True` or `False` and nothing else (ruling R83): a string, `None`, a number,
a Mock or the coroutine of an `async def` is no answer, however true it looks, and ends the load in
E-INTERNAL.

Whatever goes wrong fails closed, and says only what went wrong (ruling R56): ssh-keygen is not
there or takes too long, a callback raises or answers wrongly, or a check has a bug. The result is
no policy and one E-INTERNAL, with the name of the exception class as its `detail`. The text of an
exception can hold text of the file, so it is never used.

`verify` handles one file. The checks across all policies (3.9) are done by the loader that loads
them, with `check_set`.
"""

import inspect
import re
import stat
import subprocess
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from aiven.policy.catalog import Catalog
from aiven.policy.config import PlatformConfig
from aiven.policy.constants import MAX_FILE_BYTES, MAX_SIG_BYTES, NAMESPACE, SIGNER, WRAPPER_NAMES
from aiven.policy.findings import Finding
from aiven.policy.model import Policy
from aiven.policy.tools import tool_problem
from aiven.policy.validate import report_order, validate_policy

# Long enough for a slow machine, short enough that a hung ssh-keygen cannot hold up a load.
SSH_KEYGEN_TIMEOUT_S = 10

# The hash of a file as `Policy.sha256` writes it (used with fullmatch: `$` accepts a newline).
_SHA256 = re.compile(r"sha256:[0-9a-f]{64}")


class NotARegularFile(Exception):
    """The file of allowed signers is a folder, a pipe or a device. Only the name is ever shown."""


class NoPolicy(Exception):
    """The checks gave no policy and no error, which cannot be. Only the name is ever shown."""


@dataclass(frozen=True)
class ActiveVersion:
    """The version of an agent that is loaded now: its number and the hash of its file.

    `sha256` is written as `Policy.sha256` is: `sha256:` and 64 lowercase hex digits. Any other
    form raises ValueError when this is made (review M4). A hash in another form would never equal
    the hash of the file, so the active file itself would be "the same version in other bytes" at
    every reload, and nothing would load. That is a bug of the caller, and it should show at once.
    """

    version: int
    sha256: str

    def __post_init__(self) -> None:
        if not (isinstance(self.sha256, str) and _SHA256.fullmatch(self.sha256)):
            raise ValueError("sha256 must be 'sha256:' and 64 lowercase hex digits")


def verify(
    path: Path,
    data: bytes,
    sig: bytes | None,
    allowed_signers: Path,
    active: ActiveVersion | None,
    wrapper_live: Callable[[str, str], bool],
    folder_check: Callable[[str, str | None], bool],
    cfg: PlatformConfig,
    catalog: Catalog,
) -> tuple[Policy | None, list[Finding]]:
    """The policy of the file `data` that is called `path`, and the findings, in report order.

    - `path` only names the file: nothing is read from it. Its name gives the agent of
      E-SIG-MISSING.
    - `sig` is the content of `<agent>.md.sig`, or None if there is no such file.
    - `allowed_signers` is the trust anchor, the copy in the control project. It has to be a
      readable regular file (a symlink to one will do), or the result is E-INTERNAL.
    - `active` is the version that is loaded now, or None if the agent has none.
    - `wrapper_live(wrapper, agent)` says whether the wrapper (`drive`, `email`, ...) is switched
      on for the agent.
    - `folder_check(folder_id, path)` says whether the folder is in the Sandbox drive and its real
      path is `path` (None if the policy has no path).
    - Both callbacks are synchronous and answer `True` or `False`. Any other answer raises
      TypeError inside `verify`, so it is E-INTERNAL.

    The policy is None when any finding is an error. A result with no policy and no error cannot be
    (a file gives no policy only for an error), and is E-INTERNAL if it ever happens. See the
    module docstring.
    """
    where = str(path)
    if len(data) > MAX_FILE_BYTES:
        return None, [Finding("E-FILE-SIZE", "error", where, params={"size": str(len(data))})]
    if sig is None:
        agent = path.name.removesuffix(".md")
        return None, [Finding("E-SIG-MISSING", "error", where, params={"agent": agent})]
    try:
        if not _signature_holds(data, sig, allowed_signers):
            return None, [Finding("E-SIG-INVALID", "error", where)]
        checked = validate_policy(path, data, cfg, catalog)
        findings = [found for found in checked.findings if found.code != "W-TOOL-NOT-LIVE"]
        policy = checked.policy
        if policy is not None:
            findings += _version_order(where, policy, active)
            findings += _tools_not_live(where, policy, checked.tool_lines, catalog, wrapper_live)
            findings += _folder_not_in_sandbox(where, policy, folder_check)
            findings.sort(key=report_order)
        failed = any(found.severity == "error" for found in findings)
        if policy is None and not failed:
            raise NoPolicy  # a file gives no policy only for an error (review M5)
    except Exception as error:
        params = {"detail": type(error).__name__}
        return None, [Finding("E-INTERNAL", "error", where, params=params)]
    return (None if failed else policy), findings


def _signature_holds(data: bytes, sig: bytes, allowed_signers: Path) -> bool:
    """Whether `ssh-keygen -Y verify` accepts `sig` as the signature of `data` (section 2).

    A signature over `MAX_SIG_BYTES` is none (ruling R80), and is refused before it is written. A
    file of allowed signers that cannot be used raises (ruling R82), before ssh-keygen is run.
    """
    if len(sig) > MAX_SIG_BYTES:
        return False
    _check_trust_anchor(allowed_signers)
    with tempfile.TemporaryDirectory(prefix="aiven-policy-") as folder:
        sig_file = Path(folder) / "policy.sig"
        sig_file.write_bytes(sig)
        done = subprocess.run(
            [
                "ssh-keygen",
                "-Y",
                "verify",
                "-f",
                str(allowed_signers),
                "-I",
                SIGNER,
                "-n",
                NAMESPACE,
                "-s",
                str(sig_file),
            ],
            input=data,
            capture_output=True,
            timeout=SSH_KEYGEN_TIMEOUT_S,
            check=False,
        )
    return done.returncode == 0


def _check_trust_anchor(allowed_signers: Path) -> None:
    """Raise unless `allowed_signers` is a regular file that this process can read (ruling R82).

    ssh-keygen would only say that it could not verify, and E-SIG-INVALID tells the reader that the
    file changed after it was signed. A trust anchor that is missing or unreadable would put that
    on every agent, although the fault is in the setup. So the load ends in E-INTERNAL, with the
    name of the error as its detail: FileNotFoundError, PermissionError, NotARegularFile and so on.
    A symlink is followed, as ssh-keygen follows it. The type is looked at before the file is
    opened, because opening a pipe waits for whoever writes to it.
    """
    if not stat.S_ISREG(allowed_signers.stat().st_mode):
        raise NotARegularFile
    with allowed_signers.open("rb"):
        pass


def _answer(callback: Callable[..., object], *args: str | None) -> bool:
    """What `callback(*args)` answers, which has to be `True` or `False` (ruling R83).

    Anything else is not taken for a yes or a no: a string, `None`, a number, a Mock, or the
    coroutine that an `async def` callback gives, which nobody awaits. They would all be read as an
    answer, and most of them as "yes". It is a fault of the caller, so it raises, and the load ends
    in E-INTERNAL. The coroutine is closed first, so that no warning about it leaks out.
    """
    answer = callback(*args)
    if type(answer) is not bool:  # not isinstance: a Mock(spec=bool) says it is a bool
        if inspect.iscoroutine(answer):
            answer.close()
        raise TypeError("a callback must answer True or False")
    return answer


def _version_order(where: str, policy: Policy, active: ActiveVersion | None) -> list[Finding]:
    """E-VERSION-ORDER: older than the active version, or the same version in other bytes.

    Old versions can never come back. A newer version is allowed whatever the gap: that it is the
    previous one + 1 is held in CI (`check_set`), not at load.
    """
    if active is None:
        return []
    older = policy.version < active.version
    other = policy.version == active.version and policy.sha256 != active.sha256
    if not (older or other):
        return []
    params = {"value": str(policy.version), "next": str(active.version + 1)}
    return [Finding("E-VERSION-ORDER", "error", where, params=params)]


def _tools_not_live(
    where: str,
    policy: Policy,
    lines: dict[str, int],
    catalog: Catalog,
    wrapper_live: Callable[[str, str], bool],
) -> list[Finding]:
    """E-TOOL-NOT-LIVE for each tool that passed its own rules and has no live wrapper.

    The caller is asked once for each wrapper, and not at all for a wrapper that is planned.
    """
    asked: dict[str, bool] = {}
    findings = []
    for tool in policy.tools:
        if tool_problem(tool, catalog) is not None:
            continue
        wrapper = catalog.actions[tool].wrapper
        if wrapper not in asked:
            built = catalog.wrapper_status[wrapper] != "planned"
            asked[wrapper] = built and _answer(wrapper_live, wrapper, policy.agent)
        if not asked[wrapper]:
            params = {"tool": tool, "wrapper": WRAPPER_NAMES[wrapper]}
            findings.append(
                Finding("E-TOOL-NOT-LIVE", "error", where, lines.get(tool), params=params)
            )
    return findings


def _folder_not_in_sandbox(
    where: str, policy: Policy, folder_check: Callable[[str, str | None], bool]
) -> list[Finding]:
    """E-SCOPE-NOT-IN-SANDBOX: the policy has a folder ID, and the caller does not vouch for it."""
    folder_id, folder_path = policy.scope.drive_folder_id, policy.scope.drive_folder_path
    if folder_id is None or _answer(folder_check, folder_id, folder_path):
        return []
    params = {"id": folder_id, "path": folder_path or ""}
    return [Finding("E-SCOPE-NOT-IN-SANDBOX", "error", where, params=params)]
