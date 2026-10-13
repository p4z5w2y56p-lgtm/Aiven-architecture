"""Load-time verification (validator-spec 2 and 3.10): `verify`.

`verify` is the gateway's way to load one policy file. It checks the size and the signature before
it decodes or parses any of the file (rulings R43 and R56), and only then validates it
(`validate_policy`, tested in test_validate.py) and makes the checks that are possible at load time.

The tests that need a signature use real ones (tests/support/signing.py). Each makes a throwaway
ed25519 key of its own in its `tmp_path` with `ssh-keygen -t ed25519 -N ""`, signs with it, and
writes the `allowed_signers` file that trusts it, so no key is stored anywhere. They do not skip
when ssh-keygen is missing: they fail, loudly. The tests that look at the call to ssh-keygen stand
in for `subprocess.run`, and sign before they do.

The valid file is the base (`valid_base()`): version 1 of `invoice-reminder`. A clean load has the
Drive and Email wrappers built (`LIVE`), switched on for every agent, and a folder in the sandbox.
The real catalog has every wrapper planned.
"""

import gc
import hashlib
import stat
import subprocess
import tempfile
import warnings
from collections import Counter
from collections.abc import Callable
from pathlib import Path
from typing import NamedTuple
from unittest.mock import Mock

import pytest

from aiven.policy import constants
from aiven.policy import validate as validate_module
from aiven.policy import verify as verify_module
from aiven.policy.constants import MAX_FILE_BYTES, MAX_SCANNED_BYTES
from aiven.policy.findings import Finding, format_line, message
from aiven.policy.validate import Validated, report_order, validate_file
from aiven.policy.verify import ActiveVersion, verify
from tests.support.bodies import policy_of, rerendered
from tests.support.frontmatter import BASE_TEXT, tool_line, without
from tests.support.policies import (
    BASE_PATH,
    FOLDER_ID,
    TEMPLATE_NAME,
    TEMPLATE_PATH,
    line_of,
    padded,
    valid_base,
)
from tests.support.rules import (
    CATALOG,
    CFG,
    UNSETTLED_TOOLS,
    catalog_with,
    setting,
    with_tools,
)
from tests.support.signing import Signer, make_signer
from tests.support.signing import work_in_a_temporary_folder as work_in_a_temporary_folder
from tests.support.spies import CHECKS, spy_on
from tests.support.variants import variant_file

BASE = valid_base()
TEMPLATE = TEMPLATE_PATH.read_bytes()
AGENT = "invoice-reminder"
SANDBOX_PATH = "AIVEN Architecture Sandbox / Invoices"
LIVE = catalog_with(drive="built", email="built")

# The tools of the base, and how a finding shows the wrapper of each.
BASE_TOOLS = {"sheets.read": "Drive", "gmail.draft": "Email", "gmail.send": "Email"}

INVALID = Finding("E-SIG-INVALID", "error", str(BASE_PATH))
OTHER_HASH = "sha256:" + "a" * 64


# --- the signers of the tests (tests/support/signing.py makes them)


@pytest.fixture
def signer(tmp_path) -> Signer:
    """The signer of the tests: the key of "matthijs", trusted for the policy namespace only."""
    return make_signer(tmp_path / "matthijs")


@pytest.fixture
def stand_in(tmp_path) -> Signer:
    """A signer for the tests that stand in for ssh-keygen: no key, and a file of allowed signers
    that exists (verify checks that) and that nobody reads."""
    allowed = tmp_path / "allowed_signers"
    allowed.write_text("nothing that ssh-keygen reads\n")
    return Signer(tmp_path / "key", allowed)


# --- calling verify


def all_live(wrapper: str, agent: str) -> bool:
    return True


def in_sandbox(folder_id: str, path: str | None) -> bool:
    return True


def verify_with(
    signer: Signer,
    data: bytes,
    sig: bytes | None,
    *,
    path: Path = BASE_PATH,
    active=None,
    wrapper_live: Callable[[str, str], bool] = all_live,
    folder_check: Callable[[str, str | None], bool] = in_sandbox,
    catalog=LIVE,
):
    """`verify` with the trust anchor of `signer`, and the defaults of a clean load."""
    anchor = signer.allowed_signers
    return verify(path, data, sig, anchor, active, wrapper_live, folder_check, CFG, catalog)


def load(signer: Signer, data: bytes, **options):
    """`verify` for the file `data` as `signer` signs it."""
    return verify_with(signer, data, signer.sign(data), **options)


def shape(findings):
    return [(found.code, found.line, found.params) for found in findings]


def shown(findings) -> str:
    """Every way the findings are shown: the line, both languages, the params and the repr."""
    return "\n".join(
        f"{format_line(f)}\n{message(f, 'en')}\n{message(f, 'nl')}\n{f.params}\n{f!r}"
        for f in findings
    )


def not_live(*tools: str) -> list[tuple[str, int, dict[str, str]]]:
    """The `shape` of E-TOOL-NOT-LIVE for tools of the base, on their lines in the base."""
    return [
        ("E-TOOL-NOT-LIVE", tool_line(BASE_TEXT, tool), {"tool": tool, "wrapper": BASE_TOOLS[tool]})
        for tool in tools
    ]


# --- standing in for ssh-keygen


class Call(NamedTuple):
    """One call of the stand-in for subprocess.run, as it was made."""

    args: tuple
    kwargs: dict
    sig: bytes  # what the signature file held during the call
    folder_mode: int  # the permission bits of the folder that held it

    @property
    def argv(self) -> list[str]:
        return self.args[0]

    @property
    def sig_path(self) -> Path:
        return Path(self.argv[-1])


def stub_run(monkeypatch, *, returncode=0, stdout=b"", stderr=b"", error=None) -> list[Call]:
    """Stand in for subprocess.run: record each call, then answer it (or raise `error`).

    The signature file is read during the call, while it is there. Sign before you stub: the
    signing helpers use subprocess.run too.
    """
    calls: list[Call] = []

    def run(*args, **kwargs):
        sig_file = Path(args[0][-1])
        mode = stat.S_IMODE(sig_file.parent.stat().st_mode)
        calls.append(Call(args, kwargs, sig_file.read_bytes(), mode))
        if error is not None:
            raise error
        return subprocess.CompletedProcess(args[0], returncode, stdout, stderr)

    monkeypatch.setattr(subprocess, "run", run)
    return calls


def test_the_tests_of_this_module_run_in_a_folder_of_their_own(tmp_path):
    # The fixture of tests/support/signing.py, imported above: it looks unused, and it is not.
    assert tmp_path in Path.cwd().parents


# --- the size comes first (ruling R56, step 1)


@pytest.mark.parametrize("signed", [True, False], ids=["signed", "unsigned"])
@pytest.mark.parametrize("size", [MAX_FILE_BYTES + 1, MAX_SCANNED_BYTES + 1])
def test_a_file_over_64_kib_gets_e_file_size_and_nothing_else(signer, size, signed):
    data = padded(size)
    sig = signer.sign(data) if signed else None  # a valid signature does not save it
    assert verify_with(signer, data, sig) == (
        None,
        [Finding("E-FILE-SIZE", "error", str(BASE_PATH), params={"size": str(size)})],
    )


def test_a_file_of_exactly_64_kib_is_not_too_large(signer):
    policy, findings = load(signer, padded(MAX_FILE_BYTES))
    assert (policy is not None, findings) == (True, [])


# --- no signature (ruling R56, step 2)


def test_missing_sig(signer):
    assert verify_with(signer, BASE, None) == (
        None,
        [Finding("E-SIG-MISSING", "error", str(BASE_PATH), params={"agent": AGENT})],
    )


def test_the_template_is_not_signed_and_does_not_load(signer):
    result = verify_with(signer, TEMPLATE, None, path=TEMPLATE_NAME)
    assert result == (
        None,
        [
            Finding(
                "E-SIG-MISSING", "error", str(TEMPLATE_NAME), params={"agent": "policy-template"}
            )
        ],
    )


@pytest.mark.parametrize(
    "name, agent", [("a.md", "a"), ("invoice-reminder.md", AGENT), ("notes.txt", "notes.txt")]
)
def test_the_agent_of_e_sig_missing_is_the_file_name_without_md(signer, name, agent):
    _, findings = verify_with(signer, BASE, None, path=Path("policies") / name)
    assert shape(findings) == [("E-SIG-MISSING", None, {"agent": agent})]


# --- the signature (ruling R56, step 3)


def test_valid_signature_loads(signer):
    policy, findings = load(signer, BASE)
    assert findings == []
    assert policy == policy_of(BASE)
    assert policy.sha256 == "sha256:" + hashlib.sha256(BASE).hexdigest()


def test_one_byte_change_fails(signer):
    sig = signer.sign(BASE)
    changed = BASE.replace(b"Once a day", b"once a day", 1)  # the one byte of a capital
    assert sum(a != b for a, b in zip(BASE, changed, strict=True)) == 1
    # By itself the changed file is a valid policy: the signature is the one reason it is refused.
    assert not [f for f in validate_file(BASE_PATH, changed, CFG, LIVE) if f.severity == "error"]
    assert verify_with(signer, changed, sig) == (None, [INVALID])


@pytest.mark.parametrize(
    "change",
    [
        lambda data: data + b"\n",
        lambda data: data[:-1],
        lambda data: data[1:],
        lambda data: data.replace(b"\n", b"\r\n", 1),
        lambda data: data.replace(b"version: 1", b"version: 2", 1),
        lambda data: data.replace(b"Once a", b"Onc ea", 1),
    ],
    ids=["added", "dropped end", "dropped start", "carriage return", "version", "swapped"],
)
def test_any_change_to_the_bytes_fails(signer, change):
    sig = signer.sign(BASE)
    assert verify_with(signer, change(BASE), sig) == (None, [INVALID])


def test_git_namespace_signature_fails(tmp_path):
    anywhere = make_signer(tmp_path / "anywhere", namespaces=None)  # trusted for every namespace
    assert load(anywhere, BASE)[1] == []  # its signature in the policy namespace loads
    git = anywhere.sign(BASE, namespace="git")  # the signature that a commit has
    assert verify_with(anywhere, BASE, git) == (None, [INVALID])


def test_a_signature_of_another_key_fails(signer, tmp_path):
    stranger = make_signer(tmp_path / "stranger")
    assert verify_with(signer, BASE, stranger.sign(BASE)) == (None, [INVALID])


def test_a_signer_who_is_trusted_for_other_namespaces_only_fails(tmp_path):
    git_only = make_signer(tmp_path / "git-only", namespaces="git")
    assert load(git_only, BASE) == (None, [INVALID])


def test_only_the_signer_matthijs_counts(tmp_path):
    someone = make_signer(tmp_path / "someone", name="someone")
    assert load(someone, BASE) == (None, [INVALID])


@pytest.mark.parametrize(
    "garbage",
    [b"", b"not a signature\n", b"-----BEGIN SSH SIGNATURE-----\n-----END SSH SIGNATURE-----\n"],
    ids=["empty", "text", "armor without content"],
)
def test_a_signature_that_is_not_one_fails(signer, garbage):
    assert verify_with(signer, BASE, garbage) == (None, [INVALID])


def test_a_truncated_signature_fails(signer):
    sig = signer.sign(BASE)
    assert verify_with(signer, BASE, sig[: len(sig) // 2]) == (None, [INVALID])


def test_nothing_that_ssh_keygen_says_is_in_the_finding(signer):
    _, findings = verify_with(signer, BASE, b"not a signature\n")
    assert findings == [INVALID]
    for words in ("Could not verify", "incorrect signature", "missing header", "sshsig"):
        assert words not in shown(findings)


# --- the trust anchor (ruling R82)
#
# E-SIG-INVALID tells the reader that the file changed after it was signed. A missing or unreadable
# file of allowed signers would put that on every agent, although the fault is in the setup: it is
# E-INTERNAL, with the name of the error, and ssh-keygen is not run.


def below_a_file(tmp_path: Path) -> Path:
    (tmp_path / "a-file").write_text("x")
    return tmp_path / "a-file" / "allowed_signers"


UNUSABLE_ANCHORS = {
    "missing": (lambda tmp_path: tmp_path / "nowhere", "FileNotFoundError"),
    "below a file": (below_a_file, "NotADirectoryError"),
    "a folder": (lambda tmp_path: tmp_path, "NotARegularFile"),
}


@pytest.mark.parametrize("name", UNUSABLE_ANCHORS)
def test_a_trust_anchor_that_cannot_be_used_is_e_internal_and_ssh_keygen_is_not_run(
    signer, tmp_path, monkeypatch, name
):
    make_path, detail = UNUSABLE_ANCHORS[name]
    sig = signer.sign(BASE)
    calls = stub_run(monkeypatch)
    made = spy_on(monkeypatch, tempfile, ["TemporaryDirectory"])
    result = verify_with(Signer(signer.key, make_path(tmp_path)), BASE, sig)
    assert result == (None, [internal(detail)])
    assert calls == [] and sum(made.values()) == 0  # not run, and nothing written for it
    assert str(tmp_path) not in shown(
        result[1]
    )  # where the trust anchor is stays out of the finding


def test_an_unreadable_file_of_allowed_signers_is_e_internal(signer, monkeypatch):
    # A process that runs as root can read any file, so a chmod would prove nothing here (CI does
    # not run as root, and this container does). The refusal of the system is stood in for.
    sig = signer.sign(BASE)
    real_open = Path.open

    def refuse(self, *args, **kwargs):
        if self == signer.allowed_signers:
            raise PermissionError(LEAK)
        return real_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", refuse)
    calls = stub_run(monkeypatch)
    made = spy_on(monkeypatch, tempfile, ["TemporaryDirectory"])
    result = verify_with(signer, BASE, sig)
    assert result == (None, [internal("PermissionError")])
    assert calls == [] and sum(made.values()) == 0
    assert "LEAK" not in shown(result[1])


def test_a_file_of_allowed_signers_that_is_a_symlink_is_followed(signer, tmp_path):
    # A mounted secret or config file is often one. ssh-keygen follows it, and so does the check.
    link = tmp_path / "allowed_signers_link"
    link.symlink_to(signer.allowed_signers)
    policy, findings = load(Signer(signer.key, link), BASE)
    assert (policy is not None, findings) == (True, [])


def test_a_file_of_allowed_signers_that_trusts_nobody_is_still_e_sig_invalid(signer, tmp_path):
    # That is a signature that does not verify. Only a file that cannot be used is E-INTERNAL.
    empty = tmp_path / "empty_allowed_signers"
    empty.write_text("")
    assert verify_with(Signer(signer.key, empty), BASE, signer.sign(BASE)) == (None, [INVALID])


# --- the signature is small (ruling R80)

SIG_CAP = 16 * 1024  # a real SSHSIG file is under 1 KiB


def test_the_signature_cap_is_16_kib():
    assert constants.MAX_SIG_BYTES == SIG_CAP


def test_a_signature_over_16_kib_is_refused_before_anything_is_written(monkeypatch, stand_in):
    calls = stub_run(monkeypatch)
    made = spy_on(monkeypatch, tempfile, ["TemporaryDirectory"])
    assert verify_with(stand_in, BASE, b"x" * (SIG_CAP + 1)) == (None, [INVALID])
    assert calls == []  # ssh-keygen was not run
    assert sum(made.values()) == 0  # and no folder was made for the signature


def test_a_signature_of_exactly_16_kib_still_goes_to_ssh_keygen(monkeypatch, stand_in):
    calls = stub_run(monkeypatch)
    verify_with(stand_in, BASE, b"x" * SIG_CAP)
    assert [call.sig for call in calls] == [b"x" * SIG_CAP]


def test_a_genuine_signature_padded_past_16_kib_is_refused(signer):
    # OpenSSH ignores blank lines after a signature, so a genuine one can be made as large as
    # you like. Without the cap, a megabyte of them would be written out and handed to ssh-keygen.
    sig = signer.sign(BASE)
    at_the_cap = sig + b"\n" * (SIG_CAP - len(sig))
    assert verify_with(signer, BASE, at_the_cap) == (policy_of(BASE), [])
    assert verify_with(signer, BASE, at_the_cap + b"\n") == (None, [INVALID])
    assert verify_with(signer, BASE, sig + b"\n" * 1_000_000) == (None, [INVALID])


# --- the call to ssh-keygen


def test_ssh_keygen_gets_exactly_these_arguments(monkeypatch, stand_in):
    calls = stub_run(monkeypatch)
    verify_with(stand_in, BASE, b"sig")
    (call,) = calls
    assert len(call.args) == 1  # the one list
    assert call.argv[:-1] == [
        "ssh-keygen",
        "-Y",
        "verify",
        "-f",
        str(stand_in.allowed_signers),
        "-I",
        "matthijs",
        "-n",
        "aiven-policy-v1",
        "-s",
    ]
    assert call.kwargs == {"input": BASE, "capture_output": True, "timeout": 10, "check": False}


@pytest.mark.parametrize(
    "returncode, valid", [(0, True), (1, False), (2, False), (255, False), (-9, False)]
)
def test_an_exit_status_of_zero_is_a_valid_signature_and_anything_else_is_not(
    monkeypatch, stand_in, returncode, valid
):
    stub_run(monkeypatch, returncode=returncode)
    policy, findings = verify_with(stand_in, BASE, b"sig")
    assert (policy is not None, [found.code for found in findings]) == (
        valid,
        [] if valid else ["E-SIG-INVALID"],
    )


def test_nothing_of_the_file_reaches_the_arguments(monkeypatch, stand_in):
    hostile = b"; touch hacked\n-O verify-time=1\n$(id) `id` -f /etc/passwd\n" + BASE
    odd_name = Path("policies/-n git; touch hacked $(id).md")
    calls = stub_run(monkeypatch)
    verify_with(stand_in, BASE, b"sig")
    verify_with(stand_in, hostile, b"sig", path=odd_name)
    plain, other = calls
    assert other.argv[:-1] == plain.argv[:-1]
    assert other.kwargs["input"] == hostile  # the file goes in on stdin, and only there


def test_the_signature_is_in_a_private_folder_of_its_own_that_is_gone_afterwards(
    monkeypatch, stand_in
):
    calls = stub_run(monkeypatch)
    for _ in range(2):
        verify_with(stand_in, BASE, b"the signature")
    first, second = calls
    assert first.sig == second.sig == b"the signature"
    assert first.folder_mode == second.folder_mode == 0o700
    assert first.sig_path.parent != second.sig_path.parent
    assert not first.sig_path.parent.exists()
    assert not second.sig_path.parent.exists()


def test_the_output_of_ssh_keygen_never_reaches_a_finding(monkeypatch, stand_in):
    leak = b"LEAK-0123456789"
    stub_run(monkeypatch, returncode=255, stdout=leak, stderr=leak)
    result = verify_with(stand_in, BASE, b"sig")
    assert result == (None, [INVALID])
    assert "LEAK" not in shown(result[1])


# --- nothing is parsed before the signature holds (rulings R43 and R56)


def _unsigned(tmp_path):
    return make_signer(tmp_path / "k"), BASE, None, "E-SIG-MISSING"


def _changed(tmp_path):
    signer = make_signer(tmp_path / "k")
    return signer, BASE.replace(b"Once a day", b"once a day", 1), signer.sign(BASE), "E-SIG-INVALID"


def _git(tmp_path):
    signer = make_signer(tmp_path / "k", namespaces=None)
    return signer, BASE, signer.sign(BASE, namespace="git"), "E-SIG-INVALID"


def _stranger(tmp_path):
    signer = make_signer(tmp_path / "k")
    return signer, BASE, make_signer(tmp_path / "other").sign(BASE), "E-SIG-INVALID"


def _garbage(tmp_path):
    return make_signer(tmp_path / "k"), BASE, b"not a signature\n", "E-SIG-INVALID"


def _too_large_signed(tmp_path):
    signer, data = make_signer(tmp_path / "k"), padded(MAX_FILE_BYTES + 1)
    return signer, data, signer.sign(data), "E-FILE-SIZE"


def _too_large_unsigned(tmp_path):
    return make_signer(tmp_path / "k"), padded(MAX_SCANNED_BYTES + 1), None, "E-FILE-SIZE"


NOT_PARSED = {
    "no signature": _unsigned,
    "a changed byte": _changed,
    "a signature of the git namespace": _git,
    "a signature of another key": _stranger,
    "a signature that is garbage": _garbage,
    "a signed file that is too large": _too_large_signed,
    "an unsigned file that is too large": _too_large_unsigned,
}


@pytest.mark.parametrize("name", NOT_PARSED)
def test_a_file_is_not_parsed_before_its_signature_holds(monkeypatch, tmp_path, name):
    signer, data, sig, code = NOT_PARSED[name](tmp_path)
    calls = spy_on(monkeypatch, validate_module, CHECKS)
    spy_on(monkeypatch, verify_module, ["validate_policy"], calls)
    policy, findings = verify_with(signer, data, sig)
    assert (policy, [found.code for found in findings]) == (None, [code])
    assert sum(calls.values()) == 0  # not one check, not even a decoding of the bytes


def test_a_signed_file_is_validated_once_and_every_check_runs_once(signer, monkeypatch):
    sig = signer.sign(BASE)
    calls = spy_on(monkeypatch, validate_module, CHECKS)
    spy_on(monkeypatch, verify_module, ["validate_policy"], calls)
    assert verify_with(signer, BASE, sig)[0] is not None
    assert calls == Counter(dict.fromkeys(CHECKS, 1)) + Counter(validate_policy=1)


# --- the file is validated once the signature holds (ruling R56, steps 4 and 6)


def test_a_signed_file_with_errors_does_not_load(signer):
    # The template has errors of its own (its placeholders, and the name of its file).
    policy, findings = load(signer, TEMPLATE, path=TEMPLATE_NAME)
    assert policy is None
    assert findings == validate_file(TEMPLATE_NAME, TEMPLATE, CFG, LIVE)
    assert {found.code for found in findings} == {"E-FILENAME", "E-PLACEHOLDER"}


def test_a_warning_does_not_stop_a_load(signer):
    data = variant_file(setting("shadow.min_runs", 5), render=True)
    policy, findings = load(signer, data)
    assert policy == policy_of(data)
    assert [(found.code, found.severity) for found in findings] == [("W-SHADOW-LOW", "warning")]


def test_a_signed_file_that_gives_no_policy_gets_no_load_checks(signer):
    asked = []
    data = BASE.replace(b"max_class: R2", b"max_class: [")  # the front matter does not parse
    policy, findings = load(
        signer,
        data,
        active=ActiveVersion(3, OTHER_HASH),
        wrapper_live=lambda *args: asked.append(args) or False,
        folder_check=lambda *args: asked.append(args) or False,
    )
    assert (policy, asked) == (None, [])
    assert findings == validate_file(BASE_PATH, data, CFG, LIVE)
    assert {found.code for found in findings} == {"E-YAML"}


# --- the version against the active one (3.10)


def version_file(version: int) -> bytes:
    """The base as the given version, with its generated sections rendered again."""
    return variant_file(setting("version", version), render=True)


def version_order(value: int, next_version: int) -> Finding:
    params = {"value": str(value), "next": str(next_version)}
    return Finding("E-VERSION-ORDER", "error", str(BASE_PATH), params=params)


def test_older_version_refused(signer):
    result = load(signer, version_file(2), active=ActiveVersion(3, OTHER_HASH))
    assert result == (None, [version_order(2, 4)])


def test_same_version_other_hash_refused(signer):
    result = load(signer, version_file(3), active=ActiveVersion(3, OTHER_HASH))
    assert result == (None, [version_order(3, 4)])


def test_the_active_version_itself_loads_again(signer):
    data = version_file(3)
    policy, findings = load(signer, data, active=ActiveVersion(3, policy_of(data).sha256))
    assert (policy == policy_of(data), findings) == (True, [])


@pytest.mark.parametrize("version", [4, 5, 9999])
def test_a_newer_version_loads_whatever_the_gap(signer, version):
    # CI holds a version to the previous one + 1. At load only the order counts.
    data = version_file(version)
    policy, findings = load(signer, data, active=ActiveVersion(3, OTHER_HASH))
    assert (policy == policy_of(data), findings) == (True, [])


def test_with_no_active_version_any_version_loads(signer):
    data = version_file(7)
    policy, findings = load(signer, data, active=None)
    assert (policy == policy_of(data), findings) == (True, [])


# --- ActiveVersion takes the hash the way a Policy writes it (review M4)
#
# A hash in another form would make "the same version in other bytes" true of every reload of the
# active file, and nothing would load. That is a bug of the caller, so it fails where it is made.


def test_active_version_takes_the_hash_of_a_policy():
    policy = policy_of(BASE)
    assert ActiveVersion(1, policy.sha256) == ActiveVersion(1, policy.sha256)
    assert ActiveVersion(3, "sha256:" + "0123456789abcdef" * 4).version == 3


BAD_HASHES = {
    "empty": "",
    "no digest": "sha256:",
    "63 digits": "sha256:" + "a" * 63,
    "65 digits": "sha256:" + "a" * 65,
    "upper case digits": "sha256:" + "A" * 64,
    "upper case name": "SHA256:" + "a" * 64,
    "another algorithm": "sha1:" + "a" * 64,
    "no name": "a" * 64,
    "space before": " sha256:" + "a" * 64,
    "space after": "sha256:" + "a" * 64 + " ",
    "newline after": "sha256:" + "a" * 64 + "\n",
    "not hex": "sha256:" + "g" * 64,
    "a hyphen": "sha256:" + "a" * 63 + "-",
    "digits that are not ASCII": "sha256:" + "\u0661" * 64,  # what a \d would take for digits
}


@pytest.mark.parametrize("name", BAD_HASHES)
def test_active_version_refuses_a_hash_in_another_form(name):
    with pytest.raises(ValueError):
        ActiveVersion(3, BAD_HASHES[name])


@pytest.mark.parametrize(
    "sha256",
    [None, 5, b"sha256:" + b"a" * 64, ["sha256:" + "a" * 64]],
    ids=["None", "a number", "bytes", "a list"],
)
def test_active_version_refuses_a_hash_that_is_not_a_string(sha256):
    with pytest.raises(ValueError):
        ActiveVersion(3, sha256)


# --- the wrappers (3.10, E-TOOL-NOT-LIVE)


def test_wrapper_not_live_for_agent(signer):
    policy, findings = load(signer, BASE, wrapper_live=lambda wrapper, agent: wrapper != "email")
    assert policy is None
    assert shape(findings) == not_live("gmail.draft", "gmail.send")
    assert all(f.severity == "error" and f.path == str(BASE_PATH) for f in findings)


def test_a_wrapper_that_is_off_for_the_agent_is_not_live_whichever_it_is(signer):
    _, findings = load(signer, BASE, wrapper_live=lambda wrapper, agent: False)
    assert shape(findings) == not_live("sheets.read", "gmail.draft", "gmail.send")


def test_wrapper_live_is_asked_once_for_each_wrapper_with_the_agent(signer):
    asked = []
    load(signer, BASE, wrapper_live=lambda wrapper, agent: asked.append((wrapper, agent)) or True)
    assert asked == [("drive", AGENT), ("email", AGENT)]


def test_a_planned_wrapper_is_not_live_whatever_wrapper_live_says(signer):
    asked = []
    policy, findings = load(
        signer, BASE, catalog=CATALOG, wrapper_live=lambda *args: asked.append(args) or True
    )
    assert policy is None
    assert shape(findings) == not_live("sheets.read", "gmail.draft", "gmail.send")
    assert asked == []  # the wrapper is not built: nobody has switched it on for anybody


def test_at_load_w_tool_not_live_becomes_e_tool_not_live_and_both_never_appear(signer):
    warned = validate_file(BASE_PATH, BASE, CFG, CATALOG)
    assert [found.code for found in warned] == ["W-TOOL-NOT-LIVE"] * 3  # the validator warns
    _, findings = load(signer, BASE, catalog=CATALOG)
    assert [found.code for found in findings] == ["E-TOOL-NOT-LIVE"] * 3
    assert [found.line for found in findings] == [found.line for found in warned]


def test_w_tool_not_live_never_comes_out_of_verify_even_without_a_policy(signer):
    data = variant_file(without("shadow.min_runs"))  # a field is missing: no policy
    warned = validate_file(BASE_PATH, data, CFG, CATALOG)
    assert [found.code for found in warned].count("W-TOOL-NOT-LIVE") == 3
    policy, findings = load(signer, data, catalog=CATALOG)
    assert policy is None
    assert [found.code for found in findings] == ["E-FIELD-MISSING"]


@pytest.mark.parametrize("name", UNSETTLED_TOOLS)
def test_a_tool_that_failed_its_own_checks_is_not_judged_for_its_wrapper(signer, name):
    tools = UNSETTLED_TOOLS[name]
    data = variant_file(with_tools(*tools))
    _, findings = load(signer, data, wrapper_live=lambda wrapper, agent: False)
    judged = [(f.params["tool"], f.line) for f in findings if f.code == "E-TOOL-NOT-LIVE"]
    # sheets.read is the one tool in these lists that passes its own checks.
    expected = [(tool, tool_line(data.decode(), tool)) for tool in tools if tool == "sheets.read"]
    assert judged == expected


def test_a_tool_that_breaks_another_rule_is_still_judged_for_its_wrapper(signer):
    data = variant_file(setting("max_class", "R0"))  # gmail.draft is R1 and gmail.send is R2
    _, findings = load(signer, data, wrapper_live=lambda wrapper, agent: False)
    assert [found.code for found in findings].count("E-TOOL-ABOVE-MAX-CLASS") == 2
    judged = [f.params["tool"] for f in findings if f.code == "E-TOOL-NOT-LIVE"]
    assert judged == ["sheets.read", "gmail.draft", "gmail.send"]


def test_a_wrapper_is_shown_by_its_display_name(signer):
    data = variant_file(with_tools("sheets.read", "gmail.draft", "gmail.send", "agentbuilder.read"))
    _, findings = load(signer, data)  # the Agent Builder wrapper is planned, even in LIVE
    wrappers = {
        f.params["tool"]: f.params["wrapper"] for f in findings if f.code == "E-TOOL-NOT-LIVE"
    }
    assert wrappers == {"agentbuilder.read": "Agent Builder"}


# --- the folder (3.10, E-SCOPE-NOT-IN-SANDBOX)


def email_only(*, with_folder_id: bool = False) -> bytes:
    """A valid file for an agent with no Drive tool, so no bullet for it and no folder path.

    With `with_folder_id` it keeps its folder ID. The validator warns about that (W-SCOPE-UNUSED).
    """
    unused = ["scope.drive_folder_path"]
    if not with_folder_id:
        unused.append("scope.drive_folder_id")
    data = variant_file(with_tools("gmail.draft", "gmail.send"), without(*unused)).decode()
    bullet = next(row for row in data.split("\n") if row.startswith("- `sheets.read`:"))
    return rerendered(data.replace(bullet + "\n", "").encode())


def test_folder_outside_sandbox(signer):
    asked = []

    def elsewhere(folder_id, path):
        asked.append((folder_id, path))
        return False

    policy, findings = load(signer, BASE, folder_check=elsewhere)
    assert policy is None
    assert findings == [
        Finding(
            "E-SCOPE-NOT-IN-SANDBOX",
            "error",
            str(BASE_PATH),
            params={"id": FOLDER_ID, "path": SANDBOX_PATH},
        )
    ]
    assert asked == [(FOLDER_ID, SANDBOX_PATH)]  # the folder, and the path the policy says it has


def test_a_folder_in_the_sandbox_loads(signer):
    asked = []
    policy, findings = load(signer, BASE, folder_check=lambda *args: asked.append(args) or True)
    assert (policy is not None, findings, asked) == (True, [], [(FOLDER_ID, SANDBOX_PATH)])


def test_there_is_no_folder_check_without_a_folder_id(signer):
    asked = []
    data = email_only()
    policy, findings = load(signer, data, folder_check=lambda *args: asked.append(args) or False)
    assert (policy is not None, findings, asked) == (True, [], [])


def test_a_folder_id_without_a_path_is_checked_with_none(signer):
    asked = []
    data = email_only(with_folder_id=True)
    policy, findings = load(signer, data, folder_check=lambda *args: asked.append(args) or False)
    assert asked == [(FOLDER_ID, None)]
    assert policy is None
    assert shape([f for f in findings if f.code == "E-SCOPE-NOT-IN-SANDBOX"]) == [
        ("E-SCOPE-NOT-IN-SANDBOX", None, {"id": FOLDER_ID, "path": ""})
    ]


# --- all of it together


def test_the_findings_of_the_file_and_of_the_load_come_in_one_sorted_list(signer):
    data = variant_file(setting("shadow.min_runs", 5), setting("version", 2), render=True)
    text = data.decode()
    policy, findings = load(
        signer,
        data,
        active=ActiveVersion(3, OTHER_HASH),
        wrapper_live=lambda wrapper, agent: wrapper != "email",
        folder_check=lambda folder_id, path: False,
    )
    assert policy is None
    assert [(found.code, found.line) for found in findings] == [
        ("E-SCOPE-NOT-IN-SANDBOX", None),
        ("E-VERSION-ORDER", None),
        ("E-TOOL-NOT-LIVE", tool_line(text, "gmail.draft")),
        ("E-TOOL-NOT-LIVE", tool_line(text, "gmail.send")),
        ("W-SHADOW-LOW", line_of(text, "min_runs: 5")),
    ]
    assert findings == sorted(findings, key=report_order)


# --- anything that goes wrong fails closed (ruling R56, E-INTERNAL)

LEAK = "LEAK: a line of the file and the words of an exception"


def internal(detail: str) -> Finding:
    return Finding("E-INTERNAL", "error", str(BASE_PATH), params={"detail": detail})


def raises(error: BaseException):
    def callback(*args):
        raise error

    return callback


def test_a_missing_ssh_keygen_gives_e_internal(signer, tmp_path, monkeypatch):
    sig = signer.sign(BASE)
    nothing_to_run = tmp_path / "no-programs"
    nothing_to_run.mkdir()
    monkeypatch.setenv("PATH", str(nothing_to_run))  # a real FileNotFoundError, not a stand-in
    assert verify_with(signer, BASE, sig) == (None, [internal("FileNotFoundError")])


def test_a_timeout_gives_e_internal_and_the_signature_folder_is_removed(monkeypatch, stand_in):
    calls = stub_run(monkeypatch, error=subprocess.TimeoutExpired("ssh-keygen", 10, output=LEAK))
    assert verify_with(stand_in, BASE, b"sig") == (None, [internal("TimeoutExpired")])
    assert not calls[0].sig_path.parent.exists()


@pytest.mark.parametrize(
    "error",
    [PermissionError(LEAK), OSError(LEAK), subprocess.SubprocessError(LEAK)],
    ids=["PermissionError", "OSError", "SubprocessError"],
)
def test_any_failure_to_run_ssh_keygen_gives_e_internal_with_the_class_name_only(
    monkeypatch, stand_in, error
):
    stub_run(monkeypatch, error=error)
    policy, findings = verify_with(stand_in, BASE, b"sig")
    assert (policy, findings) == (None, [internal(type(error).__name__)])
    assert "LEAK" not in shown(findings)
    assert type(error).__name__ in message(findings[0], "en")


@pytest.mark.parametrize("which", ["wrapper_live", "folder_check"])
def test_a_callback_that_raises_gives_e_internal_and_nothing_else(signer, which):
    # The file is older than the active version, so there is a finding to be dropped.
    options = {which: raises(RuntimeError(LEAK))}
    result = load(signer, version_file(2), active=ActiveVersion(3, OTHER_HASH), **options)
    assert result == (None, [internal("RuntimeError")])
    assert "LEAK" not in shown(result[1])


def test_a_crash_in_the_checks_gives_e_internal_with_the_class_name_only(signer, monkeypatch):
    sig = signer.sign(BASE)
    monkeypatch.setattr(verify_module, "validate_policy", raises(KeyError(LEAK)))
    result = verify_with(signer, BASE, sig)
    assert result == (None, [internal("KeyError")])
    assert "LEAK" not in shown(result[1])


@pytest.mark.parametrize("which", ["wrapper_live", "folder_check"])
def test_an_interrupt_is_not_swallowed(signer, which):
    with pytest.raises(KeyboardInterrupt):
        load(signer, BASE, **{which: raises(KeyboardInterrupt())})


# --- no policy and no error cannot be (review M5)
#
# validate_policy gives a policy unless something is wrong, and what is wrong is an error. If it
# ever gave neither, `(None, [])` or `(None, [a warning])` would read as "nothing to load, and
# nothing wrong".


ERROR = Finding("E-FIELD-MISSING", "error", str(BASE_PATH), params={"field": "shadow"})
WARNING = Finding("W-SHADOW-LOW", "warning", str(BASE_PATH), 28, params={"value": "5"})


def validates_as(monkeypatch, validated: Validated) -> None:
    """Make verify get this result from validate_policy, whatever the file is."""
    monkeypatch.setattr(verify_module, "validate_policy", lambda *args: validated)


@pytest.mark.parametrize("findings", [[], [WARNING]], ids=["no finding", "only a warning"])
def test_no_policy_and_no_error_is_e_internal(signer, monkeypatch, findings):
    sig = signer.sign(BASE)
    validates_as(monkeypatch, Validated(None, findings, {}))
    assert verify_with(signer, BASE, sig) == (None, [internal("NoPolicy")])


def test_no_policy_with_an_error_is_that_error_and_nothing_more(signer, monkeypatch):
    sig = signer.sign(BASE)
    validates_as(monkeypatch, Validated(None, [ERROR, WARNING], {}))
    assert verify_with(signer, BASE, sig) == (None, [ERROR, WARNING])


def test_a_policy_and_no_error_still_loads(signer, monkeypatch):
    sig = signer.sign(BASE)
    validates_as(monkeypatch, Validated(policy_of(BASE), [WARNING], {}))
    assert verify_with(signer, BASE, sig) == (policy_of(BASE), [WARNING])


# --- a callback must answer True or False (ruling R83)


async def answers_in_a_coroutine(*args):
    """A callback written as `async def`: calling it gives a coroutine, and nobody awaits that."""
    return True


NOT_A_BOOL = {
    "a string that says false": lambda *args: "false",
    "None": lambda *args: None,
    "zero": lambda *args: 0,
    "one": lambda *args: 1,
    "a dict": lambda *args: {"live": False},
    "a Mock": lambda *args: Mock(),
    "a Mock that says it is a bool": lambda *args: Mock(spec=bool),
    "a coroutine of an async def": answers_in_a_coroutine,
}


@pytest.mark.parametrize("which", ["wrapper_live", "folder_check"])
@pytest.mark.parametrize("name", NOT_A_BOOL)
def test_a_callback_that_does_not_answer_true_or_false_gives_e_internal(signer, which, name):
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        result = load(signer, BASE, **{which: NOT_A_BOOL[name]})
        gc.collect()  # a coroutine that was never awaited warns when it is collected
    assert result == (None, [internal("TypeError")])
    assert [str(warning.message) for warning in caught] == []
