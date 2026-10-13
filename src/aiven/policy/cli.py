"""The `aiven-policy` command line (validator-spec section 1): `validate`, `render` and `verify`.

This is where the checks meet a person, a script or CI. It reads the files, the platform values and
the catalog, runs what the other modules give, and decides what is printed and what the exit code
is. Every command takes `--config`, `--catalog` and `--debug`.

`validate <file>... [--json] [--previous-ref REF]` runs every check on each file (`validate_policy`),
the checks across the files that built a policy (`check_duplicates`, given the files sorted by
path), and the version order and the widening of each of those files whose history is known
(`check_history`, ruling R91). The output is file by file in the order of the arguments, a file
named twice counting once, in whatever spelling (with `..`, by a link). A file's own findings come
in the order of `validate_file`, and the findings across the files are in with those of the file
they are about. With `--previous-ref` the previous version of a file is the file as it is at that
Git ref (`git -C FOLDER show REF:path`, run without a shell, in the folder of the file: the command
can be run from anywhere). A file that is not there is a new agent, and must be version 1. The
previous files are loaded and built and nothing is said of them. A file whose history is not known
has no version order and no widening, and is no new agent: `check_history` is not called for it.
That is every file without a ref (one note on stderr), and a file whose previous version gives no
policy (a note on stderr for each; the gateway still refuses a lower version at load). `--json`
prints one document, `{"findings": [...]}`, with the column, the parameters and the text in both
languages (section 1).

`render <file>` rewrites the two generated sections, when the front matter loads and builds a policy
without an error (ruling R29). A finding of the file, the body or the content does not stop it
(`FILE_AND_BODY_CODES`): a template has them on its way to being a policy (section 9). Otherwise the
file is not touched, the exit code is 1, and the findings of the front matter are printed, or all
findings when the front matter has no error (see `_render`). The sections are written all at once
(`_replace_file`).

`verify <file> --sig S --allowed-signers P [--active-version N --active-sha256 H]` is the check
before an upload. Whether a wrapper is switched on for the agent and whether the folder is in the
Sandbox drive only the gateway knows (section 8), so here a wrapper is live unless the catalog says
it is planned and the folder check passes. A note on stderr says so.

The platform values are `--config`, else `$AIVEN_POLICY_CONFIG`, else `config/platform.yaml`, else
`config/platform.example.yaml` with a note on stderr (ruling R61). The example names another agents
project than a real policy does, so a real policy fails E-PRINCIPAL against it: the fallback fails
closed, and it lets `validate templates/policy-template.md` run as section 9 has it. A choice that
cannot be read is a crash, and does not go on to the next one. The catalog is
`catalog/catalog-v1.yaml`.

Exit codes: 0 when there is no error (warnings are allowed), 1 when there is one, 2 when the
validator could not run. A crash of any command, and a `verify` that says E-INTERNAL, are 2. A crash
prints one E-INTERNAL for each file of the command and nothing else: the name of the class of the
exception is its `detail`. Its message and its traceback can hold text of a file, so they are not
printed, unless `--debug` is given (traceback, on stderr); after a crash that is caught here, and
without `--debug`, one fixed line on stderr says to use it (not for an E-INTERNAL that `verify`
makes: it keeps no traceback, and `--debug` would show nothing more). Two more things are exit code
2: a command line that makes no sense (a usage error of argparse), and an output that cannot be
written (a disk that is full, a pipe that is closed), which gives one fixed line on stderr, no
traceback and no message.

Findings go to stdout and notes to stderr. Text of a file reaches the output only in a finding,
which cleans it (findings.py). A character that the encoding of stdout or stderr cannot take is
written as an escape (`\\xe9`), so a file name with an accent cannot make the output fail.
"""

import argparse
import contextlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import traceback
from collections import defaultdict
from collections.abc import Iterable, Sequence
from pathlib import Path

from aiven.policy.catalog import Catalog, load_catalog
from aiven.policy.config import PlatformConfig, load_platform_config
from aiven.policy.content import escape_unprintable, safe_text
from aiven.policy.findings import LANGUAGES, Finding, format_line, message
from aiven.policy.model import Policy
from aiven.policy.policyset import check_duplicates, check_history
from aiven.policy.render import rewrite
from aiven.policy.validate import report_order, validate_policy
from aiven.policy.verify import ActiveVersion, verify

EXIT_VALID, EXIT_ERRORS, EXIT_CRASH = 0, 1, 2

CONFIG_ENV = "AIVEN_POLICY_CONFIG"
CONFIG_PATH = Path("config/platform.yaml")
EXAMPLE_CONFIG_PATH = Path("config/platform.example.yaml")
CATALOG_PATH = Path("catalog/catalog-v1.yaml")
EXAMPLE_NOTE = "note: using the example platform config"
VERIFY_NOTE = "note: wrapper enablement and the Drive folder are checked at the gateway"
WRITE_NOTE = "note: the output could not be written"
DEBUG_NOTE = "note: run again with --debug to see the cause"
NO_REF_NOTE = "note: version order and widening need --previous-ref"
NO_POLICY_NOTE = (
    "note: the previous version of {path} gives no policy, "
    "so its version order and widening are not checked"
)
GIT_TIMEOUT_S = 60

# The codes of the checks of the whole file, of the body and of the content: validator-spec 3.1, 3.7
# and 3.8. A render does not stop for them. Every other code that `validate_policy` gives belongs to
# the front matter.
FILE_AND_BODY_CODES = frozenset(
    {
        "E-ENCODING",
        "E-LINE-ENDINGS",
        "E-FINAL-NEWLINE",
        "E-FILE-SIZE",
        "E-FILENAME",
        "E-HIDDEN-CHAR",
        "E-PLACEHOLDER",
        "E-BODY-TITLE",
        "E-BODY-SECTIONS",
        "E-BODY-EMPTY",
        "E-BODY-TOOL-UNEXPLAINED",
        "E-BODY-TOOL-EXTRA",
        "E-BODY-DRIFT",
        "E-BODY-HTML",
        "E-BODY-LINK",
        "E-SECRET",
        "E-BANK-DETAILS",
        "E-ID-NUMBER",
    }
)


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command line and give the exit code: 0, 1 or 2 (see the module)."""
    _escape_what_cannot_be_encoded()
    args = _parser().parse_args(argv)
    caught = False
    try:
        cfg, catalog = _platform(args)
        findings, status = args.run(args, cfg, catalog)
        text = _text(findings, as_json=args.json)
    except Exception as error:
        # Whatever went wrong, the files count as invalid (fail closed), and what is said is the
        # name of the class of the error: its message and its traceback can hold text of a file.
        caught = True
        if args.debug:
            with contextlib.suppress(Exception):
                traceback.print_exc()
        findings = [_crash(path, error) for path in dict.fromkeys(args.files)]
        text, status = _text(findings, as_json=args.json), EXIT_CRASH
    if not _write(text):
        return EXIT_CRASH
    if caught and not args.debug:
        # The line says what went wrong and not why, and the traceback has the why. It is said for
        # the crash that is caught here only: an E-INTERNAL that verify() makes has no traceback to
        # show, and --debug would give nothing more (ruling R90).
        _note(DEBUG_NOTE)
    return status


def _escape_what_cannot_be_encoded() -> None:
    """Make stdout and stderr write an escape for a character that their encoding cannot take.

    A file name with an accent would otherwise be a UnicodeEncodeError at the last moment, when the
    output goes to a terminal or a log that is ASCII (PYTHONIOENCODING, a C locale). A stream that
    cannot be set (a stand-in, one that is closed) is left as it is.
    """
    for stream in (sys.stdout, sys.stderr):
        with contextlib.suppress(AttributeError, ValueError, OSError):
            stream.reconfigure(errors="backslashreplace")


def _write(text: str) -> bool:
    """Write the output to stdout, and say whether that worked.

    It can fail for reasons that are not the validator's: a disk that is full, a pipe that the
    reader has closed (`| head`). The error is not shown, as its message can hold text of a file;
    one fixed line goes to stderr, and the exit code is 2.
    """
    try:
        sys.stdout.write(text)
        sys.stdout.flush()
    except Exception:
        _point_stdout_at_the_null_device()
        _note(WRITE_NOTE)
        return False
    return True


def _point_stdout_at_the_null_device() -> None:
    """Send what is left in the buffer of the stdout of the process to the null device.

    Python writes the buffer of stdout once more when it exits. After a write that failed that
    fails again: the error is printed, and the exit code becomes 120. A stand-in for stdout (pytest,
    a caller) has no descriptor of the process to change, and gets none changed.
    """
    if sys.stdout is not sys.__stdout__:
        return
    with contextlib.suppress(Exception):
        null = os.open(os.devnull, os.O_WRONLY)
        try:
            os.dup2(null, sys.stdout.fileno())
        finally:
            os.close(null)


def _note(line: str) -> None:
    """Say a line on stderr. A note that cannot be written is no reason to stop."""
    with contextlib.suppress(Exception):
        print(line, file=sys.stderr)


def _platform(args: argparse.Namespace) -> tuple[PlatformConfig, Catalog]:
    return load_platform_config(_config_path(args.config)), load_catalog(args.catalog)


def _config_path(given: Path | None) -> Path:
    """The platform values to use: --config, else $AIVEN_POLICY_CONFIG, else the files (ruling R61).

    The files are config/platform.yaml, and when that is not there config/platform.example.yaml,
    which says so on stderr. A choice that cannot be read is an error and not a reason to go on to
    the next one.
    """
    if given is not None:
        return given
    if os.environ.get(CONFIG_ENV):
        return Path(os.environ[CONFIG_ENV])
    if CONFIG_PATH.is_file():
        return CONFIG_PATH
    _note(EXAMPLE_NOTE)
    return EXAMPLE_CONFIG_PATH


def _parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--config",
        type=Path,
        help=f"the platform values (else ${CONFIG_ENV}, {CONFIG_PATH}, {EXAMPLE_CONFIG_PATH})",
    )
    common.add_argument(
        "--catalog",
        type=Path,
        default=CATALOG_PATH,
        help="the action catalog (default: %(default)s)",
    )
    common.add_argument("--debug", action="store_true", help="print the traceback of a crash")
    parser = argparse.ArgumentParser(prog="aiven-policy", description="Policy validator, v1.")
    commands = parser.add_subparsers(dest="command", required=True)

    validate = commands.add_parser("validate", parents=[common], help="check policy files")
    validate.add_argument("files", nargs="+", metavar="file", type=Path)
    validate.add_argument("--json", action="store_true", help="one JSON document, EN and NL text")
    validate.add_argument(
        "--previous-ref", metavar="REF", help="the Git ref that holds the previous versions"
    )
    validate.set_defaults(run=_validate)

    render = commands.add_parser(
        "render", parents=[common], help="rewrite the generated sections of a policy file"
    )
    render.add_argument("files", nargs=1, metavar="file", type=Path)
    render.set_defaults(run=_render, json=False)

    verifying = commands.add_parser(
        "verify", parents=[common], help="check a signed policy file before it is uploaded"
    )
    verifying.add_argument("files", nargs=1, metavar="file", type=Path)
    verifying.add_argument("--sig", required=True, type=Path, help="the signature file")
    verifying.add_argument(
        "--allowed-signers", required=True, type=Path, help="the file of allowed signers"
    )
    verifying.add_argument(
        "--active-version", type=_version, help="the version that is loaded now (1 or more)"
    )
    verifying.add_argument("--active-sha256", help="the hash of the file of that version")
    verifying.set_defaults(run=_verify, json=False, parser=verifying)
    return parser


def _version(text: str) -> int:
    """A version number for the command line: a whole number of 1 or more, or a usage error."""
    if not (text.isascii() and text.isdecimal()) or int(text) < 1:
        raise argparse.ArgumentTypeError(
            f"{text!r} is not a version: use a whole number, 1 or more"
        )
    return int(text)


def _validate(
    args: argparse.Namespace, cfg: PlatformConfig, catalog: Catalog
) -> tuple[list[Finding], int]:
    """The findings of all files, file by file, and the exit code (see the module)."""
    paths = _distinct(args.files)
    runs = [validate_policy(path, path.read_bytes(), cfg, catalog) for path in paths]
    built = sorted(
        (
            (path, run.policy)
            for path, run in zip(paths, runs, strict=True)
            if run.policy is not None
        ),
        key=lambda item: str(item[0]),
    )
    # A file whose history is not known has no version order and no widening, and is no new agent
    # either (rulings R86 and R88): without a ref that is every file, with one it is a file whose
    # previous version gives no policy. The history is not asked for it (ruling R91).
    previous: dict[str, Policy] = {}
    unknown, notes = paths, [NO_REF_NOTE]
    if args.previous_ref is not None:
        previous, unknown = _previous_policies(args.previous_ref, paths, cfg, catalog)
        notes = [NO_POLICY_NOTE.format(path=_shown(path)) for path in unknown]
    left_out = set(unknown)
    across = defaultdict(list)
    for finding in check_duplicates(built):
        across[finding.path].append(finding)
    for path, policy in built:
        if path not in left_out:
            for finding in check_history(path, policy, previous.get(policy.agent)):
                across[finding.path].append(finding)
    findings = []
    for path, run in zip(paths, runs, strict=True):
        found = [*run.findings, *across[_shown(path)]]
        findings += sorted(found, key=report_order)
    for note in notes:
        _note(note)
    return findings, _status(findings)


def _distinct(paths: Iterable[Path]) -> list[Path]:
    """The files once each, by the file that a path names, with the spelling that came first.

    `policies/../policies/a.md` and `policies/a.md` are one file, and so is a link and what it
    points at. Left in twice, a file is its own duplicate (E-AGENT-DUPLICATE).
    """
    files: dict[Path, Path] = {}
    for path in paths:
        files.setdefault(path.resolve(), path)
    return list(files.values())


def _render(
    args: argparse.Namespace, cfg: PlatformConfig, catalog: Catalog
) -> tuple[list[Finding], int]:
    """Rewrite the generated sections of the file, if its front matter is good (ruling R29).

    The front matter is good when it builds a policy and has no error. A finding of the file, the
    body or the content does not matter (`FILE_AND_BODY_CODES`): a template has them all on its way
    to being a policy. When the front matter is not good the file is not touched, the exit code is
    1, and the findings of the front matter are shown if one of them is an error. If none is, all
    findings of the file are shown, because the reason is not in the front matter: a placeholder
    where a number belongs gives no policy (its finding is of the file), and the renderer can refuse
    the sections (a ValueError, which holds no text of the file) where the errors of the body say
    why.
    """
    (path,) = args.files
    data = path.read_bytes()
    checked = validate_policy(path, data, cfg, catalog)
    front = [f for f in checked.findings if f.code not in FILE_AND_BODY_CODES]
    bad = any(f.severity == "error" for f in front)
    if checked.policy is not None and not bad:
        try:
            content = rewrite(data, checked.policy, catalog)
        except ValueError:
            pass
        else:
            _replace_file(path, content)
            return [], EXIT_VALID
    return (front if bad else checked.findings), EXIT_ERRORS


def _verify(
    args: argparse.Namespace, cfg: PlatformConfig, catalog: Catalog
) -> tuple[list[Finding], int]:
    """The check before an upload: the signature, the file, and the version against the active one.

    Whether a wrapper is switched on for the agent (`enabled_for`) and whether the folder is in the
    Sandbox drive are known to the gateway only. So a wrapper counts as live unless the catalog says
    it is planned, the folder check passes, and the note on stderr says so.
    """
    (path,) = args.files
    active = _active_version(args)
    data = path.read_bytes()
    try:
        sig = args.sig.read_bytes()
    except FileNotFoundError:  # any other trouble with the file is a crash and not a missing one
        sig = None
    _, findings = verify(
        path,
        data,
        sig,
        args.allowed_signers,
        active,
        lambda wrapper, agent: catalog.wrapper_status[wrapper] != "planned",
        lambda folder_id, folder_path: True,
        cfg,
        catalog,
    )
    _note(VERIFY_NOTE)
    return findings, _status(findings)


def _active_version(args: argparse.Namespace) -> ActiveVersion | None:
    """The active version of the agent from the command line, if it is there and well formed."""
    if (args.active_version is None) != (args.active_sha256 is None):
        args.parser.error("--active-version and --active-sha256 go together")
    if args.active_version is None:
        return None
    try:
        return ActiveVersion(args.active_version, args.active_sha256)
    except ValueError:
        args.parser.error("--active-sha256 is sha256: and 64 lowercase hex digits")


def _replace_file(path: Path, content: bytes) -> None:
    """Put `content` in the file at once: write a temporary file next to it, then rename it over.

    The file keeps its permissions. A symbolic link is followed, so the file behind it is the one
    that changes. When anything fails the file is as it was, and the temporary file is removed.
    """
    target = path.resolve()
    handle, name = tempfile.mkstemp(dir=target.parent, prefix=f".{target.name}.", suffix=".tmp")
    try:
        with os.fdopen(handle, "wb") as temporary:
            temporary.write(content)
        shutil.copymode(target, name)
        os.replace(name, target)
    except BaseException:
        Path(name).unlink(missing_ok=True)
        raise


def _previous_policies(
    ref: str, paths: list[Path], cfg: PlatformConfig, catalog: Catalog
) -> tuple[dict[str, Policy], list[Path]]:
    """The previous signed policy of each agent: its file as it is at `ref` in Git (section 3.9).

    A file that is not at `ref` is a new agent and has none. What is there is loaded and built, and
    nothing is said of its findings. A file that is there and gives no policy is a file whose
    history is not known (ruling R88): the second item is those files.
    """
    if not ref or ref.startswith("-"):  # not a ref: an empty one means the index, "-" an option
        raise ValueError("not a git ref")
    previous: dict[str, Policy] = {}
    unknown = []
    for path in paths:
        where = path.resolve()
        # Git is asked in the folder of the file, so the folder of the command does not matter.
        folder = str(where.parent)
        root = Path(os.fsdecode(_git(folder, "rev-parse", "--show-toplevel").rstrip(b"\n")))
        name = where.relative_to(root).as_posix()
        if _git(folder, "ls-tree", "-z", "--full-tree", "--name-only", ref, "--", name):
            old_bytes = _git(folder, "show", f"{ref}:{name}")
            before = validate_policy(path, old_bytes, cfg, catalog).policy
            if before is None:
                unknown.append(path)
            else:
                previous[before.agent] = before
    return previous, unknown


def _git(folder: str, *args: str) -> bytes:
    """What `git` prints when it runs in `folder` (`git -C`) with these arguments.

    It is no shell command, so nothing is expanded, and `folder` is where the file is: a command
    that is run from outside the repository, with a path to a file in it, works.
    """
    command = ["git", "-C", folder, *args]
    return subprocess.run(command, capture_output=True, check=True, timeout=GIT_TIMEOUT_S).stdout


def _text(findings: list[Finding], *, as_json: bool) -> str:
    """What is printed: a line for each finding, or one JSON document (validator-spec section 1)."""
    if as_json:
        return json.dumps({"findings": [_entry(f) for f in findings]}) + "\n"
    return "".join(format_line(f) + "\n" for f in findings)


def _entry(f: Finding) -> dict[str, object]:
    """A finding for the JSON document.

    The params go through `safe_text` once more (ruling R23): this reads `f.params` directly, and
    the dict is not frozen, so it may hold what the finding did not when it was made.
    """
    return {
        "path": f.path,
        "line": f.line,
        "column": f.column,
        "severity": f.severity,
        "code": f.code,
        "params": {name: safe_text(value) for name, value in f.params.items()},
        **{lang: message(f, lang) for lang in LANGUAGES},
    }


def _shown(path: Path) -> str:
    """The path as a finding shows it, with each character that must be escaped written out."""
    return escape_unprintable(str(path))


def _crash(path: Path, error: Exception) -> Finding:
    """E-INTERNAL for a file: the validator could not finish, so the file counts as invalid."""
    return Finding("E-INTERNAL", "error", str(path), params={"detail": type(error).__name__})


def _status(findings: list[Finding]) -> int:
    """2 when the validator could not finish (`verify` says so with E-INTERNAL), 1 for an error."""
    if any(f.code == "E-INTERNAL" for f in findings):
        return EXIT_CRASH
    return EXIT_ERRORS if any(f.severity == "error" for f in findings) else EXIT_VALID
