"""The `aiven-policy` command line (validator-spec section 1): `validate`, `render` and `verify`.

This is where the checks meet a person, a script or CI. It reads the files, the platform values and
the catalog, runs what the other modules give, and decides what is printed and what the exit code
is. Every command takes `--config`, `--catalog` and `--debug`.

`validate <file>... [--json] [--previous-ref REF]` runs every check on each file (`validate_policy`)
and the checks across the files that built a policy (`check_set`, given the files sorted by path).
The output is file by file in the order of the arguments, a file named twice counting once. A file's
own findings come in the order of `validate_file`, and the findings across the files are in with
those of the file they are about. With `--previous-ref` the previous version of a file is the file
as it is at that Git ref (`git show REF:path`, run without a shell). A file that is not there is a
new agent. The previous files are loaded and built and nothing is said of them. Without a ref every
file is a new agent, so a version other than 1 is E-VERSION-ORDER. `--json` prints one document,
`{"findings": [...]}`, with the column, the parameters and the text in both languages (section 1).

`render <file>` rewrites the two generated sections, when the front matter loads and builds a policy
without an error (ruling R29). A finding of the file, the body or the content does not stop it
(`FILE_AND_BODY_CODES`): a template has them on its way to being a policy (section 9). Otherwise the
findings of the front matter are printed, the exit code is 1, and the file is not touched. The
sections are written all at once (`_replace_file`).

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
printed, unless `--debug` is given (traceback, on stderr). The same goes for a command line that
makes no sense: a usage error of argparse, also exit code 2.

Findings go to stdout and notes to stderr. Text of a file reaches the output only in a finding,
which cleans it (findings.py).
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import traceback
from collections import defaultdict
from collections.abc import Sequence
from pathlib import Path

from aiven.policy.catalog import Catalog, load_catalog
from aiven.policy.config import PlatformConfig, load_platform_config
from aiven.policy.content import escape_unprintable, safe_text
from aiven.policy.findings import LANGUAGES, Finding, format_line, message
from aiven.policy.model import Policy
from aiven.policy.policyset import check_set
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
    args = _parser().parse_args(argv)
    try:
        cfg, catalog = _platform(args)
        findings, status = args.run(args, cfg, catalog)
        text = _text(findings, as_json=args.json)
    except Exception as error:
        # Whatever went wrong, the files count as invalid (fail closed), and what is said is the
        # name of the class of the error: its message and its traceback can hold text of a file.
        if args.debug:
            traceback.print_exc()
        findings = [_crash(path, error) for path in dict.fromkeys(args.files)]
        text, status = _text(findings, as_json=args.json), EXIT_CRASH
    sys.stdout.write(text)
    return status


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
    print(EXAMPLE_NOTE, file=sys.stderr)
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
    verifying.add_argument("--active-version", type=int, help="the version that is loaded now")
    verifying.add_argument("--active-sha256", help="the hash of the file of that version")
    verifying.set_defaults(run=_verify, json=False, parser=verifying)
    return parser


def _validate(
    args: argparse.Namespace, cfg: PlatformConfig, catalog: Catalog
) -> tuple[list[Finding], int]:
    """The findings of all files, file by file, and the exit code (see the module)."""
    paths = list(dict.fromkeys(args.files))  # a file named twice is checked once
    runs = [validate_policy(path, path.read_bytes(), cfg, catalog) for path in paths]
    built = sorted(
        (
            (path, run.policy)
            for path, run in zip(paths, runs, strict=True)
            if run.policy is not None
        ),
        key=lambda item: str(item[0]),
    )
    previous = {}
    if args.previous_ref is not None:
        previous = _previous_policies(args.previous_ref, paths, cfg, catalog)
    across = defaultdict(list)
    for finding in check_set(built, previous):
        across[finding.path].append(finding)
    findings = []
    for path, run in zip(paths, runs, strict=True):
        found = [*run.findings, *across[escape_unprintable(str(path))]]
        findings += sorted(found, key=report_order)
    return findings, _status(findings)


def _render(
    args: argparse.Namespace, cfg: PlatformConfig, catalog: Catalog
) -> tuple[list[Finding], int]:
    """Rewrite the generated sections of the file, if its front matter is good (ruling R29).

    The front matter is good when it builds a policy and has no error. A finding of the file, the
    body or the content does not matter (`FILE_AND_BODY_CODES`): a template has them all on its way
    to being a policy. When the front matter is not good, what is shown is its findings and the file
    is not touched. It is the same when the renderer refuses the sections (a ValueError, which
    holds no text of the file): the findings of the body say why, and then all findings are shown.
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
    print(VERIFY_NOTE, file=sys.stderr)
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
) -> dict[str, Policy]:
    """The previous signed policy of each agent: its file as it is at `ref` in Git (section 3.9).

    A file that is not at `ref` is a new agent and has none. What is there is loaded and built, and
    nothing is said of its findings; a file that gives no policy counts as no previous version.
    """
    if not ref or ref.startswith("-"):  # not a ref: an empty one means the index, "-" an option
        raise ValueError("not a git ref")
    root = Path(os.fsdecode(_git("rev-parse", "--show-toplevel").rstrip(b"\n")))
    previous = {}
    for path in paths:
        name = path.resolve().relative_to(root).as_posix()
        if _git("ls-tree", "-z", "--full-tree", "--name-only", ref, "--", name):
            before = validate_policy(path, _git("show", f"{ref}:{name}"), cfg, catalog).policy
            if before is not None:
                previous[before.agent] = before
    return previous


def _git(*args: str) -> bytes:
    """What `git` prints with these arguments. It is no shell command, so nothing is expanded."""
    done = subprocess.run(["git", *args], capture_output=True, check=True, timeout=GIT_TIMEOUT_S)
    return done.stdout


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


def _crash(path: Path, error: Exception) -> Finding:
    """E-INTERNAL for a file: the validator could not finish, so the file counts as invalid."""
    return Finding("E-INTERNAL", "error", str(path), params={"detail": type(error).__name__})


def _status(findings: list[Finding]) -> int:
    """2 when the validator could not finish (`verify` says so with E-INTERNAL), 1 for an error."""
    if any(f.code == "E-INTERNAL" for f in findings):
        return EXIT_CRASH
    return EXIT_ERRORS if any(f.severity == "error" for f in findings) else EXIT_VALID
