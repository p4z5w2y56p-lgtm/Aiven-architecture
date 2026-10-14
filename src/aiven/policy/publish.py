"""`aiven-policy publish`: Matthijs publishes a signed policy, the catalog or the trust anchor
(plan Task 3.5b; M3 flag #1).

Only Matthijs publishes, with his own login (application default credentials of
m.vanhoorn@aivenstudios.com), from his own machine:

    aiven-policy publish policies/<agent>.md --sig policies/<agent>.md.sig \\
        --control-project <id> --by <his address> [--config config/platform.yaml]
    aiven-policy publish --catalog catalog/catalog-v1.yaml --sig catalog/catalog-v1.yaml.sig \\
        --control-project <id>
    aiven-policy publish --allowed-signers allowed_signers --control-project <id>

A policy is validated and verified here, against the trust anchor and the catalog of the control
project (each read capped, the catalog's signature checked under `aiven-catalog-v1`), and against
the record in Firestore `releases`: its version must be above the published one (E-VERSION-ORDER
otherwise; publishing the published file again does nothing). Then the diff against the file that
is published now is shown, and one question is asked. On "y", the file is uploaded, then its
signature, each only if the object is still the one that was read (`if_generation_match`), and
last the record `policy_versions/{agent}` = {version, sha256, by, at}, only if it is still the one
that was read (a transaction). A failure in between leaves the record as it was, and a file without
its record is never loaded by the gateway. The file goes before its signature: a gateway reload
that falls between the two sees a file that is not the published one, keeps the active version
and alerts once (ruling R184); the other order would stop the agent for a minute.

The catalog and the trust anchor are published the same way, without a record: the catalog's
signature is checked first, and the trust anchor must trust `matthijs` for both namespaces.

Exit codes: 0 published, or nothing to do; 1 refused or declined; 2 Google could not be reached or
answered with an error, which is named by its class only (its message can hold a token).
"""

import argparse
import difflib
import shlex
import sys
import tempfile
from collections.abc import Callable, Sequence
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol, TextIO

from aiven.gateway.bucket_io import Missing, TooLarge, read_capped
from aiven.gateway.control import PolicyVersion
from aiven.policy.catalog import Catalog, CatalogError, parse_catalog
from aiven.policy.config import PlatformConfig, load_platform_config
from aiven.policy.constants import (
    CATALOG_NAMESPACE,
    MAX_FILE_BYTES,
    MAX_SIG_BYTES,
    NAMESPACE,
    SIGNER,
    WRAPPER_NAMES,
)
from aiven.policy.content import escape_unprintable
from aiven.policy.findings import format_line
from aiven.policy.verify import ActiveVersion, verify, verify_signature

EXIT_DONE, EXIT_REFUSED, EXIT_ERROR = 0, 1, 2
ALLOWED_SIGNERS = "allowed_signers"
CATALOG = "catalog/catalog-v1.yaml"


class Releases(Protocol):
    """The records of `releases/policy_versions`."""

    def get(self, agent: str) -> PolicyVersion | None: ...

    def put_if(self, agent: str, expected: PolicyVersion | None, new: PolicyVersion) -> bool: ...


class FirestoreReleases:
    """`policy_versions/{agent}` in Firestore `releases` of the control project."""

    def __init__(self, client: Any) -> None:
        self._db = client

    def _ref(self, agent: str) -> Any:
        return self._db.collection("policy_versions").document(agent)

    @staticmethod
    def _version(doc: dict[str, Any]) -> PolicyVersion:
        return PolicyVersion(doc["version"], doc["sha256"], doc["by"], doc["at"])

    def get(self, agent: str) -> PolicyVersion | None:
        snapshot = self._ref(agent).get()
        return self._version(snapshot.to_dict()) if snapshot.exists else None

    def put_if(self, agent: str, expected: PolicyVersion | None, new: PolicyVersion) -> bool:
        from google.cloud import firestore

        ref = self._ref(agent)

        @firestore.transactional
        def step(transaction: Any) -> bool:
            snapshot = ref.get(transaction=transaction)
            current = self._version(snapshot.to_dict()) if snapshot.exists else None
            if current != expected:
                return False
            transaction.set(
                ref, {"version": new.version, "sha256": new.sha256, "by": new.by, "at": new.at}
            )
            return True

        return step(self._db.transaction())


class _Refused(Exception):
    """Publishing stops here, with this line, and exit 1."""


def _say(out: TextIO, line: str) -> None:
    out.write(line + "\n")
    out.flush()


def _diff(out: TextIO, old: bytes | None, new: bytes, name: str) -> None:
    before = [] if old is None else old.decode("utf-8", "replace").splitlines()
    after = new.decode("utf-8", "replace").splitlines()
    lines = difflib.unified_diff(before, after, f"{name} (published)", f"{name} (new)", lineterm="")
    shown = [escape_unprintable(line) for line in lines]
    _say(out, "\n".join(shown) if shown else "(no change in the text)")


def _current(bucket: Any, name: str, cap: int) -> tuple[bytes | None, int]:
    """What `name` holds now, and its generation (0 when there is none)."""
    blob = bucket.get_blob(name)
    if blob is None:
        return None, 0
    return read_capped(bucket, name, cap), blob.generation


def _upload(bucket: Any, name: str, data: bytes, generation: int, content_type: str) -> None:
    from google.api_core.exceptions import PreconditionFailed

    try:
        bucket.blob(name).upload_from_string(
            data, content_type=content_type, if_generation_match=generation
        )
    except PreconditionFailed as error:
        raise _Refused(
            f"{name} changed in the bucket while publishing; nothing more was written. "
            "Run publish again."
        ) from error


def _anchor(bucket: Any, folder: Path) -> Path:
    try:
        data = read_capped(bucket, ALLOWED_SIGNERS, MAX_FILE_BYTES)
    except (Missing, TooLarge) as error:
        raise _Refused(
            "the bucket has no usable allowed_signers: publish it first "
            "(aiven-policy publish --allowed-signers)"
        ) from error
    path = folder / "allowed_signers"
    path.write_bytes(data)
    path.chmod(0o600)
    return path


def _catalog(bucket: Any, anchor: Path, folder: Path) -> Catalog:
    try:
        data = read_capped(bucket, CATALOG, MAX_FILE_BYTES)
        sig = read_capped(bucket, CATALOG + ".sig", MAX_SIG_BYTES)
    except (Missing, TooLarge) as error:
        raise _Refused(
            "the bucket has no usable catalog: publish it first (aiven-policy publish --catalog)"
        ) from error
    if not verify_signature(data, sig, anchor, namespace=CATALOG_NAMESPACE, tmpdir=folder):
        raise _Refused("the catalog in the bucket is not validly signed: publish it again")
    try:
        return parse_catalog(data, "catalog-v1.yaml")
    except CatalogError as error:
        raise _Refused("the catalog in the bucket is not valid catalog v1") from error


def _guarded(out: TextIO, work: Callable[[], int]) -> int:
    try:
        return work()
    except _Refused as refused:
        _say(out, f"Not published: {refused}")
        return EXIT_REFUSED
    except Exception as error:
        _say(out, f"Not published: Google answered with an error ({type(error).__name__}).")
        return EXIT_ERROR


def publish_policy(
    path: Path,
    sig_path: Path,
    *,
    bucket: Any,
    releases: Releases,
    cfg: PlatformConfig,
    by: str,
    confirm: Callable[[str], bool],
    out: TextIO,
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> int:
    """Publish one policy. See the module docstring."""

    def work() -> int:
        agent = path.name.removesuffix(".md")
        data, sig = path.read_bytes(), sig_path.read_bytes()
        record = releases.get(agent)
        with tempfile.TemporaryDirectory(prefix="aiven-publish-") as name:
            folder = Path(name)
            anchor = _anchor(bucket, folder)
            catalog = _catalog(bucket, anchor, folder)
            active = None if record is None else ActiveVersion(record.version, record.sha256)
            # Whether a wrapper is live, and where the folder is, are judged by the gateway at
            # load (validator-spec 3.10): here every wrapper counts as built and switched on.
            every_wrapper = replace(
                catalog, wrapper_status=dict.fromkeys(catalog.wrapper_status, "built")
            )
            policy, findings = verify(
                Path(f"policies/{agent}.md"),
                data,
                sig,
                anchor,
                active,
                lambda wrapper, who: True,
                lambda folder_id, folder_path: True,
                cfg,
                every_wrapper,
                tmpdir=folder,
            )
        for finding in findings:
            _say(out, format_line(finding))
        if policy is None:
            raise _Refused(f"{path} has errors (above)")
        for tool in policy.tools:
            wrapper = catalog.actions[tool].wrapper
            if catalog.wrapper_status[wrapper] == "planned":
                _say(
                    out,
                    f"note: {tool} needs the {WRAPPER_NAMES[wrapper]} wrapper, which is not built "
                    "yet; the gateway loads this policy only once it is (E-TOOL-NOT-LIVE).",
                )
        if record is not None and record.sha256 == policy.sha256:
            _say(out, f"{agent} version {policy.version} is already published; nothing to do.")
            return EXIT_DONE
        name = f"policies/{agent}.md"
        current, generation = _current(bucket, name, MAX_FILE_BYTES)
        _, sig_generation = _current(bucket, name + ".sig", MAX_SIG_BYTES)
        old = "none" if record is None else str(record.version)
        _say(out, f"{agent}: version {old} -> {policy.version}, {policy.sha256}")
        _diff(out, current, data, name)
        if not confirm(f"Publish {agent} version {policy.version}? (y/n) "):
            _say(out, "No: nothing was published.")
            return EXIT_REFUSED
        _upload(bucket, name, data, generation, "text/markdown")
        _upload(bucket, name + ".sig", sig, sig_generation, "text/plain")
        new = PolicyVersion(policy.version, policy.sha256, by, now())
        if not releases.put_if(agent, record, new):
            raise _Refused(
                "the published version changed while publishing; the file waits in the bucket, "
                "unpublished. Run publish again."
            )
        _say(out, f"Published {agent} version {policy.version} ({policy.sha256}).")
        return EXIT_DONE

    return _guarded(out, work)


def publish_catalog(
    path: Path, sig_path: Path, *, bucket: Any, confirm: Callable[[str], bool], out: TextIO
) -> int:
    """Publish the catalog, signed under `aiven-catalog-v1`."""

    def work() -> int:
        data, sig = path.read_bytes(), sig_path.read_bytes()
        with tempfile.TemporaryDirectory(prefix="aiven-publish-") as name:
            folder = Path(name)
            anchor = _anchor(bucket, folder)
            signed = verify_signature(data, sig, anchor, namespace=CATALOG_NAMESPACE, tmpdir=folder)
        if not signed:
            raise _Refused(f"{path} is not signed by {SIGNER} under {CATALOG_NAMESPACE}")
        try:
            parse_catalog(data, path.name)
        except CatalogError as error:
            raise _Refused(f"{path} is not valid catalog v1") from error
        return _publish_plain(bucket, CATALOG, data, sig, confirm, out)

    return _guarded(out, work)


def publish_allowed_signers(
    path: Path, *, bucket: Any, confirm: Callable[[str], bool], out: TextIO
) -> int:
    """Publish the trust anchor: `matthijs`, trusted for the policy and the catalog namespace."""

    def work() -> int:
        data = path.read_bytes()
        lines = [
            line
            for line in data.decode("utf-8", "replace").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        needed = {NAMESPACE, CATALOG_NAMESPACE}
        for line in lines:
            words = shlex.split(line)
            namespaces = next(
                (w.split("=", 1)[1] for w in words if w.startswith("namespaces=")), ""
            )
            if words[:1] != [SIGNER] or not needed <= set(namespaces.split(",")):
                raise _Refused(
                    f"every line must trust {SIGNER} with "
                    f'namespaces="{NAMESPACE},{CATALOG_NAMESPACE}"'
                )
        if not lines:
            raise _Refused(f"{path} trusts nobody")
        return _publish_plain(bucket, ALLOWED_SIGNERS, data, None, confirm, out)

    return _guarded(out, work)


def _publish_plain(
    bucket: Any,
    name: str,
    data: bytes,
    sig: bytes | None,
    confirm: Callable[[str], bool],
    out: TextIO,
) -> int:
    current, generation = _current(bucket, name, MAX_FILE_BYTES)
    if current == data:
        _say(out, f"{name} is already published; nothing to do.")
        return EXIT_DONE
    _diff(out, current, data, name)
    if not confirm(f"Publish {name}? (y/n) "):
        _say(out, "No: nothing was published.")
        return EXIT_REFUSED
    _upload(bucket, name, data, generation, "text/plain")
    if sig is not None:
        _, sig_generation = _current(bucket, name + ".sig", MAX_SIG_BYTES)
        _upload(bucket, name + ".sig", sig, sig_generation, "text/plain")
    _say(out, f"Published {name}.")
    return EXIT_DONE


def _ask(prompt: str) -> bool:
    """One question on the terminal: y or yes publishes, anything else does not."""
    try:
        answer = input(prompt)
    except EOFError:
        return False
    return answer.strip().lower() in ("y", "yes")


def main(argv: Sequence[str] | None = None) -> int:  # pragma: no cover - Google and a terminal
    """The command line. See the module docstring."""
    parser = argparse.ArgumentParser(prog="aiven-policy publish")
    parser.add_argument("file", nargs="?", type=Path, help="a policy file, policies/<agent>.md")
    parser.add_argument("--catalog", type=Path, help="publish this catalog instead")
    parser.add_argument("--allowed-signers", type=Path, help="publish this trust anchor instead")
    parser.add_argument("--sig", type=Path, help="the signature of the policy or catalog")
    parser.add_argument("--control-project", required=True, help="the control project's ID")
    parser.add_argument("--by", help="your address, for the record (policies only)")
    parser.add_argument("--config", type=Path, default=Path("config/platform.yaml"))
    args = parser.parse_args(argv)
    chosen = [args.file, args.catalog, args.allowed_signers]
    if sum(each is not None for each in chosen) != 1:
        parser.error("give one of: a policy file, --catalog, --allowed-signers")
    if (args.file or args.catalog) and args.sig is None:
        parser.error("--sig is needed")
    if args.file and not args.by:
        parser.error("--by is needed for a policy")
    from google.cloud import firestore, storage

    bucket = storage.Client(project=args.control_project).bucket(f"{args.control_project}-policies")
    out = sys.stdout
    if args.allowed_signers:
        return publish_allowed_signers(args.allowed_signers, bucket=bucket, confirm=_ask, out=out)
    if args.catalog:
        return publish_catalog(args.catalog, args.sig, bucket=bucket, confirm=_ask, out=out)
    releases = FirestoreReleases(
        firestore.Client(project=args.control_project, database="releases")
    )
    return publish_policy(
        args.file,
        args.sig,
        bucket=bucket,
        releases=releases,
        cfg=load_platform_config(args.config),
        by=args.by,
        confirm=_ask,
        out=out,
    )
