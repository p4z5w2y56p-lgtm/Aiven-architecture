"""The signed policy registry (plan Task 3.5; validator-spec 2, 3.9, 3.10; M3 flags #1 to #4).

The registry holds the verified catalog, the price list and the active policy of each published
agent, all read from the policy bucket in control:

- `allowed_signers`, the trust anchor, written to the gateway's private folder (0700);
- `catalog/catalog-v1.yaml` with its `.sig`, verified under `aiven-catalog-v1` before it is parsed
  (flag #2). Without a valid catalog the gateway does not start (`StartupRefused`); a catalog that
  fails later is not taken, the verified one stays, and Matthijs is alerted;
- `policies/<agent>.md` with its `.sig`, for each agent that has a record `policy_versions/{agent}`
  in Firestore `releases` (flag #1). No record: not published, no policy. A record that cannot be
  read: nothing new loads, and an alert;
- `pricing/models.yaml`, for the cost per run.

Every object is read capped (bucket_io.py, flag #3) and every signature is checked with the pinned
`/usr/bin/ssh-keygen` (startup.py, flag #4); if that binary is not safe, nothing loads and an alert
says so.

For each published agent, the file in the bucket is compared with the record:

- the file is the published one (its hash is the record's): it is verified (`verify`) against the
  gateway's high-water mark (`active/{agent}` in the working store), so an older version or the same
  version in other bytes is E-VERSION-ORDER. Verified, it becomes active and raises the mark;
- the file is another one: it is verified against the record, never loaded. A signed newer version
  is a publish in progress and waits quietly for its record; anything else (unsigned, older, the
  same version in other bytes) alerts (AT-SELF-5, AT-SELF-6).

A version that fails keeps the active one (and alerts). If the active version itself fails now
(its wrapper was switched off, say), the agent is stopped and Matthijs is alerted. Two policies
with one agent or one principal load neither (3.9). Each change writes a `policy_load` entry; a
reload that changes nothing writes none. The policies are re-read when the last load is more than
60 s old, or at once on `policies:reload` (gateway-design section 13).
"""

import hashlib
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from aiven.common.audit import AuditEntry, AuditWriteFailed, AuditWriter
from aiven.gateway.bucket_io import Bucket, Missing, TooLarge, read_capped
from aiven.gateway.control import ControlReader, ControlUnavailable, PolicyVersion, fail_closed_line
from aiven.gateway.pricing import Pricing, PricingError
from aiven.gateway.startup import SSH_KEYGEN, UnsafeSshKeygen
from aiven.gateway.startup import check_ssh_keygen as default_check
from aiven.gateway.store import Store
from aiven.policy.catalog import Catalog, CatalogError, parse_catalog
from aiven.policy.config import PlatformConfig
from aiven.policy.constants import CATALOG_NAMESPACE, MAX_FILE_BYTES, MAX_SIG_BYTES
from aiven.policy.model import Policy
from aiven.policy.policyset import check_duplicates
from aiven.policy.verify import ActiveVersion, verify, verify_signature

CATALOG_OBJECT = "catalog/catalog-v1.yaml"
ALLOWED_SIGNERS_OBJECT = "allowed_signers"
PRICING_OBJECT = "pricing/models.yaml"
REFRESH_AFTER = timedelta(seconds=60)


class StartupRefused(Exception):
    """There is no verified catalog: the gateway does not start (validator-spec 5)."""


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class _Outcome:
    """What one agent's load came to: the policy to hold, and why it failed, if it did."""

    policy: Policy | None
    failure: str | None = None


class PolicyRegistry:
    """The verified policies, catalog and price list. See the module docstring."""

    def __init__(
        self,
        *,
        bucket: Bucket,
        control: ControlReader,
        store: Store,
        audit: AuditWriter,
        cfg: PlatformConfig,
        folder_check: Callable[[str, str | None], bool],
        tmpdir: Path,
        ssh_keygen: str = SSH_KEYGEN,
        check_ssh_keygen: Callable[[str], None] = default_check,
        actor: str = "gateway",
    ) -> None:
        self._bucket = bucket
        self._control = control
        self._store = store
        self._audit = audit
        self._cfg = cfg
        self._folder_check = folder_check
        self._tmpdir = tmpdir
        self._ssh_keygen = ssh_keygen
        self._check_ssh_keygen = check_ssh_keygen
        self._actor = actor
        self._catalog: Catalog | None = None
        self._active: dict[str, Policy] = {}
        self._last: datetime | None = None
        self._usable = True
        self._lock = threading.Lock()
        self.pricing: Pricing | None = None

    # --- what the pipeline reads

    @property
    def catalog(self) -> Catalog:
        if self._catalog is None:
            raise StartupRefused("no verified catalog")
        return self._catalog

    def for_principal(self, email: str) -> Policy | None:
        return next((p for p in self._active.values() if p.principal == email), None)

    def for_agent(self, agent: str) -> Policy | None:
        return self._active.get(agent)

    # --- loading

    def start(self, now: datetime) -> None:
        """The first load. Raises StartupRefused without a verified catalog."""
        try:
            self._check_ssh_keygen(self._ssh_keygen)
        except UnsafeSshKeygen:
            self._usable = False
            self._entry(outcome="refused", reason="UNSAFE_SSH_KEYGEN", alert=True)
            return
        self._refresh(now)
        if self._catalog is None:
            raise StartupRefused("the catalog is missing or not validly signed")

    def refresh(self, now: datetime, *, force: bool = False) -> None:
        """Re-read when the last load is more than 60 s old, or now with `force`."""
        if not self._usable:
            return
        if not force and self._last is not None and now - self._last < REFRESH_AFTER:
            return
        if not self._lock.acquire(blocking=False):
            return  # another request is loading; this one goes on with what is loaded
        try:
            self._refresh(now)
        finally:
            self._lock.release()

    def _refresh(self, now: datetime) -> None:
        self._last = now
        anchor = self._trust_anchor()
        if anchor is None:
            return
        self._load_catalog(anchor)
        if self._catalog is None:
            return
        self._load_pricing()
        try:
            records = self._control.policy_versions()
        except ControlUnavailable:
            self._entry(outcome="refused", reason="CONTROL_UNREACHABLE", alert=True)
            return
        outcomes = {
            agent: self._load_one(agent, record, anchor) for agent, record in records.items()
        }
        held = {agent: o.policy for agent, o in outcomes.items() if o.policy is not None}
        duplicated = check_duplicates([(Path(f"policies/{a}.md"), p) for a, p in held.items()])
        for finding in duplicated:
            agent = Path(finding.path).name.removesuffix(".md")
            outcomes[agent] = _Outcome(None, finding.code)
            held.pop(agent, None)
        for agent in sorted(set(self._active) | set(outcomes)):
            self._note_change(agent, self._active.get(agent), held.get(agent), outcomes.get(agent))
        self._active = held

    def _note_change(
        self, agent: str, old: Policy | None, new: Policy | None, outcome: _Outcome | None
    ) -> None:
        failure = None if outcome is None else outcome.failure
        if new is not None and (old is None or old.sha256 != new.sha256):
            self._store.set_active(agent, ActiveVersion(new.version, new.sha256))
            self._entry(agent=agent, policy=new, outcome="loaded")
        if failure is not None:
            stopped = old is not None and new is None
            shown = old if new is None else new
            self._entry(
                agent=agent,
                policy=shown,
                outcome="stopped" if stopped else "refused",
                reason=failure,
                alert=True,
            )
        elif outcome is None and old is not None:
            self._entry(agent=agent, policy=old, outcome="unpublished")

    def _trust_anchor(self) -> Path | None:
        try:
            data = read_capped(self._bucket, ALLOWED_SIGNERS_OBJECT, MAX_FILE_BYTES)
        except (Missing, TooLarge) as error:
            self._entry(
                outcome="refused", reason=_reason(error), note="allowed_signers", alert=True
            )
            return None
        anchor = self._tmpdir / "allowed_signers"
        anchor.write_bytes(data)
        anchor.chmod(0o600)
        return anchor

    def _load_catalog(self, anchor: Path) -> None:
        try:
            data = read_capped(self._bucket, CATALOG_OBJECT, MAX_FILE_BYTES)
            sig = read_capped(self._bucket, CATALOG_OBJECT + ".sig", MAX_SIG_BYTES)
        except (Missing, TooLarge) as error:
            self._catalog_failed(_reason(error, signature=".sig" in str(error)))
            return
        if self._catalog is not None and _sha256(data) == self._catalog.sha256:
            return
        try:
            signed = verify_signature(
                data,
                sig,
                anchor,
                namespace=CATALOG_NAMESPACE,
                ssh_keygen=self._ssh_keygen,
                tmpdir=self._tmpdir,
            )
        except Exception:
            signed = False  # ssh-keygen or the anchor could not be used: as good as unsigned
        if not signed:
            self._catalog_failed("E-SIG-INVALID")
            return
        try:
            catalog = parse_catalog(data, "catalog-v1.yaml")
        except CatalogError:
            self._catalog_failed("CATALOG_INVALID")
            return
        self._catalog = catalog
        self._entry(outcome="loaded", note="catalog-v1.yaml")

    def _catalog_failed(self, reason: str) -> None:
        self._entry(outcome="refused", reason=reason, note="catalog-v1.yaml", alert=True)

    def _load_pricing(self) -> None:
        try:
            self.pricing = Pricing.load(read_capped(self._bucket, PRICING_OBJECT, MAX_FILE_BYTES))
        except Missing:
            self.pricing = None
        except (TooLarge, PricingError) as error:
            reason = "E-FILE-SIZE" if isinstance(error, TooLarge) else "PRICING_INVALID"
            self._entry(outcome="refused", reason=reason, note="pricing/models.yaml", alert=True)

    def _read_policy(self, agent: str) -> tuple[bytes, bytes | None]:
        name = f"policies/{agent}.md"
        data = read_capped(self._bucket, name, MAX_FILE_BYTES)
        try:
            sig: bytes | None = read_capped(self._bucket, name + ".sig", MAX_SIG_BYTES)
        except Missing:
            sig = None
        except TooLarge:
            sig = b"\x00" * (MAX_SIG_BYTES + 1)  # over the cap: verify refuses it unread
        return data, sig

    def _verify(
        self,
        agent: str,
        data: bytes,
        sig: bytes | None,
        anchor: Path,
        against: ActiveVersion | None,
    ) -> tuple[Policy | None, str | None]:
        assert self._catalog is not None
        policy, findings = verify(
            Path(f"policies/{agent}.md"),
            data,
            sig,
            anchor,
            against,
            lambda wrapper, who: self._control.wrapper_live(wrapper, who),
            self._folder_check,
            self._cfg,
            self._catalog,
            ssh_keygen=self._ssh_keygen,
            tmpdir=self._tmpdir,
        )
        if policy is None:
            return None, next(f.code for f in findings if f.severity == "error")
        return policy, None  # its agent is its file's name, or it is E-FILENAME

    def _load_one(self, agent: str, record: PolicyVersion, anchor: Path) -> _Outcome:
        current = self._active.get(agent)
        keep = current if current is not None else None
        try:
            data, sig = self._read_policy(agent)
        except (Missing, TooLarge) as error:
            return _Outcome(keep, _reason(error))
        if _sha256(data) != record.sha256:
            # Not the published file: verified against the record, never loaded.
            published = ActiveVersion(record.version, record.sha256)
            newer, failure = self._verify(agent, data, sig, anchor, published)
            if newer is not None:
                return _Outcome(keep)  # a publish in progress: it waits for its record
            return _Outcome(keep, failure)
        mark = self._store.get_active(agent)
        policy, failure = self._verify(agent, data, sig, anchor, mark)
        if policy is None:
            same = current is not None and current.sha256 == record.sha256
            return _Outcome(None if same else keep, failure)
        if policy.version != record.version:
            return _Outcome(keep, "E-VERSION-ORDER")
        return _Outcome(policy)

    # --- the audit log

    def _entry(
        self,
        *,
        outcome: str,
        agent: str | None = None,
        policy: Policy | None = None,
        reason: str | None = None,
        note: str | None = None,
        alert: bool = False,
    ) -> None:
        fields: dict[str, Any] = {
            "event": "policy_load",
            "actor": self._actor,
            "agent": agent,
            "outcome": outcome,
            "reason": reason,
            "policy_hash": None if policy is None else policy.sha256,
            "catalog_hash": None if self._catalog is None else self._catalog.sha256,
            "note": note,
            "alert": alert,
        }
        try:
            self._audit.write(AuditEntry(**fields))
        except AuditWriteFailed:
            if alert:
                fail_closed_line(
                    reason or "POLICY_LOAD",
                    run_id=None,
                    call_id=None,
                    agent=agent,
                    audit_write_failed=True,
                )


def _reason(error: Exception, *, signature: bool = False) -> str:
    """The audit reason of a failed read: too large, or missing."""
    if isinstance(error, TooLarge):
        return "E-SIG-INVALID" if signature else "E-FILE-SIZE"
    return "MISSING_OBJECT"
