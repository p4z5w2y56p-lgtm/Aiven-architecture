"""Control reads and the fail-closed line (plan Task 3.4; gateway-design sections 5, 6, 8 and 10).

`FirestoreControl` reads the control project on every call, directly (Cloud Run gives an idle
instance no CPU, so no listener; section 8):

- Firestore `control`: `killswitch/global`, `killswitch_agents/{agent}`, `wrappers/{name}`,
  `decisions/{confirm_id}`, `signoffs/{agent}`, `taint_clears/{file_id}`;
- Firestore `releases`: `policy_versions/{agent}`, the published version of each agent (M3 flag #1,
  spec change 1). Matthijs's `aiven-policy publish` writes it; the gateway only reads it.

A switch without a document is off, and a wrapper without one is switched on for nobody: the
control UI writes them, and before it does nothing is on. Anything else that is not exactly the
shape of section 5 is `ControlUnavailable`, like any error of Firestore: the gateway then refuses
the call with CONTROL_UNREACHABLE (fail closed). The error's message never travels: it can hold a
path or a value, so only its class is named.

`fail_closed_line` is the fallback of section 10 (M3 plan, "CONTROL_UNREACHABLE when the audit log
fails too"): one JSON line on stdout, which Cloud Run keeps in the gateway project's own log, with
IDs only. An alert policy matches it, so a fail-closed refusal alerts even when control's audit log
cannot be written.
"""

import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal, Protocol, TypeVar

from aiven.gateway.decide import ControlSnapshot
from aiven.gateway.types import CLASSES, Class
from aiven.policy.constants import AGENT_ID_PATTERN
from aiven.policy.content import safe_text

_SHA256 = re.compile(r"sha256:[0-9a-f]{64}")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_LINE_VALUE_CHARS = 120

T = TypeVar("T")


class ControlUnavailable(Exception):
    """Control could not be read, or held what it may not. The message names the class only."""


@dataclass(frozen=True)
class PolicyVersion:
    """`policy_versions/{agent}` in `releases`: the version Matthijs published, and its hash."""

    version: int
    sha256: str
    by: str
    at: datetime


@dataclass(frozen=True)
class ControlDecision:
    """`decisions/{confirm_id}`: Matthijs's answer to a queued R2 (section 7)."""

    decision: Literal["approve", "reject"]
    preview_sha256: str
    by: str
    at: datetime


@dataclass(frozen=True)
class Signoff:
    """`signoffs/{agent}`: the capability that shadow mode signed off (section 5)."""

    tools: tuple[str, ...]
    max_class: Class
    policy_hash: str
    shadow_runs_seen: int
    by: str
    at: datetime


class ControlReader(Protocol):
    """What the gateway reads in control. Every method raises ControlUnavailable on any error."""

    def read(self, agent: str, wrapper: str | None) -> ControlSnapshot: ...

    def wrapper_live(self, wrapper: str, agent: str) -> bool: ...

    def policy_version(self, agent: str) -> PolicyVersion | None: ...

    def policy_versions(self) -> dict[str, PolicyVersion]: ...

    def decision(self, confirm_id: str) -> ControlDecision | None: ...

    def signoff(self, agent: str) -> Signoff | None: ...

    def taint_cleared(self, file_id: str, revision: str) -> bool: ...


def _shape(ok: bool) -> None:
    if not ok:
        raise ValueError("a control document of the wrong shape")


def _is_int(value: object) -> bool:
    return type(value) is int


def _strings(value: object) -> tuple[str, ...]:
    _shape(isinstance(value, list) and all(isinstance(item, str) for item in value))
    return tuple(value)  # type: ignore[arg-type]


def _version(doc: dict[str, Any]) -> PolicyVersion:
    version, sha256 = doc.get("version"), doc.get("sha256")
    _shape(_is_int(version) and version >= 1)  # type: ignore[operator]
    _shape(isinstance(sha256, str) and _SHA256.fullmatch(sha256) is not None)
    _shape(isinstance(doc.get("by"), str) and isinstance(doc.get("at"), datetime))
    return PolicyVersion(version, sha256, doc["by"], doc["at"])  # type: ignore[arg-type]


class FirestoreControl:
    """The control project's Firestore databases `control` and `releases`, read by the gateway."""

    def __init__(self, control: Any, releases: Any) -> None:
        self._control = control
        self._releases = releases

    @staticmethod
    def _guarded(read: Callable[[], T]) -> T:
        try:
            return read()
        except Exception as error:
            raise ControlUnavailable(
                f"control could not be read ({type(error).__name__})"
            ) from error

    @staticmethod
    def _get(client: Any, collection: str, doc_id: str) -> dict[str, Any] | None:
        snapshot = client.collection(collection).document(doc_id).get()
        return snapshot.to_dict() if snapshot.exists else None

    def _switch(self, collection: str, doc_id: str) -> bool:
        doc = self._get(self._control, collection, doc_id)
        if doc is None:
            return False
        _shape(isinstance(doc.get("on"), bool))
        return doc["on"]

    def _enabled_for(self, wrapper: str) -> tuple[str, ...]:
        doc = self._get(self._control, "wrappers", wrapper)
        return () if doc is None else _strings(doc.get("enabled_for"))

    def read(self, agent: str, wrapper: str | None) -> ControlSnapshot:
        def read() -> ControlSnapshot:
            enabled = wrapper is not None and agent in self._enabled_for(wrapper)
            return ControlSnapshot(
                kill_global=self._switch("killswitch", "global"),
                kill_agent=self._switch("killswitch_agents", agent),
                wrapper_enabled=enabled,
            )

        return self._guarded(read)

    def wrapper_live(self, wrapper: str, agent: str) -> bool:
        return self._guarded(lambda: agent in self._enabled_for(wrapper))

    def policy_version(self, agent: str) -> PolicyVersion | None:
        def read() -> PolicyVersion | None:
            doc = self._get(self._releases, "policy_versions", agent)
            return None if doc is None else _version(doc)

        return self._guarded(read)

    def policy_versions(self) -> dict[str, PolicyVersion]:
        def read() -> dict[str, PolicyVersion]:
            stream = self._releases.collection("policy_versions").stream()
            return {snapshot.id: _version(snapshot.to_dict()) for snapshot in stream}

        return self._guarded(read)

    def decision(self, confirm_id: str) -> ControlDecision | None:
        def read() -> ControlDecision | None:
            doc = self._get(self._control, "decisions", confirm_id)
            if doc is None:
                return None
            _shape(doc.get("decision") in ("approve", "reject"))
            preview = doc.get("preview_sha256")
            _shape(isinstance(preview, str) and _HEX64.fullmatch(preview) is not None)
            _shape(isinstance(doc.get("by"), str) and isinstance(doc.get("at"), datetime))
            return ControlDecision(doc["decision"], preview, doc["by"], doc["at"])  # type: ignore[arg-type]

        return self._guarded(read)

    def signoff(self, agent: str) -> Signoff | None:
        def read() -> Signoff | None:
            doc = self._get(self._control, "signoffs", agent)
            if doc is None:
                return None
            tools = _strings(doc.get("tools"))
            _shape(doc.get("max_class") in CLASSES)
            _shape(isinstance(doc.get("policy_hash"), str))
            _shape(_is_int(doc.get("shadow_runs_seen")))
            _shape(isinstance(doc.get("by"), str) and isinstance(doc.get("at"), datetime))
            return Signoff(
                tools,
                doc["max_class"],
                doc["policy_hash"],
                doc["shadow_runs_seen"],
                doc["by"],
                doc["at"],
            )

        return self._guarded(read)

    def taint_cleared(self, file_id: str, revision: str) -> bool:
        def read() -> bool:
            doc = self._get(self._control, "taint_clears", file_id)
            if doc is None:
                return False
            _shape(isinstance(doc.get("revision"), str))
            return doc["revision"] == revision

        return self._guarded(read)


# The gateway's own IDs and codes, shown as they are: safe_text may take a run of hex digits for a
# digest and hide it, and the line is no use without them. Anything else goes through safe_text.
_OWN = re.compile(rf"[rcq]_[0-9a-f]{{20,40}}|[A-Z][A-Z0-9_]{{0,39}}|{AGENT_ID_PATTERN}")


def _shown(value: str | None) -> str | None:
    if value is None:
        return None
    if len(value) <= 40 and _OWN.fullmatch(value):
        return value
    shown = safe_text(str(value))
    return shown[:_LINE_VALUE_CHARS]


def fail_closed_line(
    reason: str,
    *,
    run_id: str | None,
    call_id: str | None,
    agent: str | None,
    audit_write_failed: bool,
) -> None:
    """Print the fallback line of a fail-closed refusal on stdout (section 10). IDs only."""
    line = {
        "severity": "ALERT",
        "message": "gateway fails closed",
        "reason": _shown(reason),
        "alert": True,
        "audit_write_failed": audit_write_failed,
        "run_id": _shown(run_id),
        "call_id": _shown(call_id),
        "agent": _shown(agent),
    }
    print(json.dumps(line), flush=True)
