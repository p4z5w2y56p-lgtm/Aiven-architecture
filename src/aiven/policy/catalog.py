"""The action catalog (validator-spec section 5), loaded from `catalog/catalog-v1.yaml`.

The catalog is owned by the gateway and is the only place where classes are defined: a policy
grants tools, but it can never set or lower a class. It is reviewed and signed like a policy, and
`Catalog.sha256` is the hash that goes on every log line next to the policy hash.

The catalog fails closed (ruling R94). Its reserved list must hold every entry of
`constants.RESERVED_NAMESPACES`, in any order, and it may hold more. A catalog that has lost an
entry would let a tool in that namespace be granted, so `load_catalog` refuses it.
"""

import hashlib
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, get_args

from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

from aiven.policy.constants import POLICY_CLASSES, RESERVED_NAMESPACES

CATALOG_SCHEMA = "aiven-catalog/v1"

ActionClass = Literal["R0", "R1", "R2", "R3", "R4"]
Wrapper = Literal["drive", "email", "agentbuilder"]
WrapperStatus = Literal["planned", "built"]

_CLASSES: tuple[str, ...] = get_args(ActionClass)
_WRAPPERS: tuple[str, ...] = get_args(Wrapper)
_STATUSES: tuple[str, ...] = get_args(WrapperStatus)

# Used with fullmatch: `$` would accept a trailing newline, and a YAML block scalar can end in one.
_ACTION_ID = re.compile(r"[a-z][a-z0-9]*\.[a-z][a-z0-9_]*")
_RESERVED_ENTRY = re.compile(r"[a-z][a-z0-9]*\.(\*|[a-z][a-z0-9_]*)")


class CatalogError(ValueError):
    """The catalog file is not a valid `aiven-catalog/v1` document."""


@dataclass(frozen=True)
class Action:
    """One catalog row. `escalates_when_shared`: an R1 action that becomes R2 on a shared file."""

    id: str
    cls: ActionClass
    wrapper: Wrapper
    undo: str | None = None
    escalates_when_shared: bool = False


@dataclass(frozen=True)
class Catalog:
    """The loaded catalog. The dict fields stay out of the hash, so a catalog can be a cache key."""

    actions: dict[str, Action] = field(hash=False)
    reserved: tuple[str, ...]
    wrapper_status: dict[str, WrapperStatus] = field(hash=False)
    sha256: str


def matches(pattern: str, action_id: str) -> bool:
    """Whether `pattern` covers `action_id`: the exact name, or `ns.*` for anything under `ns.`.

    Only a trailing `.*` is a wildcard; every other `*` is an ordinary character.
    """
    if pattern.endswith(".*"):
        return action_id.startswith(pattern[:-1])
    return pattern == action_id


def is_pattern(entry: str) -> bool:
    """Whether `entry` is an exact name (`drive.delete`) or a namespace wildcard (`payments.*`).

    That is the shape of an entry of the reserved list, and of an item in a policy's `forbidden`
    list. It says nothing about whether the catalog has anything that the entry matches.
    """
    return _RESERVED_ENTRY.fullmatch(entry) is not None


def load_catalog(path: Path) -> Catalog:
    """Read a catalog file. Raises CatalogError for unknown keys, classes or wrappers, for a
    reserved list that lacks an entry of the platform (ruling R94), and for anything else that is
    not valid catalog v1."""
    path = Path(path)
    raw = path.read_bytes()
    where = path.name
    try:
        doc = YAML(typ="safe").load(raw.decode("utf-8"))
    except (UnicodeDecodeError, YAMLError) as error:
        raise CatalogError(f"{where}: not valid UTF-8 YAML: {error}") from error
    top = _mapping(doc, where, required=("schema", "wrappers", "reserved", "actions"))
    if top["schema"] != CATALOG_SCHEMA:
        raise CatalogError(f"{where}: schema is {top['schema']!r}; expected {CATALOG_SCHEMA}")
    reserved = _reserved(top["reserved"], where)
    return Catalog(
        actions=_actions(top["actions"], where, reserved),
        reserved=reserved,
        wrapper_status=_wrapper_status(top["wrappers"], where),
        sha256="sha256:" + hashlib.sha256(raw).hexdigest(),
    )


def _mapping(
    value: object, where: str, *, required: Iterable[str], optional: Iterable[str] = ()
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CatalogError(f"{where}: must be a mapping")
    required, optional = tuple(required), tuple(optional)
    for key in value:
        if key not in (*required, *optional):
            raise CatalogError(f"{where}: unknown key {key!r}")
    for key in required:
        if key not in value:
            raise CatalogError(f"{where}: missing key {key!r}")
    return value


def _wrapper_status(value: object, where: str) -> dict[str, WrapperStatus]:
    here = f"{where}: wrappers"
    wrappers = _mapping(value, here, required=_WRAPPERS)
    for name, status in wrappers.items():
        if status not in _STATUSES:
            raise CatalogError(
                f"{here}.{name}: unknown status {status!r} (known: {', '.join(_STATUSES)})"
            )
    return {name: wrappers[name] for name in _WRAPPERS}


def _reserved(value: object, where: str) -> tuple[str, ...]:
    here = f"{where}: reserved"
    if not isinstance(value, list) or not value:
        raise CatalogError(f"{here}: must be a non-empty list")
    for entry in value:
        if not isinstance(entry, str) or not _RESERVED_ENTRY.fullmatch(entry):
            raise CatalogError(f"{here}: {entry!r} is neither an exact name nor namespace.*")
        if value.count(entry) > 1:
            raise CatalogError(f"{here}: {entry!r} is listed twice")
    lacking = [name for name in RESERVED_NAMESPACES if name not in value]
    if lacking:
        raise CatalogError(f"{here}: lacks {', '.join(lacking)} (the platform reserves them all)")
    return tuple(value)


def _actions(value: object, where: str, reserved: tuple[str, ...]) -> dict[str, Action]:
    here = f"{where}: actions"
    if not isinstance(value, dict) or not value:
        raise CatalogError(f"{here}: must be a non-empty mapping")
    actions: dict[str, Action] = {}
    for action_id, body in value.items():
        if not isinstance(action_id, str) or not _ACTION_ID.fullmatch(action_id):
            raise CatalogError(f"{here}: {action_id!r} is not a valid action id (namespace.name)")
        spot = f"{here}.{action_id}"
        row = _mapping(
            body, spot, required=("class", "wrapper"), optional=("undo", "escalates_when_shared")
        )
        cls, wrapper = row["class"], row["wrapper"]
        if cls not in _CLASSES:
            raise CatalogError(f"{spot}: unknown class {cls!r} (known: {', '.join(_CLASSES)})")
        if wrapper not in _WRAPPERS:
            raise CatalogError(
                f"{spot}: unknown wrapper {wrapper!r} (known: {', '.join(_WRAPPERS)})"
            )
        escalates = row.get("escalates_when_shared", False)
        if not isinstance(escalates, bool):
            raise CatalogError(f"{spot}: escalates_when_shared must be true or false")
        undo = row.get("undo")
        if cls in POLICY_CLASSES:
            if not isinstance(undo, str) or not undo.strip():
                raise CatalogError(f"{spot}: an {cls} action needs an undo text")
        elif undo is not None:
            raise CatalogError(f"{spot}: an {cls} action must not have an undo text")
        for pattern in reserved:
            if matches(pattern, action_id):
                raise CatalogError(f"{spot}: is in a reserved namespace ({pattern})")
        actions[action_id] = Action(action_id, cls, wrapper, undo, escalates)
    return actions
