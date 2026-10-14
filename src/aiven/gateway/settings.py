"""The gateway's settings, from its environment, and its assembly (plan Task 3.10).

Terraform sets these on the Cloud Run service (modules/gateway/run.tf). Each is checked: a missing
or malformed setting stops the start, naming the setting (never its value's neighbours).

    GATEWAY_URL        the service's own URL: the audience of every ID token (https only)
    GATEWAY_PROJECT    the gateway project: Firestore `gateway`
    CONTROL_PROJECT    the control project: Firestore `control` and `releases`, the audit log
    AGENTS_PROJECT     the project in every policy's principal
    POLICY_BUCKET      <control>-policies
    SNAPSHOT_BUCKET    <control>-snapshots (for the wrappers' snapshots, M4)
    GATEWAY_PRINCIPAL  the gateway's own service account
    CONTROL_UI_EMAIL   the control UI's service account: the control API's only caller
    TRUSTED_AUTHORS    comma-separated AIVEN addresses (taint rules)
    SANDBOX_DRIVE_ID   the Sandbox drive (may be empty until it exists)
"""

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol

from aiven.policy.config import DRIVE_ID_RE, PROJECT_ID_RE, SERVICE_ACCOUNT_RE, PlatformConfig

_URL = re.compile(r"https://[a-z0-9.-]+(:[0-9]+)?")
_BUCKET = re.compile(r"[a-z0-9][a-z0-9._-]{1,61}[a-z0-9]")
_EMAIL = re.compile(r"[^@\s,]+@[a-z0-9.-]+\.[a-z]{2,}")


class SettingsError(ValueError):
    """A setting is missing or wrong. The message names the setting."""


def _get(env: Mapping[str, str], name: str, pattern: re.Pattern[str]) -> str:
    value = env.get(name, "")
    if not value:
        raise SettingsError(f"{name} is not set")
    if not pattern.fullmatch(value):
        raise SettingsError(f"{name} is not of the right form")
    return value


@dataclass(frozen=True)
class Settings:
    audience: str
    gateway_project: str
    control_project: str
    policy_bucket: str
    snapshot_bucket: str
    control_ui: str
    cfg: PlatformConfig

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> "Settings":
        authors = tuple(a for a in env.get("TRUSTED_AUTHORS", "").split(",") if a)
        if not authors or not all(_EMAIL.fullmatch(a) for a in authors):
            raise SettingsError("TRUSTED_AUTHORS must list AIVEN addresses")
        drive = env.get("SANDBOX_DRIVE_ID", "")
        if drive and not DRIVE_ID_RE.fullmatch(drive):
            raise SettingsError("SANDBOX_DRIVE_ID is not of the right form")
        return cls(
            audience=_get(env, "GATEWAY_URL", _URL),
            gateway_project=_get(env, "GATEWAY_PROJECT", PROJECT_ID_RE),
            control_project=_get(env, "CONTROL_PROJECT", PROJECT_ID_RE),
            policy_bucket=_get(env, "POLICY_BUCKET", _BUCKET),
            snapshot_bucket=_get(env, "SNAPSHOT_BUCKET", _BUCKET),
            control_ui=_get(env, "CONTROL_UI_EMAIL", SERVICE_ACCOUNT_RE),
            cfg=PlatformConfig(
                agents_project=_get(env, "AGENTS_PROJECT", PROJECT_ID_RE),
                trusted_authors=authors,
                gateway_principal=_get(env, "GATEWAY_PRINCIPAL", SERVICE_ACCOUNT_RE),
                sandbox_drive_id=drive or None,
            ),
        )


class Clients(Protocol):
    def firestore(self, project: str, database: str) -> Any: ...

    def bucket(self, project: str, name: str) -> Any: ...

    def audit(self, project: str) -> Any: ...


class GoogleClients:  # pragma: no cover - the real Google clients
    """The clients of the deployment, as the gateway's own service account. No key."""

    def firestore(self, project: str, database: str) -> Any:
        from google.cloud import firestore

        return firestore.Client(project=project, database=database)

    def bucket(self, project: str, name: str) -> Any:
        from google.cloud import storage

        return storage.Client(project=project).bucket(name)

    def audit(self, project: str) -> Any:
        from aiven.common.audit import AuditLog

        return AuditLog(project)


def build(
    env: Mapping[str, str],
    *,
    clients: Clients | None = None,
    check_ssh_keygen: Callable[[str], None] | None = None,
) -> Any:
    """The gateway's ASGI app, its registry started. Raises SettingsError or StartupRefused."""
    from aiven.gateway.app import create_app
    from aiven.gateway.auth import GoogleTokenVerifier
    from aiven.gateway.control import FirestoreControl
    from aiven.gateway.pipeline import Gateway
    from aiven.gateway.policies import PolicyRegistry
    from aiven.gateway.startup import check_ssh_keygen as default_check
    from aiven.gateway.startup import minimal_path, private_tmpdir
    from aiven.gateway.store_firestore import FirestoreStore

    settings = Settings.from_env(env)
    clients = clients or GoogleClients()
    minimal_path()
    store = FirestoreStore(clients.firestore(settings.gateway_project, "gateway"))
    control = FirestoreControl(
        clients.firestore(settings.control_project, "control"),
        clients.firestore(settings.control_project, "releases"),
    )
    audit = clients.audit(settings.control_project)
    registry = PolicyRegistry(
        bucket=clients.bucket(settings.control_project, settings.policy_bucket),
        control=control,
        store=store,
        audit=audit,
        cfg=settings.cfg,
        # No Drive wrapper in M3: a folder cannot be vouched for, so a scope fails closed.
        folder_check=lambda folder_id, folder_path: False,
        tmpdir=private_tmpdir(),
        check_ssh_keygen=check_ssh_keygen or default_check,
        actor=settings.cfg.gateway_principal,
    )
    registry.start(datetime.now(UTC))
    gateway = Gateway(store=store, control=control, audit=audit, policies=registry, wrappers={})
    return create_app(
        gateway,
        verifier=GoogleTokenVerifier(),
        audience=settings.audience,
        control_ui=settings.control_ui,
    )
