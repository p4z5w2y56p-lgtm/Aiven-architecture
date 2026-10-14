"""The signed policy registry (plan Task 3.5; validator-spec 2, 3.10; M3 flags #1 to #4).

The registry loads the catalog, the policies and the price list from the policy bucket in control.
It parses nothing that Matthijs did not sign, reads no object past its cap, verifies with the
pinned ssh-keygen, and loads a policy only when its version and hash equal the record Matthijs
published in `releases` (and are not below the gateway's own high-water mark). These tests sign
with throwaway keys (tests/support/signing.py) and serve the files from a fake bucket.
"""

import os
import stat
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from aiven.gateway.bucket_io import Missing, TooLarge, read_capped
from aiven.gateway.control import PolicyVersion
from aiven.gateway.policies import CATALOG_OBJECT, PolicyRegistry, StartupRefused
from aiven.gateway.startup import UnsafeSshKeygen, check_ssh_keygen, private_tmpdir
from aiven.policy.constants import MAX_FILE_BYTES, MAX_SIG_BYTES
from aiven.policy.verify import ActiveVersion
from tests.gateway.fakes import FakeAudit, FakeBucket, FakeControl, FakeStore
from tests.support import REPO_ROOT
from tests.support.policies import platform_config
from tests.support.rules import setting, with_tools
from tests.support.signing import Signer, make_signer
from tests.support.signing import work_in_a_temporary_folder as work_in_a_temporary_folder
from tests.support.variants import principal_of, variant_file

T0 = datetime(2026, 10, 14, 9, 0, tzinfo=UTC)
AGENT = "invoice-reminder"
PRINCIPAL = "agent-invoice-reminder@aiven-agents-test.iam.gserviceaccount.com"
POLICY_OBJECT = f"policies/{AGENT}.md"
BUILT_CATALOG = (
    (REPO_ROOT / "catalog" / "catalog-v1.yaml")
    .read_bytes()
    .replace(
        b"wrappers: {drive: planned, email: planned, agentbuilder: planned}",
        b"wrappers: {drive: built, email: built, agentbuilder: planned}",
    )
)
assert b"drive: built" in BUILT_CATALOG

V1 = variant_file(render=True)
V2 = variant_file(setting("version", 2), render=True)
V3 = variant_file(setting("version", 3), render=True)


def sha(data: bytes) -> str:
    import hashlib

    return "sha256:" + hashlib.sha256(data).hexdigest()


class World:
    """A registry on a fake bucket, signed by "matthijs" under both namespaces."""

    def __init__(self, tmp_path: Path, *, catalog: bytes = BUILT_CATALOG):
        self.signer = make_signer(tmp_path / "keys", namespaces="aiven-policy-v1,aiven-catalog-v1")
        self.bucket = FakeBucket()
        self.bucket.put("allowed_signers", self.signer.allowed_signers.read_bytes())
        self.publish_catalog(catalog)
        self.control = FakeControl()
        self.control.enabled = {"drive": [AGENT], "email": [AGENT]}
        self.store = FakeStore()
        self.audit = FakeAudit()
        self.folder_checks: list[tuple[str, str | None]] = []
        self.now = T0
        self.tmp = private_tmpdir(tmp_path / "private")
        self.ssh_keygen = "ssh-keygen"
        self.ssh_keygen_check = lambda path: None

    def publish_catalog(self, data: bytes, namespace: str = "aiven-catalog-v1") -> None:
        self.bucket.put(CATALOG_OBJECT, data)
        self.bucket.put(CATALOG_OBJECT + ".sig", self.signer.sign(data, namespace=namespace))

    def upload(self, data: bytes, *, signer: Signer | None = None) -> None:
        self.bucket.put(POLICY_OBJECT, data)
        self.bucket.put(POLICY_OBJECT + ".sig", (signer or self.signer).sign(data))

    def record(self, data: bytes, version: int) -> None:
        self.control.versions[AGENT] = PolicyVersion(version, sha(data), "m", T0)

    def publish(self, data: bytes, version: int) -> None:
        self.upload(data)
        self.record(data, version)

    def folder_check(self, folder_id: str, path: str | None) -> bool:
        self.folder_checks.append((folder_id, path))
        return True

    def registry(self) -> PolicyRegistry:
        registry = PolicyRegistry(
            bucket=self.bucket,
            control=self.control,
            store=self.store,
            audit=self.audit,
            cfg=platform_config(),
            folder_check=self.folder_check,
            ssh_keygen=self.ssh_keygen,
            tmpdir=self.tmp,
            check_ssh_keygen=self.ssh_keygen_check,
        )
        registry.start(self.now)
        return registry

    def loads(self) -> list:
        return self.audit.of("policy_load")


@pytest.fixture
def world(tmp_path) -> World:
    return World(tmp_path)


def loaded_version(registry: PolicyRegistry) -> int | None:
    policy = registry.for_agent(AGENT)
    return None if policy is None else policy.version


# --- a clean load


def test_a_published_policy_loads(world):
    world.publish(V1, 1)
    registry = world.registry()
    policy = registry.for_principal(PRINCIPAL)
    assert policy is not None and policy.version == 1 and policy.sha256 == sha(V1)
    assert registry.for_principal("someone@else.iam.gserviceaccount.com") is None
    assert world.store.get_active(AGENT) == ActiveVersion(1, sha(V1))
    (entry,) = [each for each in world.loads() if each.agent == AGENT]
    assert entry.outcome == "loaded" and entry.policy_hash == sha(V1)
    assert entry.catalog_hash == sha(BUILT_CATALOG)


def test_audit_entry_carries_verified_catalog_hash(world):
    world.publish(V1, 1)
    registry = world.registry()
    assert registry.catalog.sha256 == sha(BUILT_CATALOG)
    assert all(each.catalog_hash == sha(BUILT_CATALOG) for each in world.loads())


# --- flag #2: the catalog


def test_unsigned_catalog_refuses_to_start(world):
    del world.bucket.objects[CATALOG_OBJECT + ".sig"]
    with pytest.raises(StartupRefused):
        world.registry()
    assert world.loads()[-1].alert is True


def test_missing_catalog_sig_refused(world):
    test_unsigned_catalog_refuses_to_start(world)


def test_one_byte_change_to_catalog_refused(world):
    world.publish_catalog(BUILT_CATALOG)
    world.bucket.put(CATALOG_OBJECT, BUILT_CATALOG + b" ")
    with pytest.raises(StartupRefused):
        world.registry()


def test_catalog_signed_with_policy_namespace_refused(world):
    world.publish_catalog(BUILT_CATALOG, namespace="aiven-policy-v1")
    with pytest.raises(StartupRefused):
        world.registry()


def test_no_policy_loads_without_a_valid_catalog(world):
    world.publish(V1, 1)
    registry = world.registry()
    world.bucket.put(CATALOG_OBJECT, BUILT_CATALOG + b"# tampered\n")
    world.now += timedelta(seconds=61)
    registry.refresh(world.now)
    # The verified catalog stays; the tampered one never replaces it, and Matthijs is alerted.
    assert registry.catalog.sha256 == sha(BUILT_CATALOG) and loaded_version(registry) == 1
    assert world.loads()[-1].alert is True and world.loads()[-1].reason == "E-SIG-INVALID"


def test_a_signed_catalog_that_is_not_valid_v1_refuses_to_start(world):
    world.publish_catalog(b"schema: aiven-catalog/v9\n")
    with pytest.raises(StartupRefused):
        world.registry()


# --- flag #1: the published version


def test_no_record_means_no_policy_not_a_new_agent(world):
    world.upload(V1)  # in the bucket, never published
    registry = world.registry()
    assert registry.for_agent(AGENT) is None
    assert world.store.get_active(AGENT) is None


def test_record_read_failure_refuses_and_alerts(world):
    world.publish(V1, 1)
    world.control.down = True
    registry = world.registry()
    assert registry.for_agent(AGENT) is None
    assert world.loads()[-1].alert is True and world.loads()[-1].reason == "CONTROL_UNREACHABLE"


def test_older_signed_version_refused_after_restart(world):
    # A fresh registry and an empty working store: the record says v3, the bucket holds v2.
    world.upload(V2)
    world.control.versions[AGENT] = PolicyVersion(3, sha(V3), "m", T0)
    registry = world.registry()
    assert registry.for_agent(AGENT) is None
    entry = world.loads()[-1]
    assert entry.alert is True and entry.reason == "E-VERSION-ORDER"


def test_older_version_refused_and_alerts(world):
    # AT-SELF-6: an older signed version with more tools is uploaded after v2 is active.
    world.publish(V2, 2)
    registry = world.registry()
    wider_v1 = variant_file(with_tools("sheets.read", "gmail.draft", "gmail.send", "drive.read"),
                            render=True)  # fmt: skip
    world.upload(wider_v1)
    world.now += timedelta(seconds=61)
    registry.refresh(world.now)
    assert loaded_version(registry) == 2
    assert world.loads()[-1].alert is True and world.loads()[-1].reason == "E-VERSION-ORDER"


def test_same_version_other_hash_refused(world):
    world.publish(V2, 2)
    registry = world.registry()
    other_v2 = variant_file(
        setting("version", 2), setting("limits.records_per_run", 9), render=True
    )
    world.upload(other_v2)
    world.now += timedelta(seconds=61)
    registry.refresh(world.now)
    assert registry.for_agent(AGENT).sha256 == sha(V2)
    assert world.loads()[-1].alert is True and world.loads()[-1].reason == "E-VERSION-ORDER"


def test_bucket_newer_than_record_not_loaded(world):
    # Between the upload and the record of a publish: the new file waits, quietly.
    world.publish(V1, 1)
    registry = world.registry()
    world.upload(V2)
    world.now += timedelta(seconds=61)
    alerts = len([each for each in world.loads() if each.alert])
    registry.refresh(world.now)
    assert loaded_version(registry) == 1
    assert len([each for each in world.loads() if each.alert]) == alerts
    world.record(V2, 2)
    world.now += timedelta(seconds=61)
    registry.refresh(world.now)
    assert loaded_version(registry) == 2


def test_a_record_below_the_high_water_mark_is_refused(world):
    world.store.set_active(AGENT, ActiveVersion(3, sha(V3)))
    world.publish(V2, 2)  # the record went down: someone wrote it by hand
    assert world.registry().for_agent(AGENT) is None
    assert world.loads()[-1].reason == "E-VERSION-ORDER"


def test_a_withdrawn_record_unloads_the_agent(world):
    world.publish(V1, 1)
    registry = world.registry()
    del world.control.versions[AGENT]
    world.now += timedelta(seconds=61)
    registry.refresh(world.now)
    assert registry.for_agent(AGENT) is None


# --- AT-SELF-5 and keeping the active version


def test_tampered_file_keeps_active_and_alerts(world, tmp_path):
    world.publish(V1, 1)
    registry = world.registry()
    thief = make_signer(tmp_path / "thief")
    wider_v2 = variant_file(setting("version", 2), with_tools("sheets.read", "drive.read"),
                            render=True)  # fmt: skip
    world.upload(wider_v2, signer=thief)
    world.record(wider_v2, 2)  # stolen bucket and record access
    world.now += timedelta(seconds=61)
    registry.refresh(world.now)
    assert loaded_version(registry) == 1
    entry = world.loads()[-1]
    assert entry.alert is True and entry.reason == "E-SIG-INVALID"


def test_an_active_file_that_changes_stops_the_agent(world):
    # validator-spec 3.10: if the active version fails (its file changed), the agent is stopped.
    world.publish(V1, 1)
    registry = world.registry()
    world.control.enabled = {"drive": [AGENT], "email": []}  # its email tools are no longer live
    world.now += timedelta(seconds=61)
    registry.refresh(world.now)
    assert registry.for_agent(AGENT) is None
    entry = world.loads()[-1]
    assert (entry.outcome, entry.alert, entry.reason) == ("stopped", True, "E-TOOL-NOT-LIVE")


def test_gmail_policy_not_loaded_while_email_disabled(world):
    world.control.enabled = {"drive": [AGENT], "email": []}
    world.publish(V1, 1)  # the base has gmail.draft and gmail.send
    assert world.registry().for_agent(AGENT) is None
    assert world.loads()[-1].reason == "E-TOOL-NOT-LIVE"


def test_a_policy_with_another_agents_principal_is_refused_alone(world):
    # The validator ties a principal to its agent (E-PRINCIPAL): a second policy cannot take the
    # first one's principal, and the first one still loads.
    other = variant_file(setting("agent", "payment-nudge"), render=True)
    world.publish(V1, 1)
    world.bucket.put("policies/payment-nudge.md", other)
    world.bucket.put("policies/payment-nudge.md.sig", world.signer.sign(other))
    world.control.versions["payment-nudge"] = PolicyVersion(1, sha(other), "m", T0)
    registry = world.registry()
    assert registry.for_agent(AGENT) is not None and registry.for_agent("payment-nudge") is None
    assert [each.reason for each in world.loads() if each.agent == "payment-nudge"] == [
        "E-PRINCIPAL"
    ]


def test_two_verified_policies_with_one_principal_load_neither(world, monkeypatch):
    # 3.9 at load, as a backstop: if two verified policies ever shared a principal, neither loads.
    world.publish(V1, 1)
    world.control.versions["payment-nudge"] = PolicyVersion(1, sha(V1), "m", T0)
    world.bucket.put("policies/payment-nudge.md", V1)
    world.bucket.put("policies/payment-nudge.md.sig", world.signer.sign(V1))
    real = PolicyRegistry._verify

    def as_its_agent(self, agent, data, sig, anchor, against):
        policy, failure = real(self, AGENT, data, sig, anchor, against)
        return (None if policy is None else replace(policy, agent=agent)), failure

    monkeypatch.setattr(PolicyRegistry, "_verify", as_its_agent)
    registry = world.registry()
    assert registry.for_agent(AGENT) is None and registry.for_agent("payment-nudge") is None
    assert {each.reason for each in world.loads() if each.alert} == {"E-PRINCIPAL-DUPLICATE"}


def test_a_file_of_another_agent_under_this_name_is_refused(world):
    other = variant_file(
        setting("agent", "payment-nudge"), setting("principal", principal_of("payment-nudge")),
        render=True,
    )  # fmt: skip
    world.publish(other, 1)  # policies/invoice-reminder.md says it is payment-nudge
    registry = world.registry()
    assert registry.for_agent(AGENT) is None and registry.for_agent("payment-nudge") is None
    assert world.loads()[-1].reason == "E-FILENAME"


@pytest.mark.parametrize("real_path_matches", [True, False])
def test_folder_path_with_slash_in_name_verifies_by_id(world, real_path_matches):
    # "Invoices / 2026" may be one folder whose name holds " / ", or two folders. The registry
    # never looks a folder up by name: it gives the Drive side the folder's ID and the path as
    # written, and the ID's real ancestry decides (drive-wrapper 2; M4 resolves it).
    path = "AIVEN Architecture Sandbox / Invoices / 2026"
    data = variant_file(setting("scope.drive_folder_path", path), render=True)
    world.publish(data, 1)
    world.folder_check = lambda folder_id, written: (
        world.folder_checks.append((folder_id, written)) or real_path_matches
    )
    registry = world.registry()
    assert world.folder_checks == [("1aBcDeFgHiJkLmNoPqRsTuVwXyZ012345", path)]
    assert (registry.for_agent(AGENT) is not None) is real_path_matches
    if not real_path_matches:
        assert world.loads()[-1].reason == "E-SCOPE-NOT-IN-SANDBOX"


# --- the 60 s refresh


def test_refresh_waits_60s(world):
    world.publish(V1, 1)
    registry = world.registry()
    world.publish(V2, 2)
    world.now += timedelta(seconds=59)
    registry.refresh(world.now)
    assert loaded_version(registry) == 1
    world.now += timedelta(seconds=2)
    registry.refresh(world.now)
    assert loaded_version(registry) == 2


def test_a_forced_reload_does_not_wait(world):
    world.publish(V1, 1)
    registry = world.registry()
    world.publish(V2, 2)
    registry.refresh(world.now, force=True)
    assert loaded_version(registry) == 2


def test_an_unchanged_reload_writes_no_entry(world):
    world.publish(V1, 1)
    registry = world.registry()
    before = len(world.loads())
    for _ in range(3):
        world.now += timedelta(seconds=61)
        registry.refresh(world.now)
    assert len(world.loads()) == before


# --- the price list


def test_the_price_list_is_loaded_and_a_bad_one_keeps_the_last(world):
    prices = b"schema: aiven-pricing/v1\ncurrency: EUR\nmodels: {m: {input_per_million: '1', output_per_million: '1'}}\n"
    world.bucket.put("pricing/models.yaml", prices)
    registry = world.registry()
    assert "m" in registry.pricing.prices
    world.bucket.put("pricing/models.yaml", b"not: valid")
    world.now += timedelta(seconds=61)
    registry.refresh(world.now)
    assert "m" in registry.pricing.prices and world.loads()[-1].alert is True


def test_no_price_list_is_no_estimate(world):
    assert world.registry().pricing is None


# --- flag #3: every read is capped


def test_large_object_read_is_capped():
    bucket = FakeBucket()
    bucket.put_huge("big", 1 << 30)  # 1 GiB, said by its metadata
    with pytest.raises(TooLarge):
        read_capped(bucket, "big", MAX_FILE_BYTES)
    assert bucket.served == 0  # the metadata said enough


def test_metadata_size_over_cap_refused_without_reading():
    bucket = FakeBucket()
    bucket.put("f", b"x" * (MAX_FILE_BYTES + 1))
    with pytest.raises(TooLarge):
        read_capped(bucket, "f", MAX_FILE_BYTES)
    assert bucket.served == 0


def test_an_object_that_grew_after_its_metadata_is_read_to_the_cap_only():
    bucket = FakeBucket()
    bucket.metadata_lies["f"] = 10  # the metadata says 10 bytes; the object is 1 MiB
    bucket.put("f", b"x" * (1 << 20))
    with pytest.raises(TooLarge):
        read_capped(bucket, "f", MAX_FILE_BYTES)
    assert bucket.served == MAX_FILE_BYTES + 1


def test_a_missing_object_is_missing():
    with pytest.raises(Missing):
        read_capped(FakeBucket(), "nothing", 10)


def test_an_object_at_the_cap_is_read_whole():
    bucket = FakeBucket()
    bucket.put("f", b"x" * MAX_SIG_BYTES)
    assert len(read_capped(bucket, "f", MAX_SIG_BYTES)) == MAX_SIG_BYTES


@pytest.mark.parametrize(
    ("name", "cap"),
    [
        (POLICY_OBJECT + ".sig", MAX_SIG_BYTES),
        ("allowed_signers", MAX_FILE_BYTES),
        ("pricing/models.yaml", MAX_FILE_BYTES),
        (CATALOG_OBJECT + ".sig", MAX_SIG_BYTES),
    ],
)
def test_every_object_of_the_bucket_is_read_with_its_cap(world, name, cap):
    world.publish(V1, 1)
    world.bucket.put_huge(name, 1 << 30)
    try:
        world.registry()
    except StartupRefused:
        pass  # the catalog's signature, or the trust anchor, is needed to start
    assert world.bucket.served < 4 * MAX_FILE_BYTES  # nothing near the 1 GiB was read
    assert any(each.alert for each in world.loads())


# --- flag #4: the pinned ssh-keygen


def test_registry_uses_the_pinned_ssh_keygen(world, monkeypatch):
    import subprocess

    calls = []
    real = subprocess.run

    def spy(args, **kwargs):
        calls.append(args[0])
        return real(["ssh-keygen", *args[1:]], **kwargs)

    world.ssh_keygen = "/usr/bin/ssh-keygen"
    world.publish(V1, 1)
    monkeypatch.setattr(subprocess, "run", spy)
    world.registry()
    assert calls and set(calls) == {"/usr/bin/ssh-keygen"}


def test_missing_or_writable_ssh_keygen_loads_nothing_and_alerts(world):
    def unsafe(path):
        raise UnsafeSshKeygen("writable by others")

    world.ssh_keygen_check = unsafe
    world.publish(V1, 1)
    registry = world.registry()  # it starts, refuses everything, and alerts
    assert registry.for_agent(AGENT) is None
    assert world.loads()[-1].alert is True and world.loads()[-1].reason == "UNSAFE_SSH_KEYGEN"


def test_check_ssh_keygen_accepts_the_system_binary():
    if os.geteuid() == 0:
        with pytest.raises(UnsafeSshKeygen):  # root can write it: the gateway must not be root
            check_ssh_keygen("/usr/bin/ssh-keygen")
    else:
        check_ssh_keygen("/usr/bin/ssh-keygen")


def test_check_ssh_keygen_refuses_a_missing_file(tmp_path):
    with pytest.raises(UnsafeSshKeygen):
        check_ssh_keygen(str(tmp_path / "ssh-keygen"))


def test_check_ssh_keygen_refuses_a_file_others_can_write(tmp_path):
    binary = tmp_path / "ssh-keygen"
    binary.write_bytes(b"#!/bin/sh\n")
    binary.chmod(0o777)
    with pytest.raises(UnsafeSshKeygen):
        check_ssh_keygen(str(binary))


def test_check_ssh_keygen_refuses_a_symlink(tmp_path):
    link = tmp_path / "ssh-keygen"
    link.symlink_to("/usr/bin/ssh-keygen")
    with pytest.raises(UnsafeSshKeygen):
        check_ssh_keygen(str(link))


def test_the_private_folder_is_0700(tmp_path):
    folder = private_tmpdir(tmp_path / "p")
    assert stat.S_IMODE(folder.stat().st_mode) == 0o700


def test_policies_are_kept_by_their_principal_only(world):
    world.publish(V1, 1)
    registry = world.registry()
    assert replace(registry.for_agent(AGENT)).principal == PRINCIPAL


# --- the edges of loading


def test_a_record_whose_version_is_not_its_files_is_refused(world):
    world.upload(V1)
    world.control.versions[AGENT] = PolicyVersion(2, sha(V1), "m", T0)  # hash of v1, says v2
    assert world.registry().for_agent(AGENT) is None
    assert world.loads()[-1].reason == "E-VERSION-ORDER"


def test_a_published_file_that_is_gone_is_missing(world):
    world.record(V1, 1)
    assert world.registry().for_agent(AGENT) is None
    assert world.loads()[-1].reason == "MISSING_OBJECT"


def test_a_policy_without_its_signature_is_e_sig_missing(world):
    world.publish(V1, 1)
    del world.bucket.objects[POLICY_OBJECT + ".sig"]
    assert world.registry().for_agent(AGENT) is None
    assert world.loads()[-1].reason == "E-SIG-MISSING"


def test_a_policy_signature_over_its_cap_is_e_sig_invalid(world):
    world.publish(V1, 1)
    world.bucket.put_huge(POLICY_OBJECT + ".sig", 1 << 20)
    assert world.registry().for_agent(AGENT) is None
    assert world.loads()[-1].reason == "E-SIG-INVALID"
    assert world.bucket.served < 4 * MAX_FILE_BYTES


def test_an_ssh_keygen_that_cannot_run_signs_nothing(world):
    world.ssh_keygen = "/nonexistent/ssh-keygen"
    with pytest.raises(StartupRefused):
        world.registry()
    assert world.loads()[-1].reason == "E-SIG-INVALID"


def test_no_catalog_before_the_start(world):
    registry = PolicyRegistry(
        bucket=world.bucket, control=world.control, store=world.store, audit=world.audit,
        cfg=platform_config(), folder_check=world.folder_check, tmpdir=world.tmp,
    )  # fmt: skip
    with pytest.raises(StartupRefused):
        _ = registry.catalog


def test_an_unsafe_ssh_keygen_stops_every_reload(world):
    test_missing_or_writable_ssh_keygen_loads_nothing_and_alerts(world)
    world.bucket.served = 0
    registry = world.registry()
    registry.refresh(world.now + timedelta(hours=1), force=True)
    assert world.bucket.served == 0


def test_a_reload_while_another_one_runs_waits_for_nothing(world):
    world.publish(V1, 1)
    registry = world.registry()
    world.publish(V2, 2)
    registry._lock.acquire()
    try:
        registry.refresh(world.now, force=True)
    finally:
        registry._lock.release()
    assert loaded_version(registry) == 1


def test_an_alert_the_audit_log_will_not_take_prints_the_line(world, capsys):
    import json

    world.audit.fail_on = {"*"}
    del world.bucket.objects[CATALOG_OBJECT + ".sig"]
    with pytest.raises(StartupRefused):
        world.registry()
    line = json.loads(capsys.readouterr().out.splitlines()[-1])
    assert line["alert"] is True and line["audit_write_failed"] is True


def test_check_ssh_keygen_refuses_a_folder_others_can_write(tmp_path):
    folder = tmp_path / "open"
    folder.mkdir()
    folder.chmod(0o777)
    binary = folder / "ssh-keygen"
    binary.write_bytes(b"#!/bin/sh\n")
    binary.chmod(0o755)
    with pytest.raises(UnsafeSshKeygen):
        check_ssh_keygen(str(binary))


def test_check_ssh_keygen_passes_a_root_file_the_service_cannot_write(tmp_path, monkeypatch):
    if os.geteuid() != 0:
        pytest.skip("the files of this test must be root's")
    folder = tmp_path / "bin"
    folder.mkdir(mode=0o755)
    folder.chmod(0o755)
    binary = folder / "ssh-keygen"
    binary.write_bytes(b"#!/bin/sh\n")
    binary.chmod(0o755)
    monkeypatch.setattr(os, "access", lambda path, mode: False)  # as the non-root service user
    check_ssh_keygen(str(binary))


def test_a_private_folder_is_made_when_none_is_named():
    folder = private_tmpdir()
    try:
        assert stat.S_IMODE(folder.stat().st_mode) == 0o700
    finally:
        folder.rmdir()


def test_the_process_gets_the_systems_path_only(monkeypatch):
    from aiven.gateway.startup import minimal_path

    monkeypatch.setenv("PATH", "/home/someone/bin:/usr/bin")
    minimal_path()
    assert os.environ["PATH"] == "/usr/bin:/bin"


def test_an_entry_without_an_alert_that_the_log_will_not_take_prints_nothing(world, capsys):
    world.publish(V1, 1)
    world.audit.fail_on = {"*"}
    assert world.registry().for_agent(AGENT) is not None
    assert capsys.readouterr().out == ""
