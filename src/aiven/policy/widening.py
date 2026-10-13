"""Widening (validator-spec section 3.6): what a new version allows that the previous one did not.

`widening(prev, new)` compares two policies of the same agent. It gives one string for each field
in which `new` gives the agent more room, in this order, and whether shadow mode starts again
(ruling R73: a field never gives more than one string, so that the list stays short):

1. the tools that `new` has and `prev` has not, in the order of `new`, each with a plus sign and
   separated by spaces: `tools: +<tool> +<tool>`;
2. a higher `max_class`: `max_class: R0 -> R1`;
3. each of `emails_per_day`, `records_per_run`, `max_runtime_s` and `runs_per_day` that rose, in
   that order: `limits.<name>: 10 -> 20`. The spend is not one of them: it must be 0
   (E-LIMIT-SPEND);
4. in the scope, in this order: a folder ID that is set and is not the old one
   (`scope.drive_folder_id: changed`), a folder path that is neither the old path nor a folder
   inside it (`scope.drive_folder_path: changed`), and the `email_to` entries that the old list
   does not allow, grouped like the tools (`scope.email_to: +<entry> +<entry>`). The old list
   allows the entries that it has, and each address `name@d` when it has `@d` (ruling R74): a
   domain entry allows the addresses of that exact domain, and none of a subdomain (section 3.3).
   A new domain entry is a widening, also when addresses in that domain were listed;
5. `untrusted_input` from `strict` to `taint`: `untrusted_input: strict -> taint`;
6. a lower `shadow.min_runs`: `shadow.min_runs: 10 -> 5`.

Narrowing is never listed. Shadow mode starts again exactly when a tool is added or `max_class`
rises (section 3.6). It then lasts `new.shadow_min_runs` runs, which the caller reads from `new`.

The policy of a file with errors is compared as it is. The classes that a policy may have are R0,
R1 and R2: R3 and R4 are E-MAX-CLASS-R3 and E-MAX-CLASS-R4 of their own file, and a placeholder is
E-PLACEHOLDER, so such a class is not ranked here. The other fields are compared whatever their
values are.

The strings are plain ASCII (`->`), and `check_set` joins them with `; ` for W-WIDENS. They hold
text from the file: tools, addresses and the numbers of limits. Each such value goes through
`content.safe_text` before it is grouped (ruling R77), so one that the guard would hide, a
credential, a bank detail or an ID number, shows as `[hidden]` in its own place. Without that the
`Finding` that quotes the joined list hides the whole of it when a single entry looks like one, and
the tool and the limit next to a BSN-shaped address are lost with it. The `Finding` still judges
the list as a whole, and shows up to 2,000 characters of it.
"""

from aiven.policy.constants import POLICY_CLASSES
from aiven.policy.content import safe_text
from aiven.policy.model import Policy

# The limits that widening looks at, in the order of the file. The spend is not one of them.
_LIMITS = ("emails_per_day", "records_per_run", "max_runtime_s", "runs_per_day")


def widening(prev: Policy, new: Policy) -> tuple[list[str], bool]:
    """The changes that give the agent more room in `new`, and whether shadow mode starts again."""
    added = [tool for tool in new.tools if tool not in prev.tools]
    raised = _raised(prev.max_class, new.max_class)
    changes = [_grouped("tools", added)] if added else []
    if raised:
        changes.append(f"max_class: {prev.max_class} -> {new.max_class}")
    changes += _limits(prev, new)
    changes += _scope(prev, new)
    if prev.untrusted_input == "strict" and new.untrusted_input == "taint":
        changes.append("untrusted_input: strict -> taint")
    if new.shadow_min_runs < prev.shadow_min_runs:
        changes.append(
            f"shadow.min_runs: {_shown(prev.shadow_min_runs)} -> {_shown(new.shadow_min_runs)}"
        )
    return changes, bool(added) or raised


def _raised(old: str, new: str) -> bool:
    """Whether `new` is a higher class than `old`, where R0 < R1 < R2.

    Only the classes that a policy may have are ranked: with any other class on either side (R3,
    R4, a placeholder) nothing is raised, because that file has its own code for it.
    """
    return (
        old in POLICY_CLASSES
        and new in POLICY_CLASSES
        and POLICY_CLASSES.index(new) > POLICY_CLASSES.index(old)
    )


def _limits(prev: Policy, new: Policy) -> list[str]:
    changes = []
    for name in _LIMITS:
        old, now = getattr(prev.limits, name), getattr(new.limits, name)
        if now > old:
            changes.append(f"limits.{name}: {_shown(old)} -> {_shown(now)}")
    return changes


def _scope(prev: Policy, new: Policy) -> list[str]:
    old, now = prev.scope, new.scope
    changes = []
    if now.drive_folder_id is not None and now.drive_folder_id != old.drive_folder_id:
        changes.append("scope.drive_folder_id: changed")
    path = now.drive_folder_path
    if path is not None and not _inside(path, old.drive_folder_path):
        changes.append("scope.drive_folder_path: changed")
    added = [
        entry
        for entry in now.email_to
        if entry not in old.email_to and not _domain_listed(entry, old.email_to)
    ]
    if added:
        changes.append(_grouped("scope.email_to", added))
    return changes


def _domain_listed(entry: str, listed: tuple[str, ...]) -> bool:
    """Whether the list has the domain entry `@d` for the entry, an address `name@d`.

    The domain is what follows the first `@`, as `limits_scope` reads an entry, so an odd entry
    (`a@b@d`) is judged by the longer domain, and is more likely to be listed as new. An entry
    with no `@` has no domain. A domain entry `@d` is only allowed by having `@d` itself, and
    addresses in `d` do not make it so.
    """
    _, at, domain = entry.partition("@")
    return bool(at) and f"@{domain}" in listed


def _grouped(field: str, added: list[str]) -> str:
    """The string of one field that gains entries: `tools: +a +b`."""
    return f"{field}: " + " ".join(f"+{_shown(entry)}" for entry in added)


def _shown(value: object) -> str:
    """A value of the file as the list shows it, cleaned by the guard: `[hidden]` if it must be."""
    return safe_text(str(value))


def _inside(path: str, root: str | None) -> bool:
    """Whether `path` is the Drive path `root` or a folder inside it.

    The parts of a path are whole folders, joined by ` / ` (section 3.3): `Invoices-old` is not
    inside `Invoices`.
    """
    return root is not None and (path == root or path.startswith(f"{root} / "))
