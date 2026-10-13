"""Running the field, tool, limit and scope rules (validator-spec 3.3 to 3.5) on small texts.

`check(change)` writes `DATA` with `change(data)` applied (see tests/support/frontmatter.py), loads
it, and runs `build_policy` on it. What comes back is a `Run`: the policy, the findings of
`build_policy` only (the findings of `load` are not in it, so a case sees the rules and nothing
else), and the text, so that a test can find the line of a field by its content.
"""

from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any

from aiven.policy.catalog import Action, Catalog, load_catalog
from aiven.policy.config import PlatformConfig
from aiven.policy.findings import Finding
from aiven.policy.frontmatter import FIRST_LINE, load
from aiven.policy.model import Policy, build_policy
from tests.support import REPO_ROOT
from tests.support.frontmatter import edited, lookup
from tests.support.policies import BASE_PATH, platform_config, valid_base

WRAPPER_WARNING = "W-TOOL-NOT-LIVE"

CFG = platform_config()
CATALOG = load_catalog(REPO_ROOT / "catalog" / "catalog-v1.yaml")
BASE = valid_base()

# Lists of tools that are not settled (rulings R49 and R53): an entry that fails its own rules, an
# entry that is a placeholder, and no tool at all (a size that fails E-RANGE). Most of them have
# the tool sheets.read next to the odd entry, which is a tool that passes.
UNSETTLED_TOOLS = {
    "a name that is not in the catalog": ["sheets.read", "gmail.sned"],
    "a wildcard": ["sheets.read", "drive.*"],
    "a reserved name": ["sheets.read", "payments.pay"],
    "an R3 action": ["sheets.read", "drive.move"],
    "a placeholder": ["sheets.read", "TODO"],
    "only entries that fail": ["gmail.sned", "drive.move"],
    "no tool": [],
}


def catalog_with(*actions: Action, **status: str) -> Catalog:
    """The catalog with more actions, and with the status of some wrappers changed."""
    return replace(
        CATALOG,
        actions={**CATALOG.actions, **{action.id: action for action in actions}},
        wrapper_status={**CATALOG.wrapper_status, **status},
    )


@dataclass
class Run:
    """The result of `build_policy` on one front matter text."""

    front: str
    policy: Policy | None
    findings: list[Finding]

    def line(self, needle: str) -> int:
        """The file line of the one line of the front matter that holds `needle`."""
        rows = [
            number
            for number, row in enumerate(self.front.split("\n"), start=FIRST_LINE)
            if needle in row
        ]
        assert len(rows) == 1, f"{needle!r} must stand in exactly one line, found {len(rows)}"
        return rows[0]

    def entry(self, name: str, text: str) -> int:
        """The file line of the entry `text` of the list `name` (`tools`, `scope.email_to`).

        A name can stand in two lists (`drive.delete` is a tool here and an item of `forbidden`
        there), so the line is looked up inside the list.
        """
        key = name.rsplit(".", 1)[-1] + ":"
        rows = self.front.split("\n")
        start = next(n for n, row in enumerate(rows) if row.strip().split(" ")[0] == key)
        indent = len(rows[start]) - len(rows[start].lstrip())
        found = []
        for number in range(start + 1, len(rows)):
            row = rows[number]
            if row.strip() and len(row) - len(row.lstrip()) <= indent:
                break  # the list is over
            if row.strip() == f'- "{text}"':
                found.append(FIRST_LINE + number)
        assert len(found) == 1, f"{text!r} must stand once in {name}, found {len(found)}"
        return found[0]

    def seen(self, wrappers: bool) -> list[Finding]:
        return [f for f in self.findings if wrappers or f.code != WRAPPER_WARNING]

    def places(self, *, wrappers: bool = False) -> list[tuple[str, int | None]]:
        """(code, line) of the findings, in the order of the file and then of the code.

        The warnings about planned wrappers are left out unless `wrappers` is set: every policy
        that lists a Drive or Email tool has them today, and most tests are about something else.
        """
        found = ((f.code, f.line) for f in self.seen(wrappers))
        return sorted(found, key=lambda place: (place[1] or 0, place[0]))

    def codes(self, *, wrappers: bool = False) -> list[str]:
        return sorted(f.code for f in self.seen(wrappers))

    def lines_of(self, code: str) -> list[int | None]:
        """The lines of the findings with this code, in the order they were made."""
        return [f.line for f in self.findings if f.code == code]

    def only(self, code: str) -> Finding:
        """The one finding with this code."""
        (found,) = [f for f in self.findings if f.code == code]
        return found

    def params(self, code: str) -> dict[str, str]:
        return self.only(code).params


def run_front(
    front: str,
    *,
    cfg: PlatformConfig = CFG,
    catalog: Catalog = CATALOG,
    data: bytes = BASE,
) -> Run:
    """Load the front matter text and run `build_policy` on it."""
    loaded = load(front, BASE_PATH)
    policy, findings = build_policy(loaded, data, cfg, catalog, BASE_PATH)
    return Run(front, policy, findings)


def check(
    change: Callable[[dict[str, Any]], object] | None = None,
    *,
    cfg: PlatformConfig = CFG,
    catalog: Catalog = CATALOG,
) -> Run:
    """`DATA` with `change(data)` applied, written as front matter, and run through the rules."""
    return run_front(edited(change or (lambda data: None)), cfg=cfg, catalog=catalog)


def put(data: dict[str, Any], path: str, value: Any) -> None:
    """Set the field at a dotted path (`limits.runs_per_day`) of `data`."""
    *parents, name = path.split(".")
    lookup(data, parents)[name] = value


def setting(path: str, value: Any) -> Callable[[dict[str, Any]], None]:
    """A change for `check` that sets one field."""
    return lambda data: put(data, path, value)


def with_tools(*tools: str, **more: Any) -> Callable[[dict[str, Any]], None]:
    """A change for `check` that sets the tools, and any other top-level fields as keywords."""

    def change(data: dict[str, Any]) -> None:
        data["tools"] = list(tools)
        data.update(more)

    return change
