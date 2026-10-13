"""The tool rules (validator-spec section 3.4): `tools`, `forbidden`, and what follows from them.

For each entry of `tools` the first rule it fails decides, and the rest are skipped for it
(ruling R32): a wildcard (E-TOOL-WILDCARD), then a reserved namespace or an R4 action (E-TOOL-R4,
never also E-TOOL-UNKNOWN), then a name that is not in the catalog (E-TOOL-UNKNOWN), then an R3
action (E-TOOL-R3). An entry that passes is an R0, R1 or R2 action of the catalog, and then three
things are judged independently: its class against `max_class` (E-TOOL-ABOVE-MAX-CLASS), the
`forbidden` list (E-TOOL-FORBIDDEN, one finding for the tool, with the first item that matches),
and its wrapper (W-TOOL-NOT-LIVE, when the catalog says the wrapper is planned).

An entry that failed a rule is not a tool. `check_tools` returns the ones that are, in the order of
the file, and the errors that depend on the tools (E-LIMIT-CONFLICT, E-SCOPE-MISSING) look only at
those (ruling R33). An entry that holds a placeholder skips its checks and is not a tool either.

The list is settled when every entry passed, none is a placeholder, and the number of entries is in
range. Until then it is not known which tools there will be, and a warning that guesses at them
would be wrong or would come from the error to fix first: W-LIMIT-UNUSED, W-SCOPE-UNUSED and
W-MAX-CLASS-SLACK are made only for a settled list (rulings R49 and R53).

An item of `forbidden` is an exact action name or `namespace.*` (E-FORBIDDEN-PATTERN), and it must
match something in the catalog or in the reserved list, or a typo would protect nothing
(E-FORBIDDEN-UNKNOWN); a bad pattern is not also unknown. A name inside a reserved namespace
(`payments.pay`) matches the reserved list (ruling R50). The four items of the baseline must be
there literally (E-FORBIDDEN-BASELINE, one finding for each that is missing).
"""

from dataclasses import dataclass

from aiven.policy.catalog import Action, Catalog, is_pattern, matches
from aiven.policy.constants import FORBIDDEN_BASELINE, POLICY_CLASSES, WRAPPER_NAMES
from aiven.policy.fields import Entry, Fields, size_finding
from aiven.policy.findings import Finding


@dataclass(frozen=True)
class Tools:
    """What the rules after `check_tools` need to know about the tools of a policy.

    `actions` are the entries that passed their rules, in the order of the file. The list is
    `settled` when nothing about it is left to guess (see the module docstring).
    """

    actions: tuple[Action, ...]
    settled: bool


def check_forbidden(fields: Fields, catalog: Catalog) -> tuple[list[Finding], list[str]]:
    """The findings about `forbidden`, and its items that forbid something (in file order).

    Those are the items of the right form (a placeholder is none, and a bad pattern forbids
    nothing). When the list has no value, load has reported that and there is nothing to add.
    """
    entries = fields.entries("forbidden")
    if entries is None:
        return [], []
    findings: list[Finding] = []
    patterns: list[str] = []
    for entry in entries:
        if entry.placeholder:
            continue
        if not is_pattern(entry.text):
            findings.append(fields.report("E-FORBIDDEN-PATTERN", entry.line, {"entry": entry.text}))
            continue
        patterns.append(entry.text)
        if not _matches_anything(entry.text, catalog):
            findings.append(fields.report("E-FORBIDDEN-UNKNOWN", entry.line, {"entry": entry.text}))
    listed = {entry.text for entry in entries}
    findings += [
        fields.report("E-FORBIDDEN-BASELINE", "forbidden", {"missing": item})
        for item in FORBIDDEN_BASELINE
        if item not in listed
    ]
    return findings, patterns


def _matches_anything(entry: str, catalog: Catalog) -> bool:
    """Whether the item matches an action of the catalog or an entry of the reserved list.

    A namespace item matches when any action or reserved entry lies in that namespace. An exact
    name matches an action, or a reserved entry that covers it (`payments.pay` lies under
    `payments.*`): the reserved list holds it, so it is no typo (ruling R50).
    """
    names = (*catalog.actions, *catalog.reserved)
    return any(matches(entry, name) for name in names) or any(
        matches(pattern, entry) for pattern in catalog.reserved
    )


def check_tools(
    fields: Fields, catalog: Catalog, max_class: str | None, forbidden: list[str]
) -> tuple[list[Finding], Tools | None]:
    """The findings about `tools`, and the tools themselves (None: the list has no value).

    `max_class` is the class that can be relied on (see `check_fields`), None to skip the rules
    that compare with it. `forbidden` are the items that forbid something (`check_forbidden`).
    """
    entries = fields.entries("tools")
    if entries is None:
        return [], None
    size = size_finding(fields, "tools")
    findings = [] if size is None else [size]
    settled = size is None
    actions: list[Action] = []
    for entry in entries:
        if entry.placeholder:
            settled = False
            continue
        problem = tool_problem(entry.text, catalog)
        if problem is not None:
            settled = False
            findings.append(fields.report(problem, entry.line, {"tool": entry.text}))
            continue
        action = catalog.actions[entry.text]
        actions.append(action)
        findings += _about_a_tool(fields, entry, action, catalog, max_class, forbidden)
    if settled:
        findings += _slack(fields, max_class, actions)
    return findings, Tools(tuple(actions), settled)


def tool_problem(tool: str, catalog: Catalog) -> str | None:
    """The code of the first rule that the tool fails (ruling R32), None if it passes them all.

    That is the test of whether an entry of `tools` is a tool (see the module docstring). The body
    checks ask it too, so that an entry that failed is not also called unexplained (ruling R33).
    """
    if "*" in tool:
        return "E-TOOL-WILDCARD"
    action = catalog.actions.get(tool)
    reserved = any(matches(pattern, tool) for pattern in catalog.reserved)
    if reserved or (action is not None and action.cls == "R4"):
        return "E-TOOL-R4"
    if action is None:
        return "E-TOOL-UNKNOWN"
    if action.cls == "R3":
        return "E-TOOL-R3"
    return None


def _about_a_tool(
    fields: Fields,
    entry: Entry,
    action: Action,
    catalog: Catalog,
    max_class: str | None,
    forbidden: list[str],
) -> list[Finding]:
    """The three things that an R0, R1 or R2 tool can be told, each independent of the others."""
    findings = []
    if max_class is not None and _rank(action.cls) > _rank(max_class):
        params = {"tool": action.id, "class": action.cls, "max": max_class}
        findings.append(fields.report("E-TOOL-ABOVE-MAX-CLASS", entry.line, params))
    pattern = next((item for item in forbidden if matches(item, action.id)), None)
    if pattern is not None:
        params = {"tool": action.id, "pattern": pattern}
        findings.append(fields.report("E-TOOL-FORBIDDEN", entry.line, params))
    if catalog.wrapper_status[action.wrapper] == "planned":
        params = {"tool": action.id, "wrapper": WRAPPER_NAMES[action.wrapper]}
        findings.append(fields.report("W-TOOL-NOT-LIVE", entry.line, params))
    return findings


def _slack(fields: Fields, max_class: str | None, actions: list[Action]) -> list[Finding]:
    """W-MAX-CLASS-SLACK: `max_class` is higher than the highest of the tools (a settled list).

    Not judged without a class that can be relied on, or without a tool to compare it with.
    """
    highest = max((action.cls for action in actions), key=_rank, default=None)
    if max_class is None or highest is None or _rank(max_class) <= _rank(highest):
        return []
    return [fields.report("W-MAX-CLASS-SLACK", "max_class", {"max": max_class, "highest": highest})]


def _rank(cls: str) -> int:
    """R0 < R1 < R2: the classes that a policy may use, in order."""
    return POLICY_CLASSES.index(cls)
