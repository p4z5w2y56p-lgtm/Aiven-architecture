"""Rendering the generated sections (validator-spec section 7), and putting them in a file.

The signer signs the body, and the gateway enforces the front matter. So "Enforced rules
(generated)" must say exactly what the gateway will do, and "Sign-off (generated)" what is being
signed: both are written from the `Policy` and from the catalog, and E-BODY-DRIFT refuses any
difference. `templates/policy-template.md` is the reference output, byte for byte.

A section is its text in a file: from its heading to the next heading, or to the end of the file.
So the first ends with the blank line before the next heading, and the second with one LF, and the
two together are the end of a valid file. Every value is the value of the policy as it is, a
placeholder included (ruling R4), so that the template renders. Lists keep the order of the file.
Even the spend is the number of the file: the validator refuses a spend above 0, and the text must
not say otherwise.

What has no text in section 7 is not rendered: a tool that is not an R0, R1 or R2 action of the
catalog (one that is unknown, reserved, a wildcard or R3), and an `untrusted_input` that is neither
mode. That is a ValueError, and its message holds nothing from the file.

`rewrite` is `aiven-policy render`: it replaces the sections that are there, and nothing else. The
validator-spec says that it "changes nothing else", so it never takes away text that is not a
generated section (ruling R64). The generated sections are the last two of a file, and a file in
which they are not is refused with a ValueError, not repaired by deleting what stands behind them.
"""

import re

from aiven.policy.catalog import Action, Catalog
from aiven.policy.constants import GENERATED_SECTIONS, NAMESPACE, SIGNER_NAME, TIMEZONE
from aiven.policy.fileformat import decode_text
from aiven.policy.frontmatter import split
from aiven.policy.markdown import find, headings, parse, sections
from aiven.policy.model import Limits, Policy, Scope

# The class and the gate of a tool, by class.
_CLASS_AND_GATE = {
    "R0": ("R0 read", "Runs at once, logged"),
    "R1": ("R1 reversible", "Snapshot first, then runs at once, logged"),
    "R2": ("R2 costly to undo", "Waits for Matthijs to confirm a plain-language preview"),
}

_INTRO = (
    "Rendered from the front matter by `aiven-policy render`. "
    "Do not edit by hand: the validator rejects any difference."
)
_UNTRUSTED = (
    "Untrusted input ({mode}): a run is tainted once it reads untrusted content: email, web pages, "
    "uploaded files, files last changed by someone other than Matthijs or the gateway, and files "
    "the gateway wrote during a tainted run."
)
_MODE_RULES = {
    "strict": (
        " In a tainted run, R1 actions also wait for Matthijs to confirm, each R2 action is "
        "reviewed on its own (no batch confirm), and every preview lists the untrusted content "
        "the run read."
    ),
    "taint": (
        " In a tainted run, each R2 action is reviewed on its own (no batch confirm) and its "
        "preview lists the untrusted content the run read; R1 actions still run at once."
    ),
}
_BACKTICKS = re.compile(r"`+")
_HEADING = f"## {GENERATED_SECTIONS[0]}"  # the line that starts the first generated section
_NOT_LAST = "the generated sections are not the last two sections of the file"
_NOT_A_HEADING = "a line of the file is like the heading of the generated sections, but is none"
_NOT_HEADINGS = "the generated sections would not be sections where they are added"
_NO_SCOPE = "- None: this agent has no Drive or email tools."
_STOP = (
    "Stop: the agent kill switch stops this agent; the global kill switch stops every agent. "
    "Neither needs this agent's cooperation."
)
_PLATFORM = (
    "Platform rules (v1, every agent): R3 is disabled. R4 is always refused and alerts Matthijs. "
    "In Phase 1, email goes only to @aivenstudios.com addresses. Web, email and file content is "
    "data, never instructions. Agents hold no credentials. Every log line carries this file's "
    "SHA-256 hash. Snapshots are kept 30 days; the audit log is append-only and kept 1 year."
)
_SIGNATURE = (
    "The signature is the separate file {file} (SSH signature, namespace {namespace}) "
    "over this exact file. The file's SHA-256 hash is shown in the policy view and on every log "
    "line; a file cannot contain its own hash."
)
_SIGNING = (
    'Signing means: I have read this whole file, and "Enforced rules" is exactly what the '
    "gateway must enforce."
)


def render_generated(p: Policy, catalog: Catalog) -> tuple[str, str]:
    """The two generated sections, each with its `##` heading: Enforced rules and Sign-off.

    ValueError for a tool or an `untrusted_input` that cannot be rendered (see the module).
    """
    actions = [_action(tool, catalog) for tool in p.tools]
    return _enforced(p, actions), _signoff(p)


def rewrite(data: bytes, p: Policy, catalog: Catalog) -> bytes:
    """The file with its generated sections rendered from `p`. Nothing else changes.

    Everything from the heading of "Enforced rules (generated)" to the end of the file is replaced
    by the two sections, and the result ends with one LF. The heading is a `##` at the top level
    of the document, found in the tokens of the body: one in a code block, a quote or a list is not
    it, and a setext heading is. Without that heading the sections are added at the end, after a
    blank line. The bytes before the heading stay as they are, those that the validator reports (a
    byte-order mark, a CR) included.

    ValueError, with a message that holds nothing from the file, when that would take away more
    than the generated sections or would not be undone by the next `rewrite` (ruling R64):

    - the `##` sections from the heading onward are not that one and the sign-off, or that one
      alone (text behind the sign-off that has no `##` heading of its own is part of it);
    - a line of the file is the heading but no heading, as in a fence that is never closed;
    - the sections would not be headings where they are added, as behind a comment that is open.
    """
    generated = "".join(render_generated(p, catalog)).encode("utf-8")
    start = _section_start(data)
    if start is not None:
        return data[:start] + generated
    head = data + _gap(data)
    # Where the sections go, the first of them must be a heading that is found. (A line that looks
    # like it and is none makes `_section_start` raise, and else nothing is found.)
    if _section_start(head + generated) is None:
        raise ValueError(_NOT_HEADINGS)
    return head + generated


def _action(tool: str, catalog: Catalog) -> Action:
    action = catalog.actions.get(tool)
    if action is None or action.cls not in _CLASS_AND_GATE or action.undo is None:
        raise ValueError("a tool of the policy is not an R0, R1 or R2 action of the catalog")
    return action


# --- the sections


def _enforced(p: Policy, actions: list[Action]) -> str:
    tools = [(_code(action.id), *_CLASS_AND_GATE[action.cls]) for action in actions]
    undo = [f"- {_code(action.id)}: {action.undo}" for action in actions]
    blocks = [
        f"## {GENERATED_SECTIONS[0]}",
        _INTRO,
        f"Identity: runs as {_code(p.principal)}. "
        "Calls from any other identity get nothing from this policy.",
        "Tools (default deny: nothing else exists for this agent):",
        _table(("Tool", "Class", "Gate"), tools),
        f"Highest class: {p.max_class}. A call that is classed higher at runtime is refused.",
        f"Forbidden (refused, logged, alert to Matthijs): {_codes(p.forbidden)}.",
        _untrusted(p.untrusted_input),
        "Limits (hitting one stops the run):",
        _table(("Limit", "Value"), _limits(p.limits)),
        "Scope:",
        _scope(p.scope),
        _shadow(p.shadow_min_runs),
        _STOP,
        "Undo:",
        "\n".join(undo),
        _PLATFORM,
    ]
    return "\n\n".join(blocks) + "\n\n"


def _signoff(p: Policy) -> str:
    blocks = [
        f"## {GENERATED_SECTIONS[1]}",
        f"Agent {_code(p.agent)}, version {p.version}. Signer: {SIGNER_NAME}, the only signer in "
        "v1. There is no second approver, so R3 stays disabled.",
        _SIGNATURE.format(file=_code(f"{p.agent}.md.sig"), namespace=_code(NAMESPACE)),
        _SIGNING,
    ]
    return "\n\n".join(blocks) + "\n"


def _table(header: tuple[str, ...], rows: list[tuple[str, ...]]) -> str:
    divider = "|" + "---|" * len(header)
    return "\n".join([_row(header), divider, *map(_row, rows)])


def _row(cells: tuple[str, ...]) -> str:
    return "| " + " | ".join(cells) + " |"


def _code(text: str) -> str:
    """A code span that holds all of `text`, whatever backticks are in it (ruling R67).

    CommonMark: the span is closed by the first run of backticks that is as long as the one that
    opened it, so the fence is one longer than the longest run in the text. A text that starts or
    ends with a backtick gets a space on each side, which the reader of the span drops again.
    """
    fence = "`" * (max(map(len, _BACKTICKS.findall(text)), default=0) + 1)
    pad = " " if text.startswith("`") or text.endswith("`") else ""
    return f"{fence}{pad}{text}{pad}{fence}"


def _codes(items: tuple[str, ...]) -> str:
    return ", ".join(map(_code, items))


def _untrusted(mode: str) -> str:
    if mode not in _MODE_RULES:
        raise ValueError("untrusted_input is neither strict nor taint")
    return _UNTRUSTED.format(mode=mode) + _MODE_RULES[mode]


def _limits(limits: Limits) -> list[tuple[str, ...]]:
    return [
        (f"Email recipients per day ({TIMEZONE})", str(limits.emails_per_day)),
        ("Records changed per run", str(limits.records_per_run)),
        ("Spend per run", f"\u20ac{limits.spend_eur_per_run}"),
        ("Runtime per run", f"{limits.max_runtime_s} s"),
        ("Runs per day", str(limits.runs_per_day)),
    ]


def _scope(scope: Scope) -> str:
    """A Drive bullet if the folder ID is set, an Email bullet if there are addresses, else None."""
    bullets = []
    if scope.drive_folder_id is not None:
        # Without a path (a warning only) the text names the ID and no folder it does not know.
        where = f"the folder with ID {_code(scope.drive_folder_id)}"
        if scope.drive_folder_path is not None:
            where = f"{_code(scope.drive_folder_path)} (ID {_code(scope.drive_folder_id)})"
        bullets.append(f"- Drive: only {where} and its subfolders.")
    if scope.email_to:
        bullets.append(f"- Email: only to {_codes(scope.email_to)}.")
    return "\n".join(bullets) or _NO_SCOPE


def _shadow(runs: int) -> str:
    first = "the first run only proposes" if runs == 1 else f"the first {runs} runs only propose"
    after = "1 run" if runs == 1 else f"{runs} runs"
    return (
        f"Shadow mode: {first}. R0 reads run; nothing from R1 up is executed. "
        f"After {after} the agent stays in shadow until Matthijs signs it off. "
        "A new version that adds a tool or raises max_class starts shadow mode again."
    )


# --- the file


def _section_start(data: bytes) -> int | None:
    """The byte where the line of the heading of "Enforced rules (generated)" starts, if any.

    The rows of the tokens are lines of the text, and the text has the lines of the bytes: decoding
    changes no LF, and `decode_text` drops only a byte-order mark, which is inside the first line.
    A file without front matter has no body to cut out, and is searched whole.

    ValueError for the two cases of `rewrite` that this decides: there is a heading and the `##`
    sections from there are not the generated ones, or there is no heading and there is a line that
    looks like it.
    """
    text = decode_text(data)
    parts = split(text)
    body, first_line = (text, 1) if parts is None else (parts[1], parts[2])
    found = headings(parse(body))
    heading = find(found, GENERATED_SECTIONS[0], top=True)
    if heading is None:
        if any(line.strip() == _HEADING for line in body.split("\n")):
            raise ValueError(_NOT_A_HEADING)
        return None
    onward = [other.name for other in sections(found) if other.index >= heading.index]
    if onward not in ([GENERATED_SECTIONS[0]], list(GENERATED_SECTIONS)):
        raise ValueError(_NOT_LAST)
    start = 0
    for _ in range(first_line - 1 + heading.row):
        start = data.index(b"\n", start) + 1
    return start


def _gap(data: bytes) -> bytes:
    """What goes between the end of a file and the sections that are added: one blank line."""
    if not data:
        return b""
    return b"\n" * max(0, 2 - (len(data) - len(data.rstrip(b"\n"))))
