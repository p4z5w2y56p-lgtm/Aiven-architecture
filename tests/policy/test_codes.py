"""One table for the codes of every check: a mutated valid policy yields exactly one new finding.

Each case is (code, mutation, expected_line), and may have the parameters of the message as a
fourth item. The mutation edits the bytes of `valid_base()`. The validator must then report exactly
one finding that the base does not have, with that code on that line (None for a finding about the
whole file). Findings that disappear are ignored, and the base carries the three warnings that no
wrapper is live (W-TOOL-NOT-LIVE), so the full list is never compared.

Rules for a mutation:
- Edit text inside one free-text line of the body (Purpose, Why each tool, Data and risks). Never
  touch the front matter or the two generated sections, and never add or remove a line. The
  exceptions are the BOM at the very start, the cases about the end of the file, the front matter
  cases, and the body cases (below). The front matter cases edit the front matter in place (a field
  is commented out, the comment-only line 2 is replaced), so that no line moves. Only
  E-LIST-DUPLICATE adds a line, behind the forbidden list, where nothing else points.
- The field, tool, limit and scope cases (Task 1.4) edit the front matter in place as well, or add
  one line behind the last entry of a list: the lines below it move down, and the base has no
  finding below any of them. They never replace a valid entry. A rule that needs a different set of
  tools (the warnings about slack and unused limits and scope) comments out the tools it does not
  want.
- A warning does not stop E-BODY-DRIFT (ruling R29). So a case that changes, without an error, a
  value that the generated sections show must also render them again (`rendered`). A case that
  comments a tool out also removes the bullet of that tool from Why each tool, and one that adds a
  tool adds its bullet: the body explains the tools of the front matter, and no others.
- The body cases (Task 1.5) change the prose or the headings of the three free-text sections, and
  may add or remove lines: the base has no finding in the body, so nothing moves under a finding.
  They never touch the generated sections, except the case of E-BODY-DRIFT itself.
- Use no URLs, links or HTML, except in the cases of E-BODY-HTML and E-BODY-LINK.
- Find the target line by content (`line_of`), not by number.
- E-FILENAME changes the path that the validator is given, not the bytes (see its own test).
- The set cases (Task 1.6, `SET_CASES`) are about several files at once, so they are not a
  mutation of one file: see the comment at the table.
"""

import codecs
import dataclasses
import json
import re
import time
from collections import Counter
from collections.abc import Callable
from pathlib import Path

import pytest

from aiven.policy.catalog import load_catalog
from aiven.policy.constants import SECTIONS
from aiven.policy.fileformat import decode_text
from aiven.policy.findings import Finding, format_line, message
from aiven.policy.model import Policy
from aiven.policy.policyset import check_set
from aiven.policy.validate import validate_file
from tests.support import REPO_ROOT, gen
from tests.support.bodies import policy_of, rerendered
from tests.support.gen import grouped
from tests.support.policies import (
    AGENTS_PROJECT,
    BASE_PATH,
    FOLDER_ID,
    TEMPLATE_PATH,
    line_of,
    platform_config,
    valid_base,
)
from tests.support.rules import setting, with_tools
from tests.support.spec_tables import code_spans, table_after
from tests.support.variants import Change, principal_of, variant, variant_file

CFG = platform_config()
CATALOG = load_catalog(REPO_ROOT / "catalog" / "catalog-v1.yaml")

BASE = valid_base()
BASE_TEXT = BASE.decode("utf-8")

# Text that occurs once in the base, on a free-text line.
PURPOSE = "Once a day, this agent reads"
PURPOSE_END = "no email goes to clients."
READS = "Reads: only the tracker columns listed above."
WHY_DRAFT = "writes one internal reminder draft"
RISKS_WRITES = "Writes: internal reminder drafts in the agent mailbox."

PURPOSE_LINE = line_of(BASE_TEXT, PURPOSE)
READS_LINE = line_of(BASE_TEXT, READS)
WHY_LINE = line_of(BASE_TEXT, WHY_DRAFT)
RISKS_LINE = line_of(BASE_TEXT, RISKS_WRITES)

# Task 1.5: lines of the body, and the text of a few of them.
BASE_LINES = BASE_TEXT.split("\n")
BODY_START = BASE_LINES.index("---", 1) + 2  # the line behind the closing delimiter
TITLE_LINE = line_of(BASE_TEXT, "# invoice-reminder")
PURPOSE_HEADING_LINE = line_of(BASE_TEXT, "## Purpose")
WHY_HEADING_LINE = line_of(BASE_TEXT, "## Why each tool")
DATA_HEADING_LINE = line_of(BASE_TEXT, "## Data and risks")
PURPOSE_TEXT = BASE_LINES[PURPOSE_LINE - 1]
PURPOSE_AFTER = PURPOSE_LINE + 2  # a line added behind the Purpose paragraph, after a blank one
# The three bullets of Why each tool, by their first words (the Undo list has the same names).
WHY_SHEETS = "- `sheets.read`: reads the tracker"
WHY_DRAFT_BULLET = "- `gmail.draft`: writes one internal"
WHY_SEND = "- `gmail.send`: sends a reminder draft"
DRAFT_BULLET_TEXT = BASE_LINES[line_of(BASE_TEXT, WHY_DRAFT_BULLET) - 1]
SEND_BULLET_LINE = line_of(BASE_TEXT, WHY_SEND)
STOP = "Stop: the agent kill switch"
STOP_LINE = line_of(BASE_TEXT, STOP)
SIGNING = "Signing means: I have read"
SIGNING_LINE = line_of(BASE_TEXT, SIGNING)
GENERATED_ENFORCED = "Enforced rules (generated)"
GENERATED_SIGNOFF = "Sign-off (generated)"

# Lines of the front matter, found by their content.
COMMENT_LINE = line_of(BASE_TEXT, "# AIVEN policy, schema v1")  # a line of comment only
COMMENT = BASE_TEXT.split("\n")[COMMENT_LINE - 1]
AGENT_LINE = line_of(BASE_TEXT, "agent: invoice-reminder")
VERSION_LINE = line_of(BASE_TEXT, "version: 1")
LIMITS_LINE = line_of(BASE_TEXT, "limits:")
RUNTIME_LINE = line_of(BASE_TEXT, "max_runtime_s: 300")
DELETE_LINE = line_of(BASE_TEXT, "- drive.delete")
LAST_FORBIDDEN_LINE = line_of(BASE_TEXT, "- gmail.send_bulk")
SCHEMA_LINE = line_of(BASE_TEXT, "schema: aiven-policy/v1")
PRINCIPAL_LINE = line_of(BASE_TEXT, "principal: agent-")
MAX_CLASS_LINE = line_of(BASE_TEXT, "max_class: R2")
SHEETS_LINE = line_of(BASE_TEXT, "- sheets.read")
DRAFT_LINE = line_of(BASE_TEXT, "- gmail.draft")
SEND_LINE = DRAFT_LINE + 1  # `- gmail.send` is also the start of the line of gmail.send_bulk
FORBIDDEN_LINE = line_of(BASE_TEXT, "forbidden:")
UNTRUSTED_LINE = line_of(BASE_TEXT, "untrusted_input: strict")
EMAILS_LINE = line_of(BASE_TEXT, "emails_per_day: 10")
RECORDS_LINE = line_of(BASE_TEXT, "records_per_run: 10")
SPEND_LINE = line_of(BASE_TEXT, "spend_eur_per_run: 0")
RUNS_LINE = line_of(BASE_TEXT, "runs_per_day: 1")
SCOPE_LINE = line_of(BASE_TEXT, "scope:")
FOLDER_ID_LINE = line_of(BASE_TEXT, "drive_folder_id:")
SANDBOX_LINE = line_of(BASE_TEXT, "drive_folder_path:")
EMAIL_TO_LINE = line_of(BASE_TEXT, "email_to:")
LAST_EMAIL_LINE = line_of(BASE_TEXT, '- "@aivenstudios.com"')
MIN_RUNS_LINE = line_of(BASE_TEXT, "min_runs: 10")

Mutation = Callable[[bytes], bytes]


def insert_after(anchor: str, payload: str | bytes) -> Mutation:
    """Insert `payload` right behind the one place where `anchor` occurs. No line is added."""

    def mutate(data: bytes) -> bytes:
        marker = anchor.encode("utf-8")
        assert data.count(marker) == 1, f"{anchor!r} must occur exactly once"
        raw = payload.encode("utf-8") if isinstance(payload, str) else payload
        assert b"\n" not in raw
        return data.replace(marker, marker + raw, 1)

    return mutate


def grow_to(size: int, anchor: str) -> Mutation:
    """Pad the line of `anchor` with filler until the file is `size` bytes."""
    return lambda data: insert_after(anchor, "x" * (size - len(data)))(data)


def replace(old: str, new: str) -> Mutation:
    """Replace the one place where `old` stands. For the front matter cases, which edit in place."""

    def mutate(data: bytes) -> bytes:
        marker = old.encode("utf-8")
        assert data.count(marker) == 1, f"{old!r} must occur exactly once"
        return data.replace(marker, new.encode("utf-8"), 1)

    return mutate


def edit_line(needle: str, old: str, new: str) -> Mutation:
    """In the one line that holds `needle`, replace the first `old` by `new`."""

    def mutate(data: bytes) -> bytes:
        lines = data.split(b"\n")
        hits = [number for number, line in enumerate(lines) if needle.encode() in line]
        assert len(hits) == 1, f"{needle!r} must occur in exactly one line"
        assert old.encode() in lines[hits[0]], f"{old!r} is not in the line of {needle!r}"
        lines[hits[0]] = lines[hits[0]].replace(old.encode(), new.encode(), 1)
        return b"\n".join(lines)

    return mutate


def insert_line_after(needle: str, new_line: str) -> Mutation:
    """Add `new_line` behind the one line that holds `needle`. The lines after it move down."""

    def mutate(data: bytes) -> bytes:
        lines = data.split(b"\n")
        hits = [number for number, line in enumerate(lines) if needle.encode() in line]
        assert len(hits) == 1, f"{needle!r} must occur in exactly one line"
        lines.insert(hits[0] + 1, new_line.encode())
        return b"\n".join(lines)

    return mutate


def findings_of(data: bytes) -> list[Finding]:
    return validate_file(BASE_PATH, data, CFG, CATALOG)


def new_findings(data: bytes) -> list[Finding]:
    """What `data` reports and the valid base does not: the multiset difference, in report order."""
    return list((Counter(findings_of(data)) - Counter(findings_of(BASE))).elements())


def assert_prints(finding: Finding, where: str | Path) -> None:
    """The finding has every param that its message needs, in both languages, and prints right.

    A missing param raises KeyError in `message`. No `{name}` may be left over (a value may hold
    braces itself: the pattern of a folder ID), and the one-line form starts with the severity,
    the code and `where`, the path of the file.
    """
    for lang in ("en", "nl"):
        text = message(finding, lang)
        for value in finding.params.values():
            text = text.replace(value, "")
        assert "{" not in text and "}" not in text
    assert format_line(finding).startswith(f"{finding.severity} {finding.code} {where}")


def case(
    code: str,
    label: str,
    mutation: Mutation,
    line: int | None,
    params: dict[str, str] | None = None,
):
    return pytest.param(code, mutation, line, params, id=f"{code} {label}")


def together(*mutations: Mutation) -> Mutation:
    """Several edits in a row."""

    def mutate(data: bytes) -> bytes:
        for mutation in mutations:
            data = mutation(data)
        return data

    return mutate


def add_tool(name: str) -> Mutation:
    """Add a tool behind the last one. The lines below it move down."""
    return replace("  - gmail.send\nforbidden:", f"  - gmail.send\n  - {name}\nforbidden:")


def add_forbidden(entry: str) -> Mutation:
    return insert_line_after("- gmail.send_bulk", f"  - {entry}")


def add_emails(*entries: str) -> Mutation:
    lines = "\n".join(f'    - "{entry}"' for entry in entries)
    return insert_line_after('- "@aivenstudios.com"', lines)


def comment_out(needle: str) -> Mutation:
    """Turn the one line that holds `needle` into a comment. No line moves."""
    return edit_line(needle, needle, f"# {needle}")


def set_value(key: str, old: str, new: str) -> Mutation:
    """Change a value in the line of a field of the front matter: `limits: 10` to `limits: 0`."""
    return edit_line(f"{key}: {old}", f"{key}: {old}", f"{key}: {new}")


def remove_line(needle: str) -> Mutation:
    """Remove the one line that holds `needle`. The lines behind it move up."""

    def mutate(data: bytes) -> bytes:
        lines = data.split(b"\n")
        hits = [number for number, line in enumerate(lines) if needle.encode() in line]
        assert len(hits) == 1, f"{needle!r} must occur in exactly one line"
        del lines[hits[0]]
        return b"\n".join(lines)

    return mutate


def swap(first: str, second: str) -> Mutation:
    """Exchange two texts, each of which stands once. No line moves."""

    def mutate(data: bytes) -> bytes:
        a, b = first.encode(), second.encode()
        assert data.count(a) == 1 and data.count(b) == 1, "both texts must occur exactly once"
        return data.replace(a, b"\0").replace(b, a).replace(b"\0", b)

    return mutate


def rendered(mutation: Mutation) -> Mutation:
    """The mutation, and then the generated sections rendered again from the new front matter.

    A warning does not stop E-BODY-DRIFT (ruling R29), so a case that changes a value that the
    sections show, without an error, has to change the sections too.
    """
    return lambda data: rerendered(mutation(data))


def drop_bullet(first_words: str) -> Mutation:
    """Remove a bullet of Why each tool: that of a tool that the case comments out."""
    return remove_line(first_words)


def add_bullet(tool: str) -> Mutation:
    """Explain a tool in Why each tool, behind the bullet of gmail.send (the last one)."""
    return insert_line_after(WHY_SEND, f"- `{tool}`: is needed for the case of the test.")


def content_samples() -> list[tuple[str, str, str, str]]:
    """(code, kind, label, value) for each kind of content that must be refused."""
    samples = [
        ("E-SECRET", kind, f"{kind} {number}", value)
        for kind, values in gen.secret_values().items()
        for number, value in enumerate(values, start=1)
    ]
    iban, card = gen.valid_iban(), gen.valid_card()
    samples += [
        ("E-BANK-DETAILS", "IBAN", "IBAN", iban),
        ("E-BANK-DETAILS", "IBAN", "IBAN in groups", grouped(iban)),
        ("E-BANK-DETAILS", "IBAN", "IBAN in lower case", iban.lower()),
        ("E-BANK-DETAILS", "card number", "card number", card),
        ("E-BANK-DETAILS", "card number", "card number in groups", grouped(card)),
        ("E-BANK-DETAILS", "card number", "card number with dashes", grouped(card, "-")),
        ("E-ID-NUMBER", "BSN", "BSN", gen.valid_bsn()),
    ]
    return samples


CONTENT_SAMPLES = content_samples()

CYRILLIC_E = "\N{CYRILLIC SMALL LETTER IE}"  # looks like the Latin e


def replace_comment(text: str) -> Mutation:
    """Put `text` where the comment-only line of the front matter stands."""
    return replace(COMMENT, text)


# Not an integer for a limit: quoted, hexadecimal, sexagesimal (YAML 1.1 reads 5:00 as 300),
# signed, and a YAML 1.1 boolean.
NOT_INTEGERS = {
    "quoted": '"300"',
    "hexadecimal": "0x12C",
    "sexagesimal": "5:00",
    "plus sign": "+5",
    "on": "on",
}

# Task 1.3: the front matter (validator-spec 3.2). Each case edits in place, see the top.
FRONT_MATTER_CASES = [
    case("E-FM-MISSING", "line 1 is not ---", replace("---\n# AIVEN", "--- \n# AIVEN"), 1),
    case(
        "E-FM-MISSING",
        "no closing ---",
        replace("---\n\n# invoice-reminder", "--- \n\n# invoice-reminder"),
        1,
    ),
    case("E-YAML", "character that starts no token", replace_comment("@"), COMMENT_LINE),
    case(
        "E-YAML-FEATURE",
        "anchor",
        edit_line("agent: invoice-reminder", "invoice-reminder", "&a invoice-reminder"),
        AGENT_LINE,
    ),
    case(
        "E-YAML-FEATURE",
        "alias",
        edit_line("agent: invoice-reminder", "invoice-reminder", "*a"),
        AGENT_LINE,
    ),
    case("E-YAML-FEATURE", "merge key", replace_comment("<<: {}"), COMMENT_LINE),
    case("E-YAML-FEATURE", "tag", edit_line("version: 1", "1", "!!str 1"), VERSION_LINE),
    case(
        "E-YAML-FEATURE",
        "escape sequence",
        edit_line("agent: invoice-reminder", "invoice-reminder", '"invoice\\x2dreminder"'),
        AGENT_LINE,
    ),
    case("E-YAML-FEATURE", "complex key", replace_comment("? [a, b]"), COMMENT_LINE),
    case("E-YAML-FEATURE", "second document", replace_comment("--- # second"), COMMENT_LINE),
    case("E-YAML-DUPLICATE-KEY", "version twice", replace_comment("version: 1"), VERSION_LINE),
    case(
        "E-FM-NON-ASCII",
        "Cyrillic e in a comment",
        edit_line("- drive.delete", "# required", f"# r{CYRILLIC_E}quired"),
        DELETE_LINE,
    ),
    case(
        "E-HIDDEN-CHAR",
        "zero width space in a front matter comment (not also non-ASCII)",
        edit_line("- drive.delete", "# required", "# required\N{ZERO WIDTH SPACE}"),
        DELETE_LINE,
    ),
    case(
        "E-FIELD-MISSING",
        "top-level field commented out",
        edit_line("untrusted_input: strict", "untrusted_input:", "# untrusted_input:"),
        1,
    ),
    case(
        "E-FIELD-MISSING",
        "nested field commented out",
        edit_line("runs_per_day: 1", "runs_per_day:", "# runs_per_day:"),
        LIMITS_LINE,
    ),
    case("E-FIELD-UNKNOWN", "Max_class", replace_comment("Max_class: R2"), COMMENT_LINE),
    *[
        case("E-FIELD-TYPE", label, edit_line("max_runtime_s: 300", "300", value), RUNTIME_LINE)
        for label, value in NOT_INTEGERS.items()
    ],
    case(
        "E-LIST-DUPLICATE",
        "forbidden entry twice",
        insert_line_after("- gmail.send_bulk", "  - drive.share"),
        LAST_FORBIDDEN_LINE + 1,
    ),
]

TOOLS_END = SEND_LINE + 1  # where an added tool stands
FORBIDDEN_END = LAST_FORBIDDEN_LINE + 1
EMAILS_END = LAST_EMAIL_LINE + 1

# The text of the base, as the cases change it.
SENDS = "  - gmail.send\nforbidden:"
NO_SENDS = "  # - gmail.send\nforbidden:"

# A policy without gmail.send. Its email limit is then 0, or it would be unused.
WITHOUT_SEND = together(replace(SENDS, NO_SENDS), set_value("emails_per_day", "10", "0"))

# A policy that only reads: R0, no emails and no records. The email scope is then unused.
ONLY_READS = together(
    replace("  - gmail.draft\n" + SENDS, "  # - gmail.draft\n" + NO_SENDS),
    set_value("max_class", "R2", "R0"),
    set_value("emails_per_day", "10", "0"),
    set_value("records_per_run", "10", "0"),
)

# A tool that is commented out has no bullet in Why each tool either (or it is E-BODY-TOOL-EXTRA),
# and the generated sections are rendered again (or it is E-BODY-DRIFT).
WITHOUT_SEND_RENDERED = rendered(together(WITHOUT_SEND, drop_bullet(WHY_SEND)))
ONLY_READS_RENDERED = rendered(
    together(ONLY_READS, drop_bullet(WHY_DRAFT_BULLET), drop_bullet(WHY_SEND))
)

# Task 1.4: the field, tool, limit and scope rules (validator-spec 3.3 to 3.5).
LONG_AGENT = "a" * 25
RULE_CASES = [
    case(
        "E-SCHEMA",
        "aiven-policy/v2",
        edit_line("schema: aiven-policy/v1", "v1", "v2"),
        SCHEMA_LINE,
        {"found": "aiven-policy/v2"},
    ),
    *[
        # Ruling R28: the file name and the principal are those of invoice-reminder and would be
        # wrong too. Without the ruling one bad id gives three findings.
        case(
            "E-AGENT-ID",
            label,
            edit_line("agent: invoice-reminder", "invoice-reminder", agent),
            AGENT_LINE,
            {"value": agent},
        )
        for label, agent in [
            ("two characters", "ab"),
            ("reserved", "admin"),
            ("25 characters", LONG_AGENT),
            ("capital", "Invoice-reminder"),
        ]
    ],
    case(
        "E-PRINCIPAL",
        "another project",
        edit_line("principal: agent-", AGENTS_PROJECT, "other-project"),
        PRINCIPAL_LINE,
        {
            "agent": "invoice-reminder",
            "project": AGENTS_PROJECT,
            "value": "agent-invoice-reminder@other-project.iam.gserviceaccount.com",
        },
    ),
    case("E-MAX-CLASS-R3", "R3", set_value("max_class", "R2", "R3"), MAX_CLASS_LINE, {}),
    case("E-MAX-CLASS-R4", "R4", set_value("max_class", "R2", "R4"), MAX_CLASS_LINE, {}),
    case(
        "E-FIELD-TYPE",
        "max_class high",
        set_value("max_class", "R2", "high"),
        MAX_CLASS_LINE,
        {"field": "max_class", "expected": "R0 | R1 | R2", "found": "high"},
    ),
    case(
        "E-UNTRUSTED-INPUT",
        "off",
        set_value("untrusted_input", "strict", "off"),
        UNTRUSTED_LINE,
        {},
    ),
    case(
        "W-UNTRUSTED-TAINT",
        "taint",
        rendered(set_value("untrusted_input", "strict", "taint")),
        UNTRUSTED_LINE,
        {},
    ),
    # E-RANGE: one above (or below) the ceiling of each number. The boundaries that pass are
    # in BOUNDARY_CASES.
    *[
        case(
            "E-RANGE",
            f"{field} {value}",
            set_value(field, old, str(value)),
            line,
            {"field": path, "value": str(value), "min": str(low), "max": str(high)},
        )
        for field, path, old, line, low, high, values in [
            ("version", "version", "1", VERSION_LINE, 1, 9999, (0, 10_000)),
            ("emails_per_day", "limits.emails_per_day", "10", EMAILS_LINE, 0, 50, (51,)),
            ("records_per_run", "limits.records_per_run", "10", RECORDS_LINE, 0, 200, (201,)),
            ("max_runtime_s", "limits.max_runtime_s", "300", RUNTIME_LINE, 30, 900, (29, 901)),
            ("runs_per_day", "limits.runs_per_day", "1", RUNS_LINE, 1, 10, (0, 11)),
            ("min_runs", "shadow.min_runs", "10", MIN_RUNS_LINE, 1, 100, (0, 101)),
        ]
        for value in values
    ],
    case(
        "E-RANGE",
        "51 addresses",
        add_emails(*[f"a{n}@aivenstudios.com" for n in range(50)]),
        EMAIL_TO_LINE,
        {"field": "scope.email_to", "value": "51", "min": "1", "max": "50"},
    ),
    case(
        "E-RANGE",
        "no address",
        together(
            edit_line("email_to:", "email_to:", "email_to: []"),
            comment_out('    - "@aivenstudios.com"'),
        ),
        EMAIL_TO_LINE,
        {"field": "scope.email_to", "value": "0", "min": "1", "max": "50"},
    ),
    case("E-TOOL-UNKNOWN", "a typo", add_tool("drive.reed"), TOOLS_END, {"tool": "drive.reed"}),
    case("E-TOOL-WILDCARD", "drive.*", add_tool("drive.*"), TOOLS_END, {"tool": "drive.*"}),
    case("E-TOOL-R3", "drive.move", add_tool("drive.move"), TOOLS_END, {"tool": "drive.move"}),
    case(
        "E-TOOL-R4", "payments.pay", add_tool("payments.pay"), TOOLS_END, {"tool": "payments.pay"}
    ),
    case(
        "E-TOOL-ABOVE-MAX-CLASS",
        "gmail.send with max_class R1",
        set_value("max_class", "R2", "R1"),
        SEND_LINE,
        {"tool": "gmail.send", "class": "R2", "max": "R1"},
    ),
    case(
        "E-TOOL-FORBIDDEN",
        "sheets.read",
        add_forbidden("sheets.read"),
        SHEETS_LINE,
        {"tool": "sheets.read", "pattern": "sheets.read"},
    ),
    case(
        "E-FORBIDDEN-PATTERN",
        "a star in the middle",
        add_forbidden("payments.*.pay"),
        FORBIDDEN_END,
        {"entry": "payments.*.pay"},
    ),
    case(
        "E-FORBIDDEN-UNKNOWN",
        "paymnets.*",
        add_forbidden("paymnets.*"),
        FORBIDDEN_END,
        {"entry": "paymnets.*"},
    ),
    case(
        "E-FORBIDDEN-BASELINE",
        "drive.share left out",
        comment_out("- drive.share"),
        FORBIDDEN_LINE,
        {"missing": "drive.share"},
    ),
    case("E-LIMIT-SPEND", "5", set_value("spend_eur_per_run", "0", "5"), SPEND_LINE, {}),
    case(
        "E-LIMIT-CONFLICT",
        "gmail.send, no emails",
        set_value("emails_per_day", "10", "0"),
        EMAILS_LINE,
        {"limit": "emails_per_day", "tool": "gmail.send"},
    ),
    case(
        "E-LIMIT-CONFLICT",
        "gmail.draft, no records",
        set_value("records_per_run", "10", "0"),
        RECORDS_LINE,
        {"limit": "records_per_run", "tool": "gmail.draft"},
    ),
    case(
        "E-SCOPE-MISSING",
        "drive_folder_id",
        comment_out("drive_folder_id:"),
        SCOPE_LINE,
        {"field": "drive_folder_id", "tool": "sheets.read"},
    ),
    case(
        "E-SCOPE-MISSING",
        "drive_folder_path",
        comment_out("drive_folder_path:"),
        SCOPE_LINE,
        {"field": "drive_folder_path", "tool": "sheets.read"},
    ),
    case(
        "E-SCOPE-MISSING",
        "email_to",
        together(comment_out("email_to:"), comment_out('    - "@aivenstudios.com"')),
        SCOPE_LINE,
        {"field": "email_to", "tool": "gmail.draft"},
    ),
    case(
        "E-FIELD-TYPE",
        "drive_folder_id too short",
        edit_line("drive_folder_id:", FOLDER_ID, "short"),
        FOLDER_ID_LINE,
        {
            "field": "scope.drive_folder_id",
            "expected": "[A-Za-z0-9_-]{10,100}",
            "found": "short",
        },
    ),
    case(
        "E-SCOPE-SANDBOX",
        "another drive",
        edit_line("drive_folder_path:", "AIVEN Architecture Sandbox", "Other Drive"),
        SANDBOX_LINE,
        {},
    ),
    *[
        case("E-SCOPE-EMAIL", entry, add_emails(entry), EMAILS_END, {"entry": entry})
        for entry in ("@Aivenstudios.com", "*@x.nl")
    ],
    case(
        "E-SCOPE-EMAIL-PUBLIC",
        "@gmail.com",
        add_emails("@gmail.com"),
        EMAILS_END,
        {"entry": "@gmail.com"},
    ),
    case(
        "E-SCOPE-EMAIL-EXTERNAL",
        "@client.nl",
        add_emails("@client.nl"),
        EMAILS_END,
        {"entry": "@client.nl"},
    ),
    case(
        "W-MAX-CLASS-SLACK",
        "R2 with nothing above R1",
        WITHOUT_SEND_RENDERED,
        MAX_CLASS_LINE,
        {"max": "R2", "highest": "R1"},
    ),
    case(
        "W-TOOL-NOT-LIVE",
        "drive.read",
        rendered(together(add_tool("drive.read"), add_bullet("drive.read"))),
        TOOLS_END,
        {"tool": "drive.read", "wrapper": "Drive"},
    ),
    case(
        "W-TOOL-NOT-LIVE",
        "agentbuilder.read",
        rendered(together(add_tool("agentbuilder.read"), add_bullet("agentbuilder.read"))),
        TOOLS_END,
        {"tool": "agentbuilder.read", "wrapper": "Agent Builder"},
    ),
    case(
        "W-LIMIT-UNUSED",
        "emails without gmail.send",
        rendered(
            together(
                replace(SENDS, NO_SENDS),
                set_value("max_class", "R2", "R1"),
                drop_bullet(WHY_SEND),
            )
        ),
        EMAILS_LINE,
        {"limit": "emails_per_day", "value": "10"},
    ),
    case(
        "W-SCOPE-UNUSED",
        "email_to without gmail tools",
        ONLY_READS_RENDERED,
        EMAIL_TO_LINE,
        {"field": "email_to"},
    ),
    case(
        "W-SHADOW-LOW",
        "5 runs",
        rendered(set_value("min_runs", "10", "5")),
        MIN_RUNS_LINE,
        {"value": "5"},
    ),
]

# Numbers on the boundary that is allowed: no new finding at all.
BOUNDARY_CASES = [
    pytest.param(rendered(set_value(field, old, str(value))), id=f"{field} {value}")
    for field, old, value in [
        ("version", "1", 9999),
        ("emails_per_day", "10", 50),
        ("records_per_run", "10", 200),
        ("max_runtime_s", "300", 30),
        ("max_runtime_s", "300", 900),
        ("runs_per_day", "1", 10),
        ("min_runs", "10", 100),
    ]
] + [
    pytest.param(
        rendered(add_emails(*[f"a{n}@aivenstudios.com" for n in range(49)])),
        id="email_to 50 addresses",
    )
]

# Task 1.5: the body (validator-spec 3.7). Each case edits the prose or the headings of the three
# free-text sections, see the top. A line that is added stands two lines behind the one it follows.
FIVE_SECTIONS = ", ".join(SECTIONS)
BODY_CASES = [
    case(
        "E-BODY-TITLE",
        "not the agent",
        edit_line("# invoice-reminder", "invoice-reminder", "invoice reminder"),
        TITLE_LINE,
        {"agent": "invoice-reminder"},
    ),
    case(
        "E-BODY-TITLE",
        "a closing #",
        edit_line("# invoice-reminder", "reminder", "reminder #"),
        TITLE_LINE,
        {"agent": "invoice-reminder"},
    ),
    case(
        "E-BODY-SECTIONS",
        "a section is missing",
        remove_line("## Data and risks"),
        BODY_START,
        {"found": ", ".join(name for name in SECTIONS if name != "Data and risks")},
    ),
    case(
        "E-BODY-SECTIONS",
        "a section is renamed",
        edit_line("## Data and risks", "risks", "risk"),
        DATA_HEADING_LINE,
        {"found": FIVE_SECTIONS.replace("Data and risks", "Data and risk")},
    ),
    case(
        "E-BODY-SECTIONS",
        "out of order",
        swap("## Purpose", "## Data and risks"),
        PURPOSE_HEADING_LINE,
        {
            "found": FIVE_SECTIONS.replace("Purpose", "@")
            .replace("Data and risks", "Purpose")
            .replace("@", "Data and risks")
        },
    ),
    case(
        "E-BODY-SECTIONS",
        "an extra ##",
        insert_line_after(PURPOSE_END, "\n## Notes"),
        PURPOSE_AFTER,
        {"found": FIVE_SECTIONS.replace("Why each tool", "Notes, Why each tool")},
    ),
    case(
        "E-BODY-SECTIONS",
        "a second title",
        insert_line_after(PURPOSE_END, "\n# Another title"),
        PURPOSE_AFTER,
        {"found": FIVE_SECTIONS},
    ),
    case(
        "E-BODY-SECTIONS",
        "### in front of the first section",
        insert_line_after("# invoice-reminder", "\n### Early"),
        TITLE_LINE + 2,
        {"found": FIVE_SECTIONS},
    ),
    case(
        "E-BODY-EMPTY",
        "Purpose of 10 characters",
        edit_line(PURPOSE, PURPOSE_TEXT, "Too short."),
        PURPOSE_HEADING_LINE,
        {"section": "Purpose"},
    ),
    case(
        "E-BODY-TOOL-UNEXPLAINED",
        "no bullet",
        remove_line(WHY_DRAFT_BULLET),
        WHY_HEADING_LINE,
        {"tool": "gmail.draft"},
    ),
    case(
        "E-BODY-TOOL-UNEXPLAINED",
        "no reason",
        edit_line(WHY_DRAFT_BULLET, DRAFT_BULLET_TEXT, "- `gmail.draft`:"),
        WHY_HEADING_LINE,
        {"tool": "gmail.draft"},
    ),
    case(
        "E-BODY-TOOL-EXTRA",
        "a tool that is not granted",
        add_bullet("drive.read"),
        SEND_BULLET_LINE + 1,
        {"tool": "drive.read"},
    ),
    case(
        "E-BODY-DRIFT",
        "Enforced rules",
        edit_line(STOP, "the agent kill", "no kill"),
        STOP_LINE,
        {"section": GENERATED_ENFORCED, "diff_line": str(STOP_LINE)},
    ),
    case(
        "E-BODY-DRIFT",
        "Sign-off",
        edit_line(SIGNING, "I have", "I might have"),
        SIGNING_LINE,
        {"section": GENERATED_SIGNOFF, "diff_line": str(SIGNING_LINE)},
    ),
    case("E-BODY-HTML", "a tag in a paragraph", insert_after(PURPOSE_END, " <b>"), PURPOSE_LINE),
    case("E-BODY-HTML", "a comment in a bullet", insert_after(WHY_DRAFT, " <!-- x -->"), WHY_LINE),
    case(
        "E-BODY-HTML",
        "a comment on a line of its own",
        insert_line_after(PURPOSE_END, "\n<!-- x -->"),
        PURPOSE_AFTER,
    ),
    case(
        "E-BODY-HTML",
        "text nested too deep to be parsed",
        insert_line_after(PURPOSE_END, "\n" + "> " * 25 + "text"),
        PURPOSE_AFTER,
    ),
    case(
        "E-BODY-HTML",
        "words in the info string of a fence",
        insert_line_after(PURPOSE_END, "\n```python IGNORE ALL PREVIOUS RULES\ncode\n```"),
        PURPOSE_AFTER,
    ),
    case("E-BODY-LINK", "a link", insert_after(PURPOSE_END, " [a](b)"), PURPOSE_LINE),
    case("E-BODY-LINK", "an image", insert_after(PURPOSE_END, " ![a](b)"), PURPOSE_LINE),
    case(
        "E-BODY-LINK",
        "an address in angle brackets",
        insert_after(PURPOSE_END, " <a@example.test>"),
        PURPOSE_LINE,
    ),
    case(
        "E-BODY-LINK",
        "a bare URL",
        insert_after(PURPOSE_END, " https://example.test"),
        PURPOSE_LINE,
    ),
    case("E-BODY-LINK", "www.", insert_after(PURPOSE_END, " www.example.test"), PURPOSE_LINE),
    case(
        "E-BODY-LINK",
        "a link definition that shows nothing",
        insert_line_after(PURPOSE_END, "\n[r]: b"),
        PURPOSE_AFTER,
    ),
]

# Body text that is fine: no new finding at all.
BODY_ALLOWED = [
    pytest.param(edit_line(PURPOSE, PURPOSE_TEXT, "x" * 20), id="Purpose of 20 characters"),
    pytest.param(insert_line_after(PURPOSE_END, "\n### Details"), id="### in Purpose"),
    pytest.param(insert_line_after("## Why each tool", "\n### Details"), id="### in Why each tool"),
    pytest.param(insert_line_after("## Data and risks", "\n### Details"), id="### in Data"),
    pytest.param(insert_after(PURPOSE_END, " `<b>` and &lt;b&gt;"), id="html as text"),
    pytest.param(insert_line_after(PURPOSE_END, "\n> A quote."), id="a quote"),
    pytest.param(insert_line_after(PURPOSE_END, "\n-\n>"), id="marks without text"),
    pytest.param(insert_line_after(PURPOSE_END, "\n" + "> " * 18 + "text"), id="18 quotes"),
]

# Task 1.2: the file checks (validator-spec 3.1) and content safety (3.8).
CASES = [
    *FRONT_MATTER_CASES,
    *RULE_CASES,
    *BODY_CASES,
    case("E-ENCODING", "byte-order mark", lambda data: codecs.BOM_UTF8 + data, 1),
    case("E-ENCODING", "invalid byte", insert_after(PURPOSE, b"\xff"), PURPOSE_LINE),
    case("E-LINE-ENDINGS", "CR before the LF", insert_after(PURPOSE_END, "\r"), PURPOSE_LINE),
    case("E-FINAL-NEWLINE", "no newline", lambda data: data.rstrip(b"\n"), None),
    case("E-FINAL-NEWLINE", "two newlines", lambda data: data + b"\n", None),
    case("E-FILE-SIZE", "65537 bytes", grow_to(65_537, PURPOSE), None),
    case("E-HIDDEN-CHAR", "zero width space", insert_after(PURPOSE, "\u200b"), PURPOSE_LINE),
    case("E-HIDDEN-CHAR", "bidi override", insert_after(PURPOSE, "\u202e"), PURPOSE_LINE),
    case("E-HIDDEN-CHAR", "tag letter", insert_after(PURPOSE, "\U000e0041"), PURPOSE_LINE),
    case("E-HIDDEN-CHAR", "no-break space", insert_after(PURPOSE, "\u00a0"), PURPOSE_LINE),
    case("E-HIDDEN-CHAR", "tab", insert_after(PURPOSE, "\t"), PURPOSE_LINE),
    *[
        case("E-PLACEHOLDER", token, insert_after(WHY_DRAFT, f" {token}"), WHY_LINE)
        for token in ("REPLACE_ME_X", "TODO", "TBD", "FIXME")
    ],
    *[
        case(code, label, insert_after(RISKS_WRITES, f" {value}"), RISKS_LINE)
        for code, _, label, value in CONTENT_SAMPLES
    ],
]


# Task 1.6: the checks across all policies (validator-spec 3.6 and 3.9). A set case is
# (code, build, findings). `build()` makes the set: the (path, policy) pairs of its files, and the
# previous signed policies by agent. `check_set` must give exactly `findings`, in order, as
# (path, params), and all of that code: a valid set has no finding, so nothing else may come with
# it. A finding is about a whole file, as a policy carries no line map.
#
# "Valid" means that `check_set` has no finding for the set. The files are versions of the base
# (tests/support/variants.py), made through the real pipeline, and as they stand they are not whole
# valid files: the generated sections still show the base, which `validate_file` reports as
# E-BODY-DRIFT. A case that changes only values that those sections show renders them again
# (`render=True`), and its files are then whole valid files (the cases of E-VERSION-ORDER and of a
# raised limit; `RENDERED_CHANGES` is tested). The others cannot be: a copy of a file with another
# agent or principal has the defects of that (E-FILENAME, E-PRINCIPAL), which is what the codes
# of the duplicates are about, and a new tool needs its bullet in Why each tool.
SetBuild = Callable[[], tuple[list[tuple[Path, Policy]], dict[str, Policy]]]

COPY_PATH = Path("policies/invoice-copy.md")
NUDGE_PATH = Path("policies/payment-nudge.md")
AGENT = "invoice-reminder"
FILES_OF_AGENT = "invoice-copy.md, invoice-reminder.md"


def a_set(
    *files: tuple[Path, tuple[Change, ...]],
    before: tuple[Change, ...] | None = None,
    render: bool = False,
) -> SetBuild:
    """The set of these files, each a path and the changes to the base that make its policy.

    `before` are the changes that make the previous signed policy of invoice-reminder, `()` for
    the base itself. Without it, the set has no previous policy. With `render` the generated
    sections of every file are rendered again, which makes whole valid files of the changes that
    only touch values that those sections show.
    """

    def build():
        items = [(path, variant(*changes, render=render)) for path, changes in files]
        return items, ({} if before is None else {AGENT: variant(*before, render=render)})

    return build


def set_case(code: str, label: str, build: SetBuild, findings: list[tuple[Path, dict[str, str]]]):
    return pytest.param(
        code, build, [(str(p), params) for p, params in findings], id=f"{code} {label}"
    )


NEXT_VERSION = setting("version", 2)
ONE_TOOL_MORE = with_tools("sheets.read", "gmail.draft", "gmail.send", "drive.read")
# Changes of values that the generated sections show: these cases render them again.
SKIPS_A_VERSION = (setting("version", 3),)
OTHER_CONTENT = (setting("shadow.min_runs", 20),)
THE_NEXT_VERSION = (NEXT_VERSION,)
MORE_RUNS_A_DAY = (NEXT_VERSION, setting("limits.runs_per_day", 2))
RENDERED_CHANGES = {
    "a version that skips one": SKIPS_A_VERSION,
    "other content": OTHER_CONTENT,
    "the next version": THE_NEXT_VERSION,
    "a raised limit": MORE_RUNS_A_DAY,
}
SET_CASES = [
    set_case(
        "E-AGENT-DUPLICATE",
        "a copy that has a principal of its own",
        a_set(
            (BASE_PATH, ()),
            (COPY_PATH, (setting("principal", principal_of("invoice-copy")),)),
        ),
        [
            (BASE_PATH, {"agent": AGENT, "files": FILES_OF_AGENT}),
            (COPY_PATH, {"agent": AGENT, "files": FILES_OF_AGENT}),
        ],
    ),
    set_case(
        "E-PRINCIPAL-DUPLICATE",
        "another agent with the principal of the first",
        a_set((BASE_PATH, ()), (NUDGE_PATH, (setting("agent", "payment-nudge"),))),
        [
            (BASE_PATH, {"principal": principal_of(AGENT), "other": "payment-nudge.md"}),
            (NUDGE_PATH, {"principal": principal_of(AGENT), "other": "invoice-reminder.md"}),
        ],
    ),
    set_case(
        "E-VERSION-ORDER",
        "a version that skips one",
        a_set((BASE_PATH, SKIPS_A_VERSION), before=(), render=True),
        [(BASE_PATH, {"value": "3", "next": "2"})],
    ),
    set_case(
        "E-VERSION-ORDER",
        "the same version, with other content",
        a_set((BASE_PATH, OTHER_CONTENT), before=(), render=True),
        [(BASE_PATH, {"value": "1", "next": "2"})],
    ),
    set_case(
        "E-VERSION-ORDER",
        "a new agent that does not start at 1",
        a_set((BASE_PATH, THE_NEXT_VERSION), render=True),
        [(BASE_PATH, {"value": "2", "next": "1"})],
    ),
    set_case(
        "W-WIDENS",
        "a tool is added, so shadow mode starts again",
        a_set((BASE_PATH, (NEXT_VERSION, ONE_TOOL_MORE)), before=()),
        [(BASE_PATH, {"changes": "tools: +drive.read", "restart_runs": "10"})],
    ),
    set_case(
        "W-WIDENS",
        "a limit is raised, with no restart",
        a_set((BASE_PATH, MORE_RUNS_A_DAY), before=(), render=True),
        [(BASE_PATH, {"changes": "limits.runs_per_day: 1 -> 2"})],
    ),
]


# The codes that a test function of this module covers and no row of a table does: a table changes
# the bytes of the valid base, and a case that needs more than that has a test of its own. Each
# entry names that test. test_coverage_of_codes.py holds the entries to it: the test must exist, and
# must mention the code.
COVERED_ELSEWHERE = {
    "E-FILENAME": "test_a_file_name_other_than_the_agent_yields_exactly_one_new_finding",
}


def test_valid_base_has_no_errors():
    # Today no wrapper is live, so the three tools give the three warnings of spec section 9, and
    # nothing else (that is how the template becomes a real policy: "only the three warnings").
    found = findings_of(BASE)
    assert [(f.code, f.severity, f.line) for f in found] == [
        ("W-TOOL-NOT-LIVE", "warning", SHEETS_LINE),
        ("W-TOOL-NOT-LIVE", "warning", DRAFT_LINE),
        ("W-TOOL-NOT-LIVE", "warning", SEND_LINE),
    ]
    assert [f.params for f in found] == [
        {"tool": "sheets.read", "wrapper": "Drive"},
        {"tool": "gmail.draft", "wrapper": "Email"},
        {"tool": "gmail.send", "wrapper": "Email"},
    ]


@pytest.mark.parametrize(("code", "mutation", "expected_line", "params"), CASES)
def test_mutation_yields_exactly_one_new_finding(code, mutation, expected_line, params):
    new = new_findings(mutation(BASE))
    assert [(f.code, f.line) for f in new] == [(code, expected_line)]
    finding = new[0]
    assert params is None or finding.params == params
    assert finding.severity == ("error" if code.startswith("E-") else "warning")
    assert_prints(finding, BASE_PATH)


def test_a_valid_set_has_no_finding():
    # What the set cases start from: a new agent at version 1, and the next version of a known one.
    # Its files are whole valid files (rendered again): validate_file has no error, here only the
    # warnings of the base, and check_set has nothing.
    first = variant_file(render=True)
    second = variant_file(NEXT_VERSION, render=True)
    for data in (first, second):
        assert {f.code for f in findings_of(data)} == {"W-TOOL-NOT-LIVE"}
    assert check_set([(BASE_PATH, policy_of(first))], {}) == []
    assert check_set([(BASE_PATH, policy_of(second))], {AGENT: policy_of(first)}) == []


@pytest.mark.parametrize("changes", RENDERED_CHANGES.values(), ids=RENDERED_CHANGES)
def test_the_rendered_files_of_the_set_cases_are_whole_valid_files(changes):
    # The cases that render say that their files are valid ones: no error, as for the base.
    found = findings_of(variant_file(*changes, render=True))
    assert {f.code for f in found} == {"W-TOOL-NOT-LIVE"}


@pytest.mark.parametrize(
    ("change", "warning"),
    [
        (setting("untrusted_input", "taint"), "W-UNTRUSTED-TAINT"),
        (setting("shadow.min_runs", 5), "W-SHADOW-LOW"),
    ],
    ids=["the mode taint", "min_runs below 10"],
)
def test_a_rendered_variant_can_have_warnings_but_no_error(change, warning):
    # "Whole valid file" means no error. The warnings of the base stay, and a mode or a number of
    # runs that the policy warns about adds its own.
    found = findings_of(variant_file(NEXT_VERSION, change, render=True))
    assert {f.code for f in found} == {"W-TOOL-NOT-LIVE", warning}
    assert all(f.severity == "warning" for f in found)


def test_a_rendered_variant_is_the_policy_of_its_rendered_file():
    # The hash is that of the bytes that were rendered, so a case that renders has those files.
    rendered_file = variant_file(NEXT_VERSION, render=True)
    assert variant(NEXT_VERSION, render=True).sha256 == policy_of(rendered_file).sha256
    assert variant(NEXT_VERSION, render=True).sha256 != variant(NEXT_VERSION).sha256


def test_a_variant_that_is_not_rendered_is_not_a_whole_valid_file():
    # Only its front matter is new, and the generated sections still show the base. This is why a
    # set that has no finding of `check_set` is called valid, and not its files.
    codes = {f.code for f in findings_of(variant_file(NEXT_VERSION))}
    assert "E-BODY-DRIFT" in codes


@pytest.mark.parametrize(("code", "build", "findings"), SET_CASES)
def test_set_case_yields_exactly_its_findings(code, build, findings):
    items, previous = build()
    found = check_set(items, previous)
    assert [(f.code, f.path, f.params) for f in found] == [
        (code, path, params) for path, params in findings
    ]
    for finding in found:
        assert (finding.line, finding.column) == (None, None)
        assert finding.severity == ("error" if code.startswith("E-") else "warning")
        assert_prints(finding, finding.path)


def test_a_file_name_other_than_the_agent_yields_exactly_one_new_finding():
    # The path is not part of the bytes, so this case changes the path that the validator gets.
    def shape(f: Finding):
        return (f.code, f.severity, f.line, f.column, tuple(f.params.items()))

    known = Counter(shape(f) for f in findings_of(BASE))
    new = []
    for finding in validate_file(Path("policies/other-name.md"), BASE, CFG, CATALOG):
        if known[shape(finding)]:
            known[shape(finding)] -= 1
        else:
            new.append(finding)
    assert [(f.code, f.line, f.column) for f in new] == [("E-FILENAME", None, None)]
    assert new[0].severity == "error"
    assert new[0].path == "policies/other-name.md"
    assert new[0].params == {"name": "other-name.md", "agent": "invoice-reminder"}
    assert message(new[0], "en") == "File name other-name.md must be invoice-reminder.md."
    assert "invoice-reminder.md" in message(new[0], "nl")


@pytest.mark.parametrize(("code", "kind", "label", "value"), CONTENT_SAMPLES)
def test_content_finding_has_the_kind_as_its_only_parameter(code, kind, label, value):
    (finding,) = new_findings(insert_after(RISKS_WRITES, f" {value}")(BASE))
    assert finding.path == str(BASE_PATH)
    assert finding.params == ({} if code == "E-ID-NUMBER" else {"kind": kind})


@pytest.mark.parametrize(("code", "kind", "label", "value"), CONTENT_SAMPLES)
def test_content_findings_never_contain_value(code, kind, label, value):
    (finding,) = new_findings(insert_after(RISKS_WRITES, f" {value}")(BASE))
    shown = [
        format_line(finding),
        message(finding, "en"),
        message(finding, "nl"),
        json.dumps(dataclasses.asdict(finding)),  # stands in for --json until the CLI exists
    ]
    squeezed = re.sub(r"[ -]", "", value)  # also catch the value printed without its separators
    for text in shown:
        assert value not in text
        assert squeezed not in text


# A value joined to a placeholder word: the placeholder's own text would carry it into a finding.
# `scan` sees the value only where no letter or digit stands in front of it, which is after the
# underscore of `REPLACE_ME_`. The guard hides it whichever way it is glued.
GOOGLE_KEYS = gen.secret_values()["Google API key"]
GLUED_VALUES = {
    "BSN": ("E-ID-NUMBER", gen.valid_bsn()),
    "IBAN": ("E-BANK-DETAILS", gen.valid_iban()),
    "card number": ("E-BANK-DETAILS", gen.valid_card()),
    "Google API key": ("E-SECRET", GOOGLE_KEYS[0]),
    "Google API key with hyphens": ("E-SECRET", GOOGLE_KEYS[1]),
    "AWS access key": ("E-SECRET", gen.secret_values()["AWS access key"][0]),
    "GitHub token": ("E-SECRET", gen.secret_values()["GitHub token"][0]),
}
GLUE = {  # the text in front of the value, and whether the content check must report it too
    "REPLACE_ME_": True,
    "REPLACE_ME": False,
    "REPLACE_ME_X": False,
}


@pytest.mark.parametrize(("glue", "must_be_reported"), GLUE.items(), ids=GLUE)
@pytest.mark.parametrize(("code", "value"), GLUED_VALUES.values(), ids=GLUED_VALUES)
def test_a_placeholder_glued_to_a_value_does_not_echo_it(glue, must_be_reported, code, value):
    new = new_findings(insert_after(WHY_DRAFT, f" {glue}{value}")(BASE))
    # The placeholder is always reported, and the value where `scan` can see it. Other findings
    # on the line are allowed: `ME`, two digits and the words behind a number can read as an IBAN
    # by chance (about once in 97 candidates), and this test is not about that. Neither output
    # holds the value. That `scan` misses a value glued to a letter is tested in test_content.
    codes = {f.code for f in new}
    assert "E-PLACEHOLDER" in codes
    assert code in codes or not must_be_reported
    assert {f.line for f in new} == {WHY_LINE}
    for finding in new:
        shown = [
            format_line(finding),
            message(finding, "en"),
            message(finding, "nl"),
            json.dumps(dataclasses.asdict(finding)),
        ]
        assert all(value not in text for text in shown)
    placeholder = next(f for f in new if f.code == "E-PLACEHOLDER")
    assert placeholder.params == {"token": "[hidden]"}


SAMPLES = gen.sensitive_samples()


@pytest.mark.parametrize(("value", "start"), SAMPLES.values(), ids=SAMPLES)
def test_a_value_after_a_template_placeholder_shows_at_most_its_public_start(value, start):
    new = new_findings(insert_after(WHY_DRAFT, f" REPLACE_ME_FOLDER_ID{value}")(BASE))
    # The word that holds the placeholder holds the value, so the token is not shown at all. Other
    # findings on the line are allowed. Whatever they are, the part of the value after its public
    # start (`AKIA`, `gh`) is in none of the outputs.
    placeholder = next(f for f in new if f.code == "E-PLACEHOLDER")
    assert placeholder.params == {"token": "[hidden]"}
    for finding in new:
        shown = [
            format_line(finding),
            message(finding, "en"),
            message(finding, "nl"),
            json.dumps(dataclasses.asdict(finding)),
        ]
        assert all(value[start:] not in text for text in shown)


def test_validate_file_decodes_the_bytes_once(monkeypatch):
    calls = []

    def counting(data: bytes) -> str:
        calls.append(len(data))
        return decode_text(data)

    monkeypatch.setattr("aiven.policy.validate.decode_text", counting)
    monkeypatch.setattr("aiven.policy.fileformat.decode_text", counting)
    findings_of(BASE)
    assert calls == [len(BASE)]


def test_content_columns_do_not_count_the_byte_order_mark():
    data = codecs.BOM_UTF8 + gen.assignment("password").encode() + b"\n"
    assert ("E-SECRET", 1, 1) in {(f.code, f.line, f.column) for f in findings_of(data)}


def test_findings_are_sorted_whole_file_first_then_by_line_column_and_code():
    # Built so that emission order differs from report order: the hidden character comes later
    # in the Purpose line than the placeholder, and the whole-file findings tie on position.
    aws = gen.secret_values()["AWS access key"][0]
    bsn = gen.valid_bsn()
    data = insert_after("Once a day,", " TODO")(BASE)
    data = insert_after("this agent reads", "\u200b")(data)
    data = insert_after(WHY_DRAFT, f" {aws}")(data)
    data = insert_after(RISKS_WRITES, f" {bsn}")(data)
    data = codecs.BOM_UTF8 + data.rstrip(b"\n")
    data = grow_to(65_537, READS)(data)

    lines = data[len(codecs.BOM_UTF8) :].decode("utf-8").split("\n")

    def column(line: int, needle: str) -> int:
        return lines[line - 1].index(needle) + 1

    assert [(f.code, f.line, f.column) for f in new_findings(data)] == [
        ("E-FILE-SIZE", None, None),
        ("E-FINAL-NEWLINE", None, None),
        ("E-ENCODING", 1, None),
        ("E-PLACEHOLDER", PURPOSE_LINE, column(PURPOSE_LINE, "TODO")),
        ("E-HIDDEN-CHAR", PURPOSE_LINE, column(PURPOSE_LINE, "\u200b")),
        ("E-SECRET", WHY_LINE, column(WHY_LINE, aws)),
        ("E-ID-NUMBER", RISKS_LINE, column(RISKS_LINE, bsn)),
    ]


# --- the front matter in validate_file


def test_without_front_matter_only_the_file_and_content_checks_still_run():
    data = replace("---\n# AIVEN", "--- \n# AIVEN")(BASE) + b"TODO\n"
    codes = {f.code for f in findings_of(data)}
    assert {"E-FM-MISSING", "E-PLACEHOLDER"} <= codes
    assert not codes & {"E-FILENAME", "E-FIELD-MISSING", "E-YAML", "E-FM-NON-ASCII"}


def test_e_fm_missing_is_reported_once_at_line_one():
    found = [f for f in findings_of(b"no front matter here\n") if f.code == "E-FM-MISSING"]
    assert [(f.line, f.column, f.params) for f in found] == [(1, None, {})]
    for lang in ("en", "nl"):
        assert "---" in message(found[0], lang)


def test_a_file_that_is_all_nesting_is_a_finding_and_not_a_hang():
    started = time.perf_counter()
    findings = findings_of(b"---\n" + b"[" * 65_000 + b"\n---\n")
    assert time.perf_counter() - started < 5  # reading all of it takes minutes
    assert ("E-YAML", 2) in {(f.code, f.line) for f in findings}


E_FILENAME_SKIPPED = {
    "yaml feature": edit_line("agent: invoice-reminder", "invoice-reminder", "&a invoice-reminder"),
    "wrong type": edit_line("agent: invoice-reminder", "invoice-reminder", "5"),
    "missing": edit_line("agent: invoice-reminder", "agent:", "# agent:"),
    "placeholder": edit_line("agent: invoice-reminder", "invoice-reminder", "TODO"),
    "no front matter": replace("---\n# AIVEN", "--- \n# AIVEN"),
    # Ruling R28: a bad id is E-AGENT-ID, and the file name is not also wrong.
    "too short": edit_line("agent: invoice-reminder", "invoice-reminder", "ab"),
    "reserved": edit_line("agent: invoice-reminder", "invoice-reminder", "admin"),
    "too long": edit_line("agent: invoice-reminder", "invoice-reminder", LONG_AGENT),
    "capital": edit_line("agent: invoice-reminder", "invoice-reminder", "Invoice-reminder"),
}


@pytest.mark.parametrize("mutation", E_FILENAME_SKIPPED.values(), ids=E_FILENAME_SKIPPED)
def test_e_filename_needs_a_usable_agent(mutation):
    findings = validate_file(Path("policies/other.md"), mutation(BASE), CFG, CATALOG)
    assert "E-FILENAME" not in {f.code for f in findings}


def test_the_template_gives_the_findings_of_spec_section_9():
    _, *rows = table_after("9. Template self-test")
    findings = validate_file(
        Path("templates/policy-template.md"), TEMPLATE_PATH.read_bytes(), CFG, CATALOG
    )
    assert [(f.severity, f.code, f.line) for f in findings] == [
        (severity, code, None if line == "(file)" else int(line))
        for severity, code, line, _ in rows
    ]
    assert [(f.code, f.line) for f in findings] == [
        ("E-FILENAME", None),
        ("E-PLACEHOLDER", 6),
        ("W-TOOL-NOT-LIVE", 9),
        ("W-TOOL-NOT-LIVE", 10),
        ("W-TOOL-NOT-LIVE", 11),
        ("E-PLACEHOLDER", 25),
        ("E-PLACEHOLDER", 56),
        ("E-PLACEHOLDER", 84),
    ]
    assert findings[0].params == {"name": "policy-template.md", "agent": "invoice-reminder"}
    for finding, (_, _, _, about) in zip(findings, rows, strict=True):
        if finding.code == "E-PLACEHOLDER":
            assert finding.params == {"token": code_spans(about)[0]}
        if finding.code == "W-TOOL-NOT-LIVE":
            wrapper = re.search(r"\(([^)]+)\)", about).group(1)  # "`sheets.read` (Drive)"
            assert finding.params == {"tool": code_spans(about)[0], "wrapper": wrapper}


def test_placeholder_skips_other_checks_for_that_field():
    # The principal of the template holds REPLACE_ME_AGENTS_PROJECT, which is no agents project.
    # A field that holds a placeholder skips its other checks (validator-spec 3.1): E-PLACEHOLDER
    # on line 6, and no E-PRINCIPAL.
    template = TEMPLATE_PATH.read_bytes()
    principal_line = line_of(template.decode("utf-8"), "principal: agent-")
    path = Path("policies/invoice-reminder.md")
    found = validate_file(path, template, CFG, CATALOG)
    assert principal_line == 6
    assert ("E-PLACEHOLDER", principal_line) in {(f.code, f.line) for f in found}
    assert "E-PRINCIPAL" not in {f.code for f in found}
    # The control: with another project in place of the placeholder, the field is checked.
    filled = template.replace(b"REPLACE_ME_AGENTS_PROJECT", b"other-project", 1)
    assert [(f.code, f.line) for f in validate_file(path, filled, CFG, CATALOG)].count(
        ("E-PRINCIPAL", principal_line)
    ) == 1


@pytest.mark.parametrize("mutation", BOUNDARY_CASES)
def test_a_number_on_the_boundary_that_is_allowed_yields_no_new_finding(mutation):
    assert new_findings(mutation(BASE)) == []


@pytest.mark.parametrize("mutation", BODY_ALLOWED)
def test_body_text_that_is_allowed_yields_no_new_finding(mutation):
    assert new_findings(mutation(BASE)) == []


def test_a_bad_agent_id_is_one_finding_also_when_the_file_has_that_name():
    # Ruling R28: one defect, one code. The file name matches here, so it is only the principal
    # of invoice-reminder that would have been wrong as well.
    data = edit_line("agent: invoice-reminder", "invoice-reminder", "ab")(BASE)
    found = validate_file(Path("policies/ab.md"), data, CFG, CATALOG)
    assert {f.code for f in found} == {"E-AGENT-ID", "W-TOOL-NOT-LIVE"}


def test_the_rules_report_alongside_the_findings_of_the_front_matter_in_one_sorted_list():
    data = together(
        set_value("max_class", "R2", "R3"),
        set_value("runs_per_day", "1", "11"),
        replace("  - gmail.send\nforbidden:", "  - gmail.send\n  - drive.reed\nforbidden:"),
        edit_line("- drive.delete", "# required", f"# r{CYRILLIC_E}quired"),
    )(BASE)
    found = findings_of(data)
    assert [(f.code, f.line) for f in found] == [
        ("E-MAX-CLASS-R3", MAX_CLASS_LINE),
        ("W-TOOL-NOT-LIVE", SHEETS_LINE),
        ("W-TOOL-NOT-LIVE", DRAFT_LINE),
        ("W-TOOL-NOT-LIVE", SEND_LINE),
        ("E-TOOL-UNKNOWN", TOOLS_END),
        ("E-FM-NON-ASCII", DELETE_LINE + 1),
        ("E-RANGE", RUNS_LINE + 1),
    ]


# --- a file too large to read through (ruling R40)


def test_a_file_over_a_mebibyte_is_not_read_through(monkeypatch):
    # Read through, 2 MiB of tabs is one hidden-character finding per byte: minutes, and gigabytes.
    monkeypatch.setattr("aiven.policy.validate.decode_text", lambda _: pytest.fail("decoded"))
    data = b"\t" * (2 * 1024 * 1024 - 1) + b"\n"
    started = time.perf_counter()
    findings = findings_of(data)
    assert time.perf_counter() - started < 1
    assert [(f.code, f.line, f.params) for f in findings] == [
        ("E-FILE-SIZE", None, {"size": str(len(data))})
    ]


def test_a_file_over_a_mebibyte_still_gets_the_checks_of_its_bytes_and_no_others():
    data = b"ok TODO\n\xff\na\rb \t\n" + b"[" * 1_048_576  # a bad byte, a CR, no final newline
    findings = findings_of(data)
    assert [(f.code, f.line) for f in findings] == [
        ("E-FILE-SIZE", None),
        ("E-FINAL-NEWLINE", None),
        ("E-ENCODING", 2),
        ("E-LINE-ENDINGS", 3),
    ]  # no E-PLACEHOLDER, no E-HIDDEN-CHAR, no E-FM-MISSING: the text is not looked at


def test_a_file_up_to_the_limit_gets_every_check_and_one_byte_more_does_not(monkeypatch):
    monkeypatch.setattr("aiven.policy.validate.MAX_SCANNED_BYTES", 5000)

    def file_of(size: int) -> bytes:
        return b"TODO\n" + b"x" * (size - 6) + b"\n"

    at_limit = {f.code for f in findings_of(file_of(5000))}
    assert {"E-PLACEHOLDER", "E-FM-MISSING"} <= at_limit
    assert findings_of(file_of(5001)) == []  # its bytes are fine, and its text is not looked at
