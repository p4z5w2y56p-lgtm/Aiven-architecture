"""The limit and scope rules (validator-spec 3.3 and 3.5).

Each case runs `build_policy` on a small front matter (tests/support/rules.py). The base lists
sheets.read, gmail.draft and gmail.send, allows 10 emails a day and 10 records a run, and has all
three scope fields. A case changes one thing, and the rules report what follows from it.
"""

import pytest

from aiven.policy import constants
from tests.support.frontmatter import DATA, front_without, swap
from tests.support.policies import FOLDER_ID
from tests.support.rules import CATALOG, check, run_front, setting, with_tools

ROOT = constants.DRIVE_ROOT
LIMITS = dict(DATA["limits"])
SCOPE_FIELDS = ("drive_folder_id", "drive_folder_path", "email_to")
FULL_SCOPE = dict(DATA["scope"])


def limits(**values):
    return lambda data: data["limits"].update(values)


def scope(**values):
    return lambda data: data["scope"].update(values)


def without_scope(*names: str):
    """A change that drops these scope fields."""

    def change(data):
        for name in names:
            del data["scope"][name]

    return change


def tools_without_scope(*tools: str):
    """A change that lists these tools and has no scope at all."""

    def change(data):
        data["tools"] = list(tools)
        del data["scope"]

    return change


def missing(run):
    """(field, tool) of every E-SCOPE-MISSING of the run, in the order they were made."""
    return [
        (f.params["field"], f.params["tool"]) for f in run.findings if f.code == "E-SCOPE-MISSING"
    ]


def reads(*tools: str, **more):
    """A change for a policy that only reads: R0, with no emails and no records a run."""
    quiet = {**LIMITS, "emails_per_day": 0, "records_per_run": 0}
    return with_tools(*tools, max_class="R0", limits=quiet, **more)


# --- spend


@pytest.mark.parametrize("spend", [1, 5, 50, 10**9])
def test_any_spend_but_zero_is_e_limit_spend_and_not_e_range(spend):
    run = check(setting("limits.spend_eur_per_run", spend))
    assert run.places() == [("E-LIMIT-SPEND", run.line("spend_eur_per_run:"))]
    assert run.params("E-LIMIT-SPEND") == {}


# --- E-LIMIT-CONFLICT: a limit of 0 for a tool that needs at least 1


def test_gmail_send_with_no_emails_a_day_is_a_conflict():
    run = check(limits(emails_per_day=0))
    assert run.places() == [("E-LIMIT-CONFLICT", run.line("emails_per_day:"))]
    assert run.params("E-LIMIT-CONFLICT") == {"limit": "emails_per_day", "tool": "gmail.send"}


def test_a_tool_that_changes_records_with_no_records_a_run_is_a_conflict():
    # The first R1 or R2 tool in the order of the file: gmail.draft comes before gmail.send.
    run = check(limits(records_per_run=0))
    assert run.places() == [("E-LIMIT-CONFLICT", run.line("records_per_run:"))]
    assert run.params("E-LIMIT-CONFLICT") == {"limit": "records_per_run", "tool": "gmail.draft"}


def test_two_limits_of_zero_are_two_conflicts_one_for_each_limit():
    run = check(limits(emails_per_day=0, records_per_run=0))
    assert run.places() == [
        ("E-LIMIT-CONFLICT", run.line("emails_per_day:")),
        ("E-LIMIT-CONFLICT", run.line("records_per_run:")),
    ]
    assert [f.params["limit"] for f in run.findings if f.code == "E-LIMIT-CONFLICT"] == [
        "emails_per_day",
        "records_per_run",
    ]


@pytest.mark.parametrize(
    ("tools", "first"),
    [
        (["gmail.send", "gmail.draft"], "gmail.send"),  # R2 counts as R1+
        (["sheets.read", "drive.create", "gmail.send"], "drive.create"),
        (["gmail.send"], "gmail.send"),
        (
            ["agentbuilder.read", "agentbuilder.publish", "agentbuilder.create"],
            "agentbuilder.publish",
        ),
    ],
)
def test_the_tool_of_a_conflict_is_the_first_r1_or_r2_tool_in_the_order_of_the_file(tools, first):
    run = check(with_tools(*tools, limits={**LIMITS, "records_per_run": 0}))
    assert run.params("E-LIMIT-CONFLICT") == {"limit": "records_per_run", "tool": first}


@pytest.mark.parametrize(
    ("tools", "zero"),
    [
        (["sheets.read", "gmail.draft"], "emails_per_day"),  # no gmail.send: no email limit needed
        (["sheets.read", "gmail.read"], "records_per_run"),  # only reads
        (["gmail.send_bulk", "sheets.read"], "emails_per_day"),  # R3 is no tool (ruling R33)
        (["drive.move", "sheets.read"], "records_per_run"),
    ],
)
def test_a_limit_of_zero_is_fine_when_no_tool_needs_it(tools, zero):
    run = check(with_tools(*tools, limits={**LIMITS, zero: 0}))
    assert "E-LIMIT-CONFLICT" not in run.codes()


# --- W-LIMIT-UNUSED: a limit above 0 that no tool uses


def test_emails_a_day_without_gmail_send_is_unused():
    run = check(with_tools("sheets.read", "gmail.draft", max_class="R1"))
    assert run.places() == [("W-LIMIT-UNUSED", run.line("emails_per_day:"))]
    assert run.params("W-LIMIT-UNUSED") == {"limit": "emails_per_day", "value": "10"}


def test_records_a_run_without_a_tool_that_changes_records_is_unused():
    run = check(with_tools("sheets.read", max_class="R0", limits={**LIMITS, "emails_per_day": 0}))
    assert run.lines_of("W-LIMIT-UNUSED") == [run.line("records_per_run:")]
    assert run.params("W-LIMIT-UNUSED") == {"limit": "records_per_run", "value": "10"}


def test_each_unused_limit_is_one_warning():
    run = check(with_tools("sheets.read", "gmail.read", max_class="R0"))
    assert run.lines_of("W-LIMIT-UNUSED") == [
        run.line("emails_per_day:"),
        run.line("records_per_run:"),
    ]


def test_gmail_send_alone_uses_both_limits():
    # It is R2, so it is an R1+ tool for the records too, and a send counts as an email.
    assert "W-LIMIT-UNUSED" not in check(with_tools("gmail.send", max_class="R2")).codes()


@pytest.mark.parametrize(("limit", "value"), [("emails_per_day", 51), ("records_per_run", 201)])
def test_a_limit_out_of_range_is_e_range_and_not_also_unused(limit, value):
    # Ruling R45: a value that fails E-RANGE skips the warnings of its field.
    run = check(with_tools("sheets.read", max_class="R0", limits={**LIMITS, limit: value}))
    assert "E-RANGE" in run.codes()
    assert limit not in [f.params["limit"] for f in run.findings if f.code == "W-LIMIT-UNUSED"]


def test_a_tool_that_failed_its_own_rules_uses_no_limit():
    # Ruling R33: gmail.sned is no tool, so emails_per_day is unused (and E-TOOL-UNKNOWN is the
    # error to fix first).
    run = check(with_tools("sheets.read", "gmail.sned", max_class="R0"))
    assert ("W-LIMIT-UNUSED", run.line("emails_per_day:")) in run.places()
    assert "E-TOOL-UNKNOWN" in run.codes()


def test_no_limit_is_judged_against_a_tool_list_that_is_not_there():
    def change(data):
        del data["tools"]
        data["limits"].update(emails_per_day=0, records_per_run=0)

    run = check(change)
    assert run.codes() == []
    assert run.policy is None


# --- E-SCOPE-MISSING

NEEDS_DRIVE = [
    "drive.list",
    "drive.read",
    "sheets.read",
    "drive.create",
    "drive.update",
    "sheets.write",
]
NEEDS_EMAIL = ["gmail.draft", "gmail.send"]
NEEDS_NOTHING = ["gmail.read", "agentbuilder.read", "agentbuilder.create", "agentbuilder.publish"]


def test_the_tools_of_the_three_groups_are_the_grantable_actions_of_the_catalog():
    grantable = {a.id for a in CATALOG.actions.values() if a.cls in ("R0", "R1", "R2")}
    assert grantable == {*NEEDS_DRIVE, *NEEDS_EMAIL, *NEEDS_NOTHING}


@pytest.mark.parametrize("tool", NEEDS_DRIVE)
def test_a_drive_or_sheets_tool_needs_the_folder_id_and_the_folder_path(tool):
    run = check(tools_without_scope(tool))
    assert run.lines_of("E-SCOPE-MISSING") == [1, 1]  # there is no scope, so line 1
    assert missing(run) == [("drive_folder_id", tool), ("drive_folder_path", tool)]


@pytest.mark.parametrize("tool", NEEDS_EMAIL)
def test_gmail_draft_and_gmail_send_need_email_to(tool):
    run = check(tools_without_scope(tool))
    assert run.lines_of("E-SCOPE-MISSING") == [1]
    assert missing(run) == [("email_to", tool)]


@pytest.mark.parametrize("tool", NEEDS_NOTHING)
def test_the_other_tools_need_no_scope(tool):
    assert "E-SCOPE-MISSING" not in check(tools_without_scope(tool)).codes()


def test_each_missing_field_is_one_finding_and_its_tool_is_the_first_that_needs_it():
    order = ("gmail.read", "gmail.send", "sheets.read", "gmail.draft", "drive.list")
    run = check(tools_without_scope(*order))
    assert run.lines_of("E-SCOPE-MISSING") == [1, 1, 1]
    assert missing(run) == [
        ("drive_folder_id", "sheets.read"),
        ("drive_folder_path", "sheets.read"),
        ("email_to", "gmail.send"),
    ]


@pytest.mark.parametrize("name", SCOPE_FIELDS)
def test_a_missing_field_of_a_scope_that_is_there_is_reported_on_the_line_of_scope(name):
    run = check(without_scope(name))
    assert run.places() == [("E-SCOPE-MISSING", run.line("scope:"))]
    assert [field for field, _ in missing(run)] == [name]


def test_the_folder_path_is_missing_too_when_the_folder_id_is_missing_and_needed():
    run = check(lambda data: data.update(scope={"email_to": ["@aivenstudios.com"]}))
    assert missing(run) == [
        ("drive_folder_id", "sheets.read"),
        ("drive_folder_path", "sheets.read"),
    ]
    assert run.lines_of("E-SCOPE-MISSING") == [run.line("scope:")] * 2


def test_a_scope_that_is_there_but_empty_misses_every_field_its_tools_need():
    run = check(lambda data: data.update(scope={}))
    assert run.places() == [("E-SCOPE-MISSING", run.line("scope:"))] * 3


@pytest.mark.parametrize(
    "values",
    [
        {"drive_folder_id": "TODO"},
        {"drive_folder_path": 5},
        {"email_to": 5},
        {"email_to": "TBD"},
    ],
    ids=["placeholder", "wrong type", "wrong type, list", "placeholder, list"],
)
def test_a_field_that_is_written_but_has_no_value_is_not_missing(values):
    # load() has reported it as a placeholder or a wrong type (and ruling R4 gives no policy).
    run = check(scope(**values))
    assert run.places() == []


def test_a_scope_that_is_a_placeholder_or_a_wrong_type_gets_no_scope_findings():
    assert check(setting("scope", "TODO")).places() == []
    assert check(setting("scope", 5)).places() == []


def test_a_tool_that_failed_its_own_rules_needs_no_scope():
    run = check(tools_without_scope("gmail.sned", "drive.move", "drive.*", "payments.pay"))
    assert "E-SCOPE-MISSING" not in run.codes()


# --- W-SCOPE-UNUSED: a scope field that no tool uses


def test_scope_fields_that_no_tool_uses_are_one_warning_each():
    run = check(reads("agentbuilder.read"))
    assert run.places() == [
        ("W-SCOPE-UNUSED", run.line("drive_folder_id:")),
        ("W-SCOPE-UNUSED", run.line("drive_folder_path:")),
        ("W-SCOPE-UNUSED", run.line("email_to:")),
    ]
    assert [f.params["field"] for f in run.findings if f.code == "W-SCOPE-UNUSED"] == list(
        SCOPE_FIELDS
    )


def test_the_email_scope_is_unused_without_gmail_draft_or_gmail_send():
    run = check(reads("sheets.read", "gmail.read"))
    assert run.places() == [("W-SCOPE-UNUSED", run.line("email_to:"))]
    assert run.params("W-SCOPE-UNUSED") == {"field": "email_to"}


def test_the_drive_scope_is_unused_without_a_drive_or_sheets_tool():
    run = check(with_tools("gmail.draft", "gmail.send"))
    assert run.places() == [
        ("W-SCOPE-UNUSED", run.line("drive_folder_id:")),
        ("W-SCOPE-UNUSED", run.line("drive_folder_path:")),
    ]


def test_a_tool_that_failed_its_own_rules_uses_no_scope_field():
    # Ruling R33: drive.move is R3 and so no tool, and nothing is left that needs the folder.
    run = check(with_tools("gmail.draft", "drive.move", max_class="R1"))
    assert run.lines_of("W-SCOPE-UNUSED") == [
        run.line("drive_folder_id:"),
        run.line("drive_folder_path:"),
    ]
    assert "E-TOOL-R3" in run.codes()


def test_a_scope_field_that_is_a_placeholder_is_not_called_unused():
    only_email = {"email_to": ["@aivenstudios.com"], "drive_folder_id": "TODO"}
    run = check(with_tools("gmail.draft", max_class="R1", scope=only_email))
    assert "W-SCOPE-UNUSED" not in run.codes()


@pytest.mark.parametrize("emails", [[], [f"a{n}@aivenstudios.com" for n in range(51)]])
def test_an_email_list_of_the_wrong_size_is_e_range_and_not_also_unused(emails):
    # Ruling R45, for a list.
    run = check(reads("sheets.read", scope={**FULL_SCOPE, "email_to": emails}))
    assert run.places() == [("E-RANGE", run.line("email_to:"))]


# --- scope.drive_folder_id

GOOD_FOLDER_IDS = {
    "ten characters": "a" * 10,
    "a hundred characters": "a" * 100,
    "hyphen and underscore": "ab_cd-ef12",
    "digits and a letter": "0123456789a",
    "both cases": "AbCdEfGhIj",
}


@pytest.mark.parametrize("folder_id", GOOD_FOLDER_IDS.values(), ids=GOOD_FOLDER_IDS)
def test_a_folder_id_of_10_to_100_letters_digits_hyphens_and_underscores_is_fine(folder_id):
    run = check(scope(drive_folder_id=folder_id))
    assert run.places() == []
    assert run.policy.scope.drive_folder_id == folder_id


BAD_FOLDER_IDS = {
    "nine characters": "a" * 9,
    "a hundred and one": "a" * 101,
    "a space inside": "abcde fghij",
    "a slash": "abcde/fghij",
    "a dot": "abcde.fghij",
    "a percent sign": "abcde%fghij",
    "a colon": "abcde:fghij",
    "not ASCII": "abcdefghi\N{LATIN SMALL LETTER E WITH ACUTE}",
}


@pytest.mark.parametrize("folder_id", BAD_FOLDER_IDS.values(), ids=BAD_FOLDER_IDS)
def test_any_other_folder_id_is_a_type_error_that_gives_the_pattern(folder_id):
    run = check(scope(drive_folder_id=folder_id))
    assert run.places() == [("E-FIELD-TYPE", run.line("drive_folder_id:"))]
    assert run.params("E-FIELD-TYPE") == {
        "field": "scope.drive_folder_id",
        "expected": "[A-Za-z0-9_-]{10,100}",
        "found": folder_id,
    }
    assert run.policy is None  # a wrong type (ruling R4)


@pytest.mark.parametrize("written", ['""', '"abcdefghij "', "|\n    abcdefghij"])
def test_a_folder_id_is_matched_as_a_whole(written):
    # The last one is "abcdefghij\n": `$` would let it through, fullmatch does not.
    run = run_front(swap(f"drive_folder_id: {FOLDER_ID}", f"drive_folder_id: {written}"))
    assert [code for code, _ in run.places()] == ["E-FIELD-TYPE"]


@pytest.mark.parametrize("placeholder", ["REPLACE_ME_FOLDER_ID", "TODO", "TBD"])
def test_a_folder_id_that_holds_a_placeholder_is_not_checked(placeholder):
    run = check(scope(drive_folder_id=placeholder))
    assert run.places() == []
    assert run.policy.scope.drive_folder_id == placeholder


# --- scope.drive_folder_path

GOOD_PATHS = {
    "the drive": ROOT,
    "a folder": f"{ROOT} / Invoices",
    "a folder in a folder": f"{ROOT} / Invoices / 2026",
    "a space inside a name": f"{ROOT} / Invoices 2026",
    "two spaces inside a name": f"{ROOT} / Q1  2026",
    "other characters": f"{ROOT} / a-b_c.d (x) & y",
}


@pytest.mark.parametrize("path", GOOD_PATHS.values(), ids=GOOD_PATHS)
def test_the_sandbox_and_the_folders_in_it_are_fine(path):
    assert check(scope(drive_folder_path=path)).places() == []


BAD_PATHS = {
    "another drive": "Other Drive / Invoices",
    "the right words in lower case": ROOT.lower(),
    "no spaces round the slash": f"{ROOT}/Invoices",
    "no space before the slash": f"{ROOT}/ Invoices",
    "no space behind the slash": f"{ROOT} /Invoices",
    "nothing behind the slash": f"{ROOT} / ",
    "a space behind the folder": f"{ROOT} / Invoices ",
    "two spaces before the slash": f"{ROOT}  / Invoices",
    "two spaces behind the slash": f"{ROOT} /  Invoices",
    "a space behind an inner folder": f"{ROOT} / a  / b",
    "a slash inside a name": f"{ROOT} / a/b",
    "an empty part": f"{ROOT} / a /  / b",
    "something in front": f"x {ROOT}",
    "something behind": f"{ROOT}x",
    "a part of the name": "Sandbox",
    "a tab behind a folder": f"{ROOT} / a\t",
}


@pytest.mark.parametrize("path", BAD_PATHS.values(), ids=BAD_PATHS)
def test_any_other_path_is_e_scope_sandbox(path):
    run = run_front(swap(f"drive_folder_path: {ROOT} / Invoices", f'drive_folder_path: "{path}"'))
    assert run.places() == [("E-SCOPE-SANDBOX", run.line("drive_folder_path:"))]
    assert run.params("E-SCOPE-SANDBOX") == {}


def test_a_path_is_matched_as_a_whole():
    # "AIVEN Architecture Sandbox\n": `$` would let it through, fullmatch does not.
    old = f"drive_folder_path: {ROOT} / Invoices"
    run = run_front(swap(old, f"drive_folder_path: |\n    {ROOT}"))
    assert [code for code, _ in run.places()] == ["E-SCOPE-SANDBOX"]


@pytest.mark.parametrize("placeholder", ["TODO", f"{ROOT} / REPLACE_ME_FOLDER"])
def test_a_path_that_holds_a_placeholder_is_not_checked(placeholder):
    assert check(scope(drive_folder_path=placeholder)).places() == []


# --- scope.email_to: one entry at a time

FINE_EMAILS = [
    "@aivenstudios.com",
    "a@aivenstudios.com",
    "first.last+tag@aivenstudios.com",
    "a_b%c-d@aivenstudios.com",
    "0@aivenstudios.com",
]

MALFORMED_EMAILS = [
    "@Aivenstudios.com",
    "*@x.nl",
    "A@aivenstudios.com",
    "a@Aivenstudios.com",
    "@x",
    "@",
    "",
    "a@",
    "a@b@c.nl",
    "a b@x.nl",
    "@x.nl.",
    "@.x.nl",
    "@x..nl",
    "@-x.nl",
    "@x-.nl",
    "@x_y.nl",
    "@*.nl",
    "*",
    "@*",
    "x.nl",
    "a@x",
    "a@@aivenstudios.com",
    "<a@x.nl>",
    "a@x.nl,b@x.nl",
    " a@x.nl",
    "a@x.nl ",
    "a@x.n\N{LATIN SMALL LETTER E WITH ACUTE}l",
]

EXTERNAL_EMAILS = [
    "@client.nl",
    "a@client.nl",
    "@mail.aivenstudios.com",
    "a@mail.aivenstudios.com",
    "@aivenstudios.nl",
    "@aivenstudios.co",
    "@aivenstudios.com.evil.nl",
    "@evilaivenstudios.com",
    "@xn--bcher-kva.nl",  # punycode is the way to write an international domain
    "a@xn--bcher-kva.nl",
    "a@gmail.com",  # an address at a public service is external, a domain there is public
    "john.doe@outlook.com",
]


def emails(*entries: str):
    return scope(email_to=list(entries))


@pytest.mark.parametrize("entry", FINE_EMAILS)
def test_an_address_or_a_domain_of_aivenstudios_com_is_fine(entry):
    assert check(emails(entry)).places() == []


@pytest.mark.parametrize("entry", MALFORMED_EMAILS, ids=repr)
def test_an_entry_that_is_malformed_in_upper_case_or_with_a_wildcard_is_e_scope_email_only(entry):
    run = check(emails(entry))
    assert run.places() == [("E-SCOPE-EMAIL", run.entry("scope.email_to", entry))]
    assert run.params("E-SCOPE-EMAIL") == {"entry": entry}


@pytest.mark.parametrize("domain", sorted(constants.PUBLIC_MAIL_DOMAINS))
def test_a_domain_entry_of_a_public_mail_service_is_e_scope_email_public_only(domain):
    entry = "@" + domain
    run = check(emails(entry))
    assert run.places() == [("E-SCOPE-EMAIL-PUBLIC", run.entry("scope.email_to", entry))]
    assert run.params("E-SCOPE-EMAIL-PUBLIC") == {"entry": entry}


@pytest.mark.parametrize("entry", EXTERNAL_EMAILS)
def test_any_other_entry_outside_aivenstudios_com_is_e_scope_email_external_only(entry):
    run = check(emails(entry))
    assert run.places() == [("E-SCOPE-EMAIL-EXTERNAL", run.entry("scope.email_to", entry))]
    assert run.params("E-SCOPE-EMAIL-EXTERNAL") == {"entry": entry}


def test_an_entry_is_matched_as_a_whole():
    # "a@aivenstudios.com\n": `$` would let it through, fullmatch does not.
    written = '- "@aivenstudios.com"'
    run = run_front(swap(written, "- |\n      a@aivenstudios.com"))
    assert [code for code, _ in run.places()] == ["E-SCOPE-EMAIL"]


def test_each_entry_is_judged_on_its_own_line():
    run = check(emails("@aivenstudios.com", "*@x.nl", "@gmail.com", "@client.nl"))
    assert run.places() == [
        ("E-SCOPE-EMAIL", run.entry("scope.email_to", "*@x.nl")),
        ("E-SCOPE-EMAIL-PUBLIC", run.entry("scope.email_to", "@gmail.com")),
        ("E-SCOPE-EMAIL-EXTERNAL", run.entry("scope.email_to", "@client.nl")),
    ]


def test_an_entry_that_is_a_placeholder_is_not_checked_and_still_counts():
    run = check(emails("@aivenstudios.com", "TODO"))
    assert run.places() == []
    assert run.policy.scope.email_to == ("@aivenstudios.com", "TODO")


def test_a_repeated_entry_that_is_wrong_is_reported_once():
    assert check(emails("@client.nl", "@client.nl")).codes() == ["E-SCOPE-EMAIL-EXTERNAL"]


def test_the_entries_are_judged_even_when_no_tool_uses_the_list():
    run = check(reads("sheets.read", scope={**FULL_SCOPE, "email_to": ["@client.nl"]}))
    assert run.codes() == ["E-SCOPE-EMAIL-EXTERNAL", "W-SCOPE-UNUSED"]


# --- scope.email_to: how many (E-RANGE)


def addresses(count: int) -> list[str]:
    return [f"a{n}@aivenstudios.com" for n in range(count)]


def test_fifty_entries_are_fine_and_fifty_one_are_e_range_on_the_line_of_the_list():
    assert check(emails(*addresses(50))).places() == []
    run = check(emails(*addresses(51)))
    assert run.places() == [("E-RANGE", run.line("email_to:"))]
    assert run.params("E-RANGE") == {
        "field": "scope.email_to",
        "value": "51",
        "min": "1",
        "max": "50",
    }


def test_an_empty_list_is_e_range_and_not_a_missing_field():
    run = check(emails())
    assert run.places() == [("E-RANGE", run.line("email_to:"))]
    assert run.params("E-RANGE") == {
        "field": "scope.email_to",
        "value": "0",
        "min": "1",
        "max": "50",
    }


def test_repeats_are_not_counted():
    assert check(emails(*addresses(50), *addresses(1))).places() == []


def test_a_list_that_is_not_there_has_no_size():
    assert run_front(front_without("scope.email_to")).codes() == ["E-SCOPE-MISSING"]
