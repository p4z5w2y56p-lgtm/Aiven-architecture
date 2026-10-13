"""Widening (validator-spec 3.6): what a new version allows that the previous signed one did not.

`widening(prev, new)` gives the changes, as strings in a fixed order, and whether shadow mode starts
again. Narrowing is never listed. The policies are made as files from the valid base and read with
the real pipeline (tests/support/variants.py); `PREV` is the base.
"""

import pytest

from aiven.policy.widening import widening
from tests.support import gen
from tests.support.bodies import policy_of
from tests.support.frontmatter import DATA, without
from tests.support.policies import valid_base
from tests.support.rules import setting, with_tools
from tests.support.variants import variant

PREV = variant()
TOOLS = tuple(DATA["tools"])  # sheets.read, gmail.draft, gmail.send
READS_ONLY = with_tools("sheets.read")
FOLDER = DATA["scope"]["drive_folder_path"]  # AIVEN Architecture Sandbox / Invoices
SANDBOX = "AIVEN Architecture Sandbox"
LIMITS = {name: value for name, value in DATA["limits"].items() if name != "spend_eur_per_run"}

# --- the main cases of validator-spec 3.6: what restarts shadow mode, and what does not


def test_added_tool_restarts_shadow():
    new = variant(with_tools(*TOOLS, "drive.read"))
    assert widening(PREV, new) == (["tools: +drive.read"], True)


@pytest.mark.parametrize(("low", "high"), [("R0", "R1"), ("R1", "R2"), ("R0", "R2")])
def test_raised_max_class_restarts_shadow(low, high):
    before = variant(READS_ONLY, setting("max_class", low))
    after = variant(READS_ONLY, setting("max_class", high))
    assert widening(before, after) == ([f"max_class: {low} -> {high}"], True)


@pytest.mark.parametrize(
    ("name", "value"),
    [("emails_per_day", 11), ("records_per_run", 200), ("max_runtime_s", 600), ("runs_per_day", 2)],
)
def test_raised_limit_widens_without_restart(name, value):
    new = variant(setting(f"limits.{name}", value))
    assert widening(PREV, new) == ([f"limits.{name}: {LIMITS[name]} -> {value}"], False)


def test_strict_to_taint_widens():
    new = variant(setting("untrusted_input", "taint"))
    assert widening(PREV, new) == (["untrusted_input: strict -> taint"], False)


def test_removed_tool_is_not_widening():
    new = variant(with_tools("sheets.read", "gmail.draft"))
    assert widening(PREV, new) == ([], False)


# --- what is widening, rule by rule


def test_a_lower_min_runs_widens_without_restart():
    new = variant(setting("shadow.min_runs", 5))
    assert widening(PREV, new) == (["shadow.min_runs: 10 -> 5"], False)


def test_added_tools_are_one_change_in_the_order_of_the_new_policy():
    # A field gives at most one string (ruling R73): the tools are joined by spaces, each with a +.
    new = variant(with_tools("gmail.send", "drive.read", "sheets.read", "drive.create"))
    assert widening(PREV, new) == (["tools: +drive.read +drive.create"], True)


def test_a_tool_that_moves_is_not_added():
    new = variant(with_tools("gmail.send", "sheets.read", "gmail.draft"))
    assert widening(PREV, new) == ([], False)


def test_a_policy_does_not_widen_against_itself():
    assert widening(PREV, PREV) == ([], False)
    assert widening(PREV, policy_of(valid_base())) == ([], False)  # the same fields, another hash


def test_another_folder_id_widens():
    new = variant(setting("scope.drive_folder_id", "0AnotherFolderId1234"))
    assert widening(PREV, new) == (["scope.drive_folder_id: changed"], False)


def test_a_folder_id_where_there_was_none_widens():
    before = variant(without("scope.drive_folder_id"))
    assert widening(before, PREV) == (["scope.drive_folder_id: changed"], False)
    assert widening(PREV, before) == ([], False)  # the other way it is gone, which is narrowing


@pytest.mark.parametrize(
    ("path", "changed"),
    [
        (FOLDER, False),
        (f"{FOLDER} / 2026", False),
        (f"{FOLDER} / 2026 / Q1", False),
        (SANDBOX, True),  # the folder above it
        (f"{SANDBOX} / Receipts", True),  # a folder next to it
        (f"{FOLDER}-old", True),  # starts with the same letters, but is not a folder inside it
        (f"{FOLDER}s", True),
    ],
)
def test_a_folder_path_widens_unless_it_is_the_old_path_or_inside_it(path, changed):
    new = variant(setting("scope.drive_folder_path", path))
    assert widening(PREV, new) == (["scope.drive_folder_path: changed"] if changed else [], False)


def test_a_folder_path_where_there_was_none_widens():
    before = variant(without("scope.drive_folder_path"))
    assert widening(before, PREV) == (["scope.drive_folder_path: changed"], False)
    assert widening(PREV, before) == ([], False)


def test_a_drive_scope_where_there_was_none_widens_with_its_tool():
    before = variant(
        with_tools("gmail.draft", "gmail.send"),
        without("scope.drive_folder_id", "scope.drive_folder_path"),
    )
    assert widening(before, PREV) == (
        [
            "tools: +sheets.read",
            "scope.drive_folder_id: changed",
            "scope.drive_folder_path: changed",
        ],
        True,
    )


def test_new_addresses_are_one_change_in_the_order_of_the_new_list():
    before = variant(setting("scope.email_to", ["a@aivenstudios.com"]))
    after = variant(
        setting(
            "scope.email_to",
            ["c@aivenstudios.com", "a@aivenstudios.com", "b@aivenstudios.com"],
        )
    )
    assert widening(before, after) == (
        ["scope.email_to: +c@aivenstudios.com +b@aivenstudios.com"],
        False,
    )


def test_an_address_in_a_domain_that_was_listed_is_not_a_widening():
    # The old list has @aivenstudios.com, which already allows every address of the domain
    # (ruling R74).
    new = variant(setting("scope.email_to", ["@aivenstudios.com", "a@aivenstudios.com"]))
    assert widening(PREV, new) == ([], False)


def test_a_domain_is_a_widening_even_when_addresses_in_it_were_listed():
    before = variant(setting("scope.email_to", ["a@aivenstudios.com", "b@aivenstudios.com"]))
    after = variant(
        setting("scope.email_to", ["a@aivenstudios.com", "b@aivenstudios.com", "@aivenstudios.com"])
    )
    assert widening(before, after) == (["scope.email_to: +@aivenstudios.com"], False)


def test_a_domain_allows_its_own_addresses_and_not_those_of_a_subdomain_or_another_domain():
    # `@d` matches that exact domain (validator-spec 3.3). Covered and new addresses are mixed.
    new = variant(
        setting(
            "scope.email_to",
            [
                "@aivenstudios.com",
                "a@aivenstudios.com",
                "b@client.nl",
                "c@aivenstudios.com",
                "d@sub.aivenstudios.com",
            ],
        )
    )
    assert widening(PREV, new) == (
        ["scope.email_to: +b@client.nl +d@sub.aivenstudios.com"],
        False,
    )


def test_an_odd_entry_is_not_allowed_by_a_domain_entry():
    # Entries that fail E-SCOPE-EMAIL are still compared. The domain is what follows the first @,
    # and an entry with no @ has none.
    before = variant(setting("scope.email_to", ["@", "@aivenstudios.com"]))
    after = variant(
        setting("scope.email_to", ["@", "@aivenstudios.com", "foo", "a@b@aivenstudios.com"])
    )
    assert widening(before, after) == (["scope.email_to: +foo +a@b@aivenstudios.com"], False)


def test_an_address_is_new_when_the_old_list_has_no_domain_entry_for_it():
    before = variant(setting("scope.email_to", ["a@aivenstudios.com"]))
    after = variant(setting("scope.email_to", ["a@aivenstudios.com", "b@aivenstudios.com"]))
    assert widening(before, after) == (["scope.email_to: +b@aivenstudios.com"], False)


def test_addresses_where_there_were_none_widen():
    before = variant(without("scope.email_to"))
    assert widening(before, PREV) == (["scope.email_to: +@aivenstudios.com"], False)
    one = variant(setting("scope.email_to", ["a@aivenstudios.com"]))
    assert widening(before, one) == (["scope.email_to: +a@aivenstudios.com"], False)


# --- a value that the guard would hide is hidden alone (ruling R77)
#
# The `Finding` that quotes the list hides the whole of it when anything in it looks like a
# credential, a bank detail or an ID number. So `widening` hides such a value itself, in its place,
# and the tools and limits around it stay readable. The values are made at test time.


def test_an_address_that_looks_like_a_bsn_is_hidden_alone():
    bsn = gen.valid_bsn()
    before = variant(setting("scope.email_to", ["z@aivenstudios.com"]))
    after = variant(
        with_tools(*TOOLS, "drive.read"),
        setting("limits.runs_per_day", 2),
        setting(
            "scope.email_to",
            ["z@aivenstudios.com", f"{bsn}@aivenstudios.com", "b@aivenstudios.com"],
        ),
    )
    changes, restart = widening(before, after)
    assert changes == [
        "tools: +drive.read",
        "limits.runs_per_day: 1 -> 2",
        "scope.email_to: +[hidden] +b@aivenstudios.com",
    ]
    assert restart is True
    assert bsn not in "".join(changes)


def test_a_tool_that_looks_like_a_bsn_is_hidden_alone():
    bsn = gen.valid_bsn()
    new = variant(with_tools(*TOOLS, f"drive.{bsn}", "drive.read"))
    changes, _ = widening(PREV, new)
    assert changes == ["tools: +[hidden] +drive.read"]
    assert bsn not in "".join(changes)


def two_bsns() -> tuple[str, str]:
    """Two different numbers that look like a BSN, made now."""
    first = gen.valid_bsn()
    return first, next(other for other in iter(gen.valid_bsn, None) if other != first)


def test_a_number_that_looks_like_a_bsn_is_hidden_alone_in_a_limit_and_in_min_runs():
    bsn = gen.valid_bsn()
    # The new number of a limit that rose is hidden, and so is the old one.
    after = variant(setting("limits.emails_per_day", int(bsn)), setting("limits.runs_per_day", 2))
    changes, _ = widening(PREV, after)
    assert changes == ["limits.emails_per_day: 10 -> [hidden]", "limits.runs_per_day: 1 -> 2"]
    before = variant(setting("limits.records_per_run", int(bsn)))
    changes, _ = widening(before, variant(setting("limits.records_per_run", 10**9)))
    assert changes == ["limits.records_per_run: [hidden] -> 1000000000"]
    # A lower min_runs: the old number is hidden, and so is the new one.
    changes, _ = widening(variant(setting("shadow.min_runs", int(bsn))), PREV)
    assert changes == ["shadow.min_runs: [hidden] -> 10"]
    changes, _ = widening(
        variant(setting("shadow.min_runs", 10**9 - 1)),
        variant(setting("shadow.min_runs", int(bsn))),
    )
    assert changes == ["shadow.min_runs: 999999999 -> [hidden]"]


def test_an_entry_is_hidden_alone_but_still_counts_for_the_comparison():
    # The comparison is of the values as they are written. Two addresses that are hidden look alike
    # in the text, but they are two entries, and an old address that is hidden still keeps the new
    # one with the same text from being new.
    one, two = two_bsns()
    old = variant(setting("scope.email_to", [f"{one}@aivenstudios.com"]))
    new = variant(setting("scope.email_to", [f"{one}@aivenstudios.com", f"{two}@aivenstudios.com"]))
    assert widening(old, new) == (["scope.email_to: +[hidden]"], False)
    assert widening(new, old) == ([], False)
    # The same for the tools: [hidden] is not a tool that was there.
    old_tools = variant(with_tools(*TOOLS, f"drive.{one}"))
    new_tools = variant(with_tools(*TOOLS, f"drive.{one}", f"drive.{two}"))
    assert widening(old_tools, new_tools) == (["tools: +[hidden]"], True)
    assert widening(new_tools, old_tools) == ([], False)


def test_a_hidden_address_in_a_domain_that_was_listed_is_still_no_widening():
    # Ruling R74 for an address that the guard hides. The old list has @aivenstudios.com, so an
    # address in that domain gives no new reach, whatever it looks like. The comparison is of the
    # entry as it is written: as it is shown it is `[hidden]`, which has no domain and would be new.
    bsn = gen.valid_bsn()
    only = variant(setting("scope.email_to", [f"{bsn}@aivenstudios.com"]))
    both = variant(setting("scope.email_to", ["@aivenstudios.com", f"{bsn}@aivenstudios.com"]))
    assert widening(PREV, only) == ([], False)
    assert widening(PREV, both) == ([], False)


def test_each_hidden_entry_keeps_its_own_place_in_the_list():
    one, two = two_bsns()
    new = variant(with_tools(*TOOLS, f"drive.{one}", "drive.read", f"drive.{two}"))
    assert widening(PREV, new) == (["tools: +[hidden] +drive.read +[hidden]"], True)


# --- what is never listed

NARROWINGS = {
    "a tool less": ((), (with_tools("sheets.read", "gmail.draft"),)),
    "the tools in another order": ((), (with_tools("gmail.send", "sheets.read", "gmail.draft"),)),
    "a lower max_class": ((), (with_tools("sheets.read", "gmail.draft", max_class="R1"),)),
    "lower limits": (
        (),
        (
            setting("limits.emails_per_day", 5),
            setting("limits.records_per_run", 5),
            setting("limits.max_runtime_s", 60),
        ),
    ),
    "taint to strict": ((setting("untrusted_input", "taint"),), ()),
    "a higher min_runs": ((), (setting("shadow.min_runs", 20),)),
    "a folder inside the old one": ((), (setting("scope.drive_folder_path", f"{FOLDER} / 2026"),)),
    "a folder inside the drive": ((setting("scope.drive_folder_path", SANDBOX),), ()),
    "no folder": ((), (without("scope.drive_folder_id", "scope.drive_folder_path"),)),
    "fewer addresses": (
        (setting("scope.email_to", ["@aivenstudios.com", "a@aivenstudios.com"]),),
        (),
    ),
    "a domain replaced by an address in it": (
        (),
        (setting("scope.email_to", ["a@aivenstudios.com"]),),
    ),
    "the addresses in another order": (
        (setting("scope.email_to", ["@aivenstudios.com", "a@aivenstudios.com"]),),
        (setting("scope.email_to", ["a@aivenstudios.com", "@aivenstudios.com"]),),
    ),
    "no scope": ((), (without("scope"),)),
    # The spend must be 0 (E-LIMIT-SPEND), so it is not one of the limits that widening lists.
    "a spend that rose": ((), (setting("limits.spend_eur_per_run", 5),)),
}


@pytest.mark.parametrize(("before", "after"), NARROWINGS.values(), ids=NARROWINGS)
def test_narrowing_is_never_listed(before, after):
    assert widening(variant(*before), variant(*after)) == ([], False)


@pytest.mark.parametrize("odd", ["R3", "R4"])
def test_a_class_that_a_policy_may_not_have_is_not_compared(odd):
    # max_class R3 and R4 are E-MAX-CLASS-R3 and E-MAX-CLASS-R4 of their own file, and the policy
    # of that file is still made. They are not ranked: no error here, and no second code for it.
    odd_class = variant(setting("max_class", odd))
    assert widening(PREV, odd_class) == ([], False)
    assert widening(odd_class, PREV) == ([], False)


def test_only_strict_to_taint_is_a_change_of_the_mode():
    # `off` is E-UNTRUSTED-INPUT of its own file, and the policy of that file is still made.
    off = variant(setting("untrusted_input", "off"))
    taint = variant(setting("untrusted_input", "taint"))
    assert widening(PREV, off) == ([], False)
    assert widening(off, taint) == ([], False)
    assert widening(taint, taint) == ([], False)


# --- all of it together

BEFORE = variant(
    with_tools("sheets.read", max_class="R0"),
    setting("limits.emails_per_day", 0),
    setting("limits.records_per_run", 0),
    setting("limits.max_runtime_s", 60),
    setting("scope.drive_folder_id", "0FolderBeforeId1234"),
    setting("scope.email_to", ["z@aivenstudios.com"]),
)
AFTER = variant(
    with_tools("gmail.send", "sheets.read", "drive.read", "gmail.draft", max_class="R2"),
    setting("untrusted_input", "taint"),
    setting("limits.emails_per_day", 20),
    setting("limits.records_per_run", 30),
    setting("limits.max_runtime_s", 600),
    setting("limits.runs_per_day", 2),
    setting("scope.drive_folder_path", SANDBOX),
    setting("scope.email_to", ["z@aivenstudios.com", "b@aivenstudios.com", "a@aivenstudios.com"]),
    setting("shadow.min_runs", 5),
)


def test_changes_come_in_a_fixed_order():
    # Tools (in the order of the new policy), max_class, the limits in the order of the file,
    # the scope (folder ID, folder path, addresses), the mode, min_runs: one string for a field.
    changes, restart = widening(BEFORE, AFTER)
    assert restart is True
    assert changes == [
        "tools: +gmail.send +drive.read +gmail.draft",
        "max_class: R0 -> R2",
        "limits.emails_per_day: 0 -> 20",
        "limits.records_per_run: 0 -> 30",
        "limits.max_runtime_s: 60 -> 600",
        "limits.runs_per_day: 1 -> 2",
        "scope.drive_folder_id: changed",
        "scope.drive_folder_path: changed",
        "scope.email_to: +b@aivenstudios.com +a@aivenstudios.com",
        "untrusted_input: strict -> taint",
        "shadow.min_runs: 10 -> 5",
    ]


def test_a_field_gives_at_most_one_change():
    changes, _ = widening(BEFORE, AFTER)
    assert len(changes) == 11
    fields = [change.split(":")[0] for change in changes]
    assert len(set(fields)) == len(fields)


def test_the_changes_are_plain_ascii_text():
    changes, _ = widening(BEFORE, AFTER)
    assert changes
    assert all(type(change) is str and change.isascii() for change in changes)
    assert all(change.isprintable() for change in changes)
