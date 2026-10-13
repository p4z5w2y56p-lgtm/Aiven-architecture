"""Platform constants v1 (validator-spec section 6), and the other fixed values the checks use.

Changing a constant means a new validator version, reviewed and signed the same way.

Values that are set at deploy are not constants and do not belong here: the agents project, the
trusted authors, the gateway principal, the Sandbox drive ID and the agent mailbox. The first
four live in `PlatformConfig`.
"""

SCHEMA = "aiven-policy/v1"

# Matthijs is the only signer; there is no second approver, so R3 stays disabled.
SIGNER = "matthijs"
SIGNER_NAME = "Matthijs van Hoorn"
NAMESPACE = "aiven-policy-v1"

# Classes a policy may use. R3 is disabled in v1; R4 is never allowed.
POLICY_CLASSES = ("R0", "R1", "R2")

FORBIDDEN_BASELINE = ("payments.*", "drive.delete", "drive.share", "gmail.send_bulk")

# These namespaces count as R4 for every agent, whatever a file says.
RESERVED_NAMESPACES = (
    "payments.*",
    "policy.*",
    "audit.*",
    "killswitch.*",
    "iam.*",
    "secrets.*",
    "agentbuilder.permissions",
)

RESERVED_AGENT_IDS = frozenset(
    {
        "admin",
        "all",
        "audit",
        "control",
        "gateway",
        "killswitch",
        "matthijs",
        "policy",
        "system",
        "template",
    }
)

PUBLIC_MAIL_DOMAINS = frozenset(
    {
        "gmail.com",
        "googlemail.com",
        "outlook.com",
        "hotmail.com",
        "hotmail.nl",
        "live.com",
        "live.nl",
        "msn.com",
        "yahoo.com",
        "icloud.com",
        "me.com",
        "proton.me",
        "protonmail.com",
        "gmx.com",
        "gmx.net",
        "aol.com",
        "ziggo.nl",
        "kpnmail.nl",
        "planet.nl",
        "home.nl",
        "xs4all.nl",
    }
)

# The Shared Drive that holds everything agents can reach. Its ID is set at deploy.
DRIVE_ROOT = "AIVEN Architecture Sandbox"

# Phase 1: agents may email @aivenstudios.com addresses only.
PHASE1_EMAIL_DOMAIN = "aivenstudios.com"

UNTRUSTED_INPUT_MODES = ("strict", "taint")
UNTRUSTED_INPUT_DEFAULT = "strict"

# A day is a calendar day in this time zone.
TIMEZONE = "Europe/Amsterdam"

# Bulk email is more than this many recipients in one message.
BULK_RECIPIENTS = 3

SHADOW_DEFAULT = 10

SNAPSHOT_RETENTION_DAYS = 30
AUDIT_RETENTION_YEARS = 1

# Allowed range (min, max), inclusive, per numeric front matter field. Keyed by field path.
CEILINGS: dict[str, tuple[int, int]] = {
    "version": (1, 9999),
    "limits.emails_per_day": (0, 50),
    "limits.records_per_run": (0, 200),
    "limits.spend_eur_per_run": (0, 0),
    "limits.max_runtime_s": (30, 900),
    "limits.runs_per_day": (1, 10),
    "shadow.min_runs": (1, 100),
}

# Allowed number of entries (min, max), inclusive, per list field.
LIST_SIZES: dict[str, tuple[int, int]] = {
    "tools": (1, 20),
    "scope.email_to": (1, 50),
}

# The shape of an agent id (validator-spec 3.3, E-AGENT-ID): 3 to 24 characters, and this pattern.
# Reserved ids (RESERVED_AGENT_IDS) are not valid either. Patterns are matched with fullmatch.
AGENT_ID_LENGTH = (3, 24)
AGENT_ID_PATTERN = "[a-z][a-z0-9]*(-[a-z0-9]+)*"

# The shape of a Drive folder ID (validator-spec 3.3, scope.drive_folder_id), for fullmatch.
DRIVE_FOLDER_ID_PATTERN = "[A-Za-z0-9_-]{10,100}"

# The tools that need a scope field (validator-spec 3.3, E-SCOPE-MISSING): exact action ids, or
# `namespace.*`. The folder path is needed with the folder ID. A field that no listed tool needs
# is unused (W-SCOPE-UNUSED).
SCOPE_TOOLS: dict[str, tuple[str, ...]] = {
    "drive_folder_id": ("drive.*", "sheets.*"),
    "drive_folder_path": ("drive.*", "sheets.*"),
    "email_to": ("gmail.draft", "gmail.send"),
}

# The tools that use `emails_per_day` (validator-spec 3.5, E-LIMIT-CONFLICT, W-LIMIT-UNUSED).
EMAIL_LIMIT_TOOLS = ("gmail.send",)

# The classes that "an R1+ tool" has in a policy: the tools that use `records_per_run`.
R1_PLUS = ("R1", "R2")

# How the catalog's wrapper ids are written in messages (validator-spec 5 and 9).
WRAPPER_NAMES = {"drive": "Drive", "email": "Email", "agentbuilder": "Agent Builder"}

# The `##` sections of a policy body, in this order (validator-spec 3.7, E-BODY-SECTIONS). The first
# three are free text, and the last two are generated from the front matter (section 7).
SECTIONS = (
    "Purpose",
    "Why each tool",
    "Data and risks",
    "Enforced rules (generated)",
    "Sign-off (generated)",
)
FREE_SECTIONS = SECTIONS[:3]
GENERATED_SECTIONS = SECTIONS[3:]

# A free-text section has at least this many characters of text (validator-spec 3.7, E-BODY-EMPTY).
MIN_SECTION_CHARS = 20

# A policy file is at most 64 KiB (validator-spec 3.1, E-FILE-SIZE).
MAX_FILE_BYTES = 64 * 1024

# A file beyond this (1 MiB, 16 times the limit) is not read through. It is invalid by its size
# alone, and checking it line by line would only cost time and memory: every hidden character,
# placeholder or secret in it is a finding of its own, so a file of tabs is a million findings. Up
# to this size a file is still checked in full, so that its author sees everything at once. Only
# the checks of the bytes (E-FILE-SIZE, E-ENCODING, E-LINE-ENDINGS, E-FINAL-NEWLINE) still run.
MAX_SCANNED_BYTES = 16 * MAX_FILE_BYTES

# Hidden characters (validator-spec 3.1, E-HIDDEN-CHAR): every character in these Unicode
# categories, and in these code point ranges (inclusive, in the order of the spec), except LF and
# the normal space (see `chars.is_hidden`). The ranges are needed because those characters are
# not in the categories: the tag characters are mostly unassigned, and the others are marks and
# letters that draw nothing.
HIDDEN_CATEGORIES = frozenset({"Cc", "Cf", "Zl", "Zp", "Zs"})
HIDDEN_RANGES = (
    (0xE0000, 0xE007F),  # tag characters
    (0x034F, 0x034F),  # combining grapheme joiner
    (0x115F, 0x115F),  # Hangul choseong filler
    (0x1160, 0x1160),  # Hangul jungseong filler
    (0x3164, 0x3164),  # Hangul filler
    (0xFFA0, 0xFFA0),  # halfwidth Hangul filler
    (0xFE00, 0xFE0F),  # variation selectors
    (0xE0100, 0xE01EF),  # variation selectors supplement
)
