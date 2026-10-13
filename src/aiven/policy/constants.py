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

# A policy file is at most 64 KiB (validator-spec 3.1, E-FILE-SIZE).
MAX_FILE_BYTES = 64 * 1024

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
