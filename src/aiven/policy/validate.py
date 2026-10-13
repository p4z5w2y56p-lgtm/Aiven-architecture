"""The validator's single entry point: every check, and one sorted list of findings.

The file checks, the content checks, the front matter, the field, tool, limit and scope rules and
the body checks are all run from here. The CLI calls `validate_file`, which gives the findings.
`verify` calls `validate_policy`, which is the same run and also gives the `Policy` that the front
matter builds, so that the policy and the findings come from one run of the checks and no check
runs twice. The checks below these two are not called from outside; `report_order` is the one
other name that is, because `verify` sorts the findings it adds with it.
"""

from dataclasses import dataclass, field
from pathlib import Path

from aiven.policy.body import check_body
from aiven.policy.catalog import Catalog
from aiven.policy.config import PlatformConfig
from aiven.policy.constants import MAX_SCANNED_BYTES
from aiven.policy.content import KIND_CODES, ContentHit, scan
from aiven.policy.fileformat import check_bytes, check_file, decode_text
from aiven.policy.findings import Finding
from aiven.policy.frontmatter import FrontMatter, check_filename, load, split
from aiven.policy.model import Policy, build_policy


@dataclass(frozen=True)
class Validated:
    """What one run of the checks gave (`validate_policy`).

    - `policy` is what the front matter builds (model.py says when there is none). A file with
      errors can have one.
    - `findings` are in report order.
    - `tool_lines` are the file lines of the entries of `tools`, by the text of the entry, and the
      line of the first entry for a tool that is written twice. A `Policy` carries no line map
      (ruling R55), and `verify` puts E-TOOL-NOT-LIVE on the line of its tool. They hold text of
      the file, so they are not in the repr.
    """

    policy: Policy | None
    findings: list[Finding]
    tool_lines: dict[str, int] = field(repr=False)


def validate_file(path: Path, data: bytes, cfg: PlatformConfig, catalog: Catalog) -> list[Finding]:
    """All findings for the policy file `data` that is called `path`.

    The file checks, the content checks and the front matter checks need neither `cfg` nor
    `catalog`; the field, tool, limit and scope rules do (`cfg` for the principal, `catalog` for
    the tools). The result is in report order: findings about the whole file first, then by line,
    then by column, then by code.

    A file over `MAX_SCANNED_BYTES` is invalid by its size, and is not read through: it gets the
    checks of its bytes and nothing else, so that a huge file cannot cost minutes and gigabytes.

    This is `validate_policy` without the policy.
    """
    return validate_policy(path, data, cfg, catalog).findings


def validate_policy(path: Path, data: bytes, cfg: PlatformConfig, catalog: Catalog) -> Validated:
    """The findings of `validate_file`, with the policy and the tool lines of the same run."""
    if len(data) > MAX_SCANNED_BYTES:
        return Validated(None, sorted(check_bytes(path, data), key=report_order), {})
    text = decode_text(data)
    findings = check_file(path, data, text)
    findings.extend(_content_finding(str(path), hit) for hit in scan(text))
    policy, front_findings, tool_lines = _front_matter_checks(path, data, text, cfg, catalog)
    findings.extend(front_findings)
    return Validated(policy, sorted(findings, key=report_order), tool_lines)


def _front_matter_checks(
    path: Path, data: bytes, text: str, cfg: PlatformConfig, catalog: Catalog
) -> tuple[Policy | None, list[Finding], dict[str, int]]:
    """The policy, the findings and the tool lines of everything that needs the front matter.

    These are the front matter checks (section 3.2), the field, tool, limit and scope rules (3.3 to
    3.5), E-FILENAME, which needs the agent id, and the body checks (3.7).

    This is where every check that needs the front matter belongs. When there is none, or it
    cannot be trusted (`split` or `load` gives no data), they are all skipped (section 1, ruling
    R27): what still runs are the file, hidden-character, placeholder and content-safety checks
    above.
    """
    parts = split(text)
    if parts is None:
        return None, [Finding("E-FM-MISSING", "error", str(path), 1)], {}
    front, body, body_line = parts
    loaded = load(front, path)
    findings = list(loaded.findings)
    if loaded.data is None:
        return None, findings, {}
    policy, rule_findings = build_policy(loaded, data, cfg, catalog, path)
    findings.extend(rule_findings)
    # An agent that is not a valid id is E-AGENT-ID, and the file name and the title are not also
    # wrong: one defect, one code (ruling R28). A placeholder agent is the same, and is skipped by
    # check_filename itself.
    named = all(found.code != "E-AGENT-ID" for found in rule_findings)
    if named:
        findings.extend(check_filename(path, loaded))
    # The body is judged against the generated sections only when the front matter has no error
    # (ruling R29): a render from an invalid front matter is noise. Warnings do not stop it, and
    # neither does E-PLACEHOLDER (a check of the file) or E-FILENAME. The checks that need the
    # policy are skipped without one (ruling R33), and E-BODY-TITLE for an agent that is not usable.
    clean = all(found.severity != "error" for found in (*loaded.findings, *rule_findings))
    usable = named and "agent" not in loaded.placeholders
    findings.extend(check_body(body, body_line, policy, catalog, path, title=usable, drift=clean))
    return policy, findings, _tool_lines(loaded)


def _tool_lines(front: FrontMatter) -> dict[str, int]:
    """The file line of each entry of `tools`, by its text. A tool written twice keeps its first.

    `load` keeps the list in `data` only when every entry is a string, and then every entry has a
    line, by its place in the list (`tools.0`, `tools.1`, ...).
    """
    lines: dict[str, int] = {}
    for number, tool in enumerate((front.data or {}).get("tools", ())):
        lines.setdefault(tool, front.lines[f"tools.{number}"])
    return lines


def _content_finding(path: str, hit: ContentHit) -> Finding:
    code = KIND_CODES[hit.kind]
    # E-ID-NUMBER names no kind: its message is about a BSN, and nothing else is needed.
    params = {} if code == "E-ID-NUMBER" else {"kind": hit.kind}
    return Finding(code, "error", path, hit.line, hit.column, params)


def report_order(finding: Finding) -> tuple[bool, int, int, str]:
    """The sort key of a report: findings about the whole file first, then line, column, code."""
    return (finding.line is not None, finding.line or 0, finding.column or 0, finding.code)
