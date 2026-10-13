"""The validator's single entry point: every check, and one sorted list of findings.

Task by task the other checks join the two here (front matter, fields, tools, limits, body). The
CLI and `verify` call `validate_file` and nothing below it.
"""

from pathlib import Path

from aiven.policy.catalog import Catalog
from aiven.policy.config import PlatformConfig
from aiven.policy.constants import MAX_SCANNED_BYTES
from aiven.policy.content import KIND_CODES, ContentHit, scan
from aiven.policy.fileformat import check_bytes, check_file, decode_text
from aiven.policy.findings import Finding
from aiven.policy.frontmatter import check_filename, load, split
from aiven.policy.model import build_policy


def validate_file(path: Path, data: bytes, cfg: PlatformConfig, catalog: Catalog) -> list[Finding]:
    """All findings for the policy file `data` that is called `path`.

    The file checks, the content checks and the front matter checks need neither `cfg` nor
    `catalog`; the field, tool, limit and scope rules do (`cfg` for the principal, `catalog` for
    the tools). The result is in report order: findings about the whole file first, then by line,
    then by column, then by code.

    A file over `MAX_SCANNED_BYTES` is invalid by its size, and is not read through: it gets the
    checks of its bytes and nothing else, so that a huge file cannot cost minutes and gigabytes.
    """
    if len(data) > MAX_SCANNED_BYTES:
        return sorted(check_bytes(path, data), key=_report_order)
    text = decode_text(data)
    findings = check_file(path, data, text)
    findings.extend(_content_finding(str(path), hit) for hit in scan(text))
    findings.extend(_front_matter_findings(path, data, text, cfg, catalog))
    return sorted(findings, key=_report_order)


def _front_matter_findings(
    path: Path, data: bytes, text: str, cfg: PlatformConfig, catalog: Catalog
) -> list[Finding]:
    """The front matter checks (section 3.2), the field, tool, limit and scope rules (3.3 to 3.5),
    and E-FILENAME, which needs the agent id.

    This is where every check that needs the front matter belongs. When there is none, or it
    cannot be trusted (`split` or `load` gives no data), they are all skipped (section 1): what
    still runs are the file, hidden-character, placeholder and content-safety checks above.
    """
    parts = split(text)
    if parts is None:
        return [Finding("E-FM-MISSING", "error", str(path), 1)]
    front, _body, _body_line = parts
    loaded = load(front, path)
    findings = list(loaded.findings)
    if loaded.data is None:
        return findings
    _policy, rule_findings = build_policy(loaded, data, cfg, catalog, path)
    findings.extend(rule_findings)
    # An agent that is not a valid id is E-AGENT-ID, and the file name is not also wrong: one
    # defect, one code (ruling R28). A placeholder agent is skipped by check_filename itself.
    if all(found.code != "E-AGENT-ID" for found in rule_findings):
        findings.extend(check_filename(path, loaded))
    # Task 1.5 adds the body checks here: the body starts on _body_line, and the generated
    # sections are rendered from the policy.
    return findings


def _content_finding(path: str, hit: ContentHit) -> Finding:
    code = KIND_CODES[hit.kind]
    # E-ID-NUMBER names no kind: its message is about a BSN, and nothing else is needed.
    params = {} if code == "E-ID-NUMBER" else {"kind": hit.kind}
    return Finding(code, "error", path, hit.line, hit.column, params)


def _report_order(finding: Finding) -> tuple[bool, int, int, str]:
    return (finding.line is not None, finding.line or 0, finding.column or 0, finding.code)
