# AIVEN Architecture Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the Phase 1 safety layer (policy validator, gateway with the Drive wrapper, control UI, email wrapper switched off, agent runtime) and pass the gates in `docs/test-plan.md`.

**Architecture:** One Python codebase with four packages:

- `aiven.policy`: the validator, also embedded in the gateway.
- `aiven.gateway`: a Cloud Run service in `aiven-gateway`.
- `aiven.control_ui`, plus two small functions: these run in `aiven-control`.
- `aiven.agent`: the runtime for agent jobs in `aiven-agents`.

Every rule is decided by one pure function (`decide`). Wrappers do the I/O. Terraform builds all three projects, so agents and gateway can be rebuilt after a budget stop.

**Tech Stack:**

- Python 3.12, uv
- FastAPI + uvicorn, Jinja2
- ruamel.yaml (YAML 1.2), markdown-it-py
- google-auth, google-cloud-firestore, google-cloud-logging, google-cloud-storage, google-cloud-billing
- google-api-python-client (Drive v3, Sheets v4, Gmail v1)
- google-genai (Gemini on Vertex AI), anthropic[vertex] (Claude on Vertex AI)
- functions-framework
- pytest + pytest-cov, ruff
- Terraform (google provider)
- GitHub Actions

**Out of scope for this plan:**

- Wrap 3 (Agent Builder): its catalog entries stay `planned`.
- The intake UI.

Both get their own plan later.

**Spec:**

- `docs/validator-spec.md`
- `docs/gateway-design.md`
- `docs/drive-wrapper.md`
- `docs/email-wrapper.md`
- `docs/test-plan.md`
- `docs/runbooks/rollback.md`
- `docs/runbooks/budget-stop.md`
- `templates/policy-template.md`

## Global Constraints

- Python 3.12; every dependency pinned in `uv.lock`.
- Every regional resource is in `europe-west4`.
- No service-account keys, no API keys, no stored credentials:
  - Google APIs are reached through attached service accounts.
  - Models through Vertex AI IAM.
  - Gmail through keyless delegation (`google.auth.iam.Signer`).
- Policy files and the catalog are in English. UI, previews and validator messages are in EN and NL; validator messages are copied verbatim from validator-spec appendix A.
- R3 is never executed. R4 and `forbidden` attempts are refused, logged and alerted. The only signer is `matthijs`, with SSH namespace `aiven-policy-v1`.
- Platform constants exactly as in validator-spec §6:
  - `emails_per_day` 0–50, `records_per_run` 0–200, `spend_eur_per_run` 0, `max_runtime_s` 30–900, `runs_per_day` 1–10, `shadow.min_runs` 1–100.
  - Bulk means more than 3 recipients.
  - Phase 1 recipients are `@aivenstudios.com` only.
  - A day is a calendar day in Europe/Amsterdam.
- Gateway constants exactly as in gateway-design §13:
  - confirm expiry 24 h
  - 3 policy refusals end a run
  - Drive call timeout 30 s
  - policy refresh after 60 s
  - Cloud Run min 0 / max 2 instances
- Fail closed. If the gateway can't read control, write the audit log or write a snapshot, it refuses the call.
- Audit entries carry actor, class, approver, policy hash and catalog hash. They never carry file content, file names or email text.
- No raw API pass-through: wrappers send allowlisted fields only.
- Budgets count gross cost (`EXCLUDE_ALL_CREDITS`): alert 10 and stop 25 in the billing account's currency (11 and 27 if it is USD).
- Tests never contain real personal data. IBAN, BSN and card values are generated at test time.

## Review Focus

1. **Parallel tool calls in one run.** Two calls racing for the last records or emails must never overshoot a limit. Test: Task 3.6 `test_parallel_reservations_never_exceed_limit`.
2. **A Drive write times out after reaching Google.** The outcome is then unknown. Expect no retry, the call marked `failed`, an alert, and the rollback runbook path. Test: Task 4.3 `test_write_timeout_marks_failed_and_never_retries`.
3. **A run that crosses midnight or a daylight-saving switch.** Counters must count by the Europe/Amsterdam date at the moment of the request. Test: Task 3.6 `test_counters_use_amsterdam_date_at_request_time`.
4. **Oversized or malformed agent requests:** a huge body, deep JSON, non-UTF-8, unknown fields. Expect 413 or 400, with no wrapper call and no content in the log. Test: Task 3.3 `test_oversized_body_413` and `test_unknown_fields_400`.
5. **Drive names with quotes, backslashes or ` / `.** Queries must stay escaped, and scope must be decided by ID, never by name. Tests: Task 4.1 `test_name_contains_escapes_quotes_and_backslashes` and Task 3.5 `test_folder_path_with_slash_in_name_verifies_by_id`.

---

## How to work through this plan

- Milestones run in order. Each one ends with a review gate: a fresh review of the milestone's diff against the spec sections it implements, before the next milestone starts.
- Every code task follows the same cycle; the task lists only what is specific to it:
  1. Write the listed tests.
  2. Run them and see them fail.
  3. Implement the listed signatures.
  4. Run them and see them pass, then run `uv run ruff check && uv run pytest -q`.
  5. Commit with the listed message.
- **Human** steps are Matthijs's. The plan says what to record.
- Spec-to-code drift is tested. Messages (Task 1.1), the catalog (Task 1.1) and the template self-test (Task 1.8) are compared against the tables in `docs/validator-spec.md`. A spec edit without a code edit, or the reverse, fails CI.

## Repository layout

```text
pyproject.toml, uv.lock, .github/workflows/ci.yml
catalog/catalog-v1.yaml                 # machine form of validator-spec §5 (signed like a policy)
catalog/schemas/<action>.json           # strict JSON Schema per action (args); used by gateway and agent runtime
config/platform.example.yaml            # deploy values: agents project, trusted authors, drive ID, mailbox
src/aiven/policy/                       # M1 validator
src/aiven/gateway/                      # M3 core, M4 wrappers/drive.py, M6 wrappers/email.py
src/aiven/control_ui/                   # M5
src/aiven/functions/budget_stop.py      # M2
src/aiven/functions/credit_reminder.py  # M2
src/aiven/agent/                        # M7 runtime + model layer
agents/<id>/policy.md, agents/<id>/runtime.yaml   # test agents (M8); real agents later
infra/terraform/                        # M2
scripts/deploy_check.py                 # M2, extended in later milestones
tests/{policy,gateway,control_ui,functions,agent,l3}/
```

---

## S. Setup (human, before Task 2.1)

- [ ] **S1. Check the project quota (need 4).** You need four projects: agents, gateway, control, and a scratch project for the budget drill. Create the four projects and link each to the billing account (Console, then Billing, then Account management shows linked projects). If the fourth won't link, stop and choose: upgrade, or run drill BD-1 later in a temporary project you delete straight after. Record the four project IDs.
- [ ] **S2. Check the billing currency.** Run `gcloud billing accounts describe <BILLING_ACCOUNT_ID> --format='value(currencyCode)'`. For EUR, set alert 10 and stop 25; for USD, set 11 and 27. Record these in `infra/terraform/terraform.tfvars` as `budget_currency`, `budget_alert_amount` and `budget_stop_amount`.
- [ ] **S3. Record the credit.** The account was upgraded to paid on 2026-10-06. €252.56 of promotional credit is left, valid until 2027-01-04. Put a calendar entry on 2026-12-20; Task 2.4 adds an automatic alert the same day.
- [ ] **S4. Confirm the organisation node.** Confirm the Google Cloud organisation for aivenstudios.com exists (it comes with Workspace). Task 2.1 applies the org policies there.
- [ ] **S5. Create the Sandbox.** Set up the Shared Drive as in drive-wrapper §1, with folders `Invoices`, `Test` and `Rollback test`. Record the drive ID and the folder IDs.
- [ ] **S6. Create the signing key.** Run `ssh-keygen -t ed25519-sk -f ~/.ssh/aiven_policy_sk` on the hardware key, then write the one-line `allowed_signers` (validator-spec §2).
- [x] **S7. Pick the model for Phase 1 agents.** Decided at the M1 review: **Gemini on Vertex AI**, which stays on the Google Cloud credit. The choice lives in `agents/*/runtime.yaml` (`provider`, `model_id`, `region`), so a later switch to Claude on Vertex AI is a config change, not a code change. Before M7, check in Vertex AI Model Garden that the chosen Gemini model is available for `aiven-agents`, and record its ID and region there.
- [ ] **S8. Later, before wrap 2 goes live:** set up the agent Workspace as in email-wrapper §1.

## Credit calendar

| Date | Check |
|---|---|
| 2026-10-06 | The account was upgraded to paid, with €252.56 of promotional credit left. |
| 2026-12-20 | Credit check. The email alert (Task 2.4) and the calendar entry both fire. See the checklist below. |
| 2027-01-04 | The credit expires. From then on all usage is billed; the budgets are unchanged. |

2026-12-20 checklist:

1. Check the remaining credit in Billing, then Credits.
2. Decide whether €10/€25 still fit, now that real charges follow.
3. Run `scripts/deploy_check.py budgets` (BD-3). Both budgets must still count gross cost, with the right amounts and currency.

---

## M1. Validator (`docs/validator-spec.md`)

### Task 1.1: Scaffold, findings, messages, constants, catalog

**Files:**

- Create: `pyproject.toml`, `.github/workflows/ci.yml`, `src/aiven/__init__.py`
- Create: `src/aiven/policy/{findings.py,constants.py,config.py,catalog.py}`
- Create: `src/aiven/policy/messages/{en.json,nl.json}`
- Create: `catalog/catalog-v1.yaml`, `catalog/schemas/*.json`
- Test: `tests/policy/test_messages.py`, `tests/policy/test_catalog.py`

**Interfaces (produces):**

- `Finding(code: str, severity: Literal["error","warning"], path: str, line: int | None, column: int | None, params: dict[str, str])`, frozen dataclass.
- `message(f: Finding, lang: Literal["en","nl"]) -> str`: `str.format_map` on the JSON text.
- `format_line(f: Finding) -> str` returns `"<severity> <CODE> <path>[:<line>]: <EN message>"`.
- `constants.py` holds validator-spec §6 verbatim:
  - `SCHEMA`, `SIGNER`, `NAMESPACE`
  - `FORBIDDEN_BASELINE`, `RESERVED_NAMESPACES`, `RESERVED_AGENT_IDS`, `PUBLIC_MAIL_DOMAINS`
  - `PHASE1_EMAIL_DOMAIN = "aivenstudios.com"`
  - `DRIVE_ROOT = "AIVEN Architecture Sandbox"`
  - `BULK_RECIPIENTS = 3`, `SHADOW_DEFAULT = 10`, `TIMEZONE = "Europe/Amsterdam"`
  - `CEILINGS: dict[str, tuple[int, int]]`
- `PlatformConfig(agents_project: str, trusted_authors: tuple[str, ...], gateway_principal: str, sandbox_drive_id: str | None)` and `load_platform_config(path: Path) -> PlatformConfig`.
- `Action(id, cls: Literal["R0","R1","R2","R3","R4"], wrapper: Literal["drive","email","agentbuilder"], undo: str | None, escalates_when_shared: bool)`.
- `Catalog(actions: dict[str, Action], reserved: tuple[str, ...], wrapper_status: dict[str, Literal["planned","built"]], sha256: str)`.
- `load_catalog(path: Path) -> Catalog`.
- `matches(pattern: str, action_id: str) -> bool`: exact, or `ns.*` matching on the `ns.` prefix.

**Tests:**

- `test_messages_match_spec_appendix`: parse the appendix A table rows. `en.json` and `nl.json` equal the EN and NL columns exactly, with 65 keys each.
- `test_catalog_matches_spec_table`: parse the §5 table. Ids, classes, wrappers, undo texts and `escalates_when_shared` (rows containing "R2 if") equal the YAML. All wrappers are `planned`.
- `test_every_write_schema_is_strict`: every schema has `additionalProperties: false` and `required`.
- `test_matches_namespace_pattern`:
  - `matches("payments.*", "payments.pay")` is True.
  - `matches("payments.*", "paymentsx.pay")` is False.
  - `matches("drive.delete", "drive.delete")` is True.

**Done when:** `uv run pytest tests/policy -q` passes. **Commit:** `feat(policy): findings, messages, constants and catalog v1`

### Task 1.2: File format and content safety (validator-spec §3.1, §3.8)

**Files:**

- Create: `src/aiven/policy/{fileformat.py,content.py}`, `tests/support/gen.py`
- Test: `tests/policy/test_fileformat.py`, `tests/policy/test_content.py`, `tests/policy/test_codes.py`

**Interfaces (produces):**

- `check_file(path: Path, data: bytes) -> list[Finding]`
- `ContentHit(kind: str, line: int, column: int)`. It carries no value field, by design.
- `scan(text: str) -> list[ContentHit]`. The gateway reuses this in M4 and M6.
- Test generators, computed at test time and never stored: `gen.valid_iban(country: str = "NL") -> str` (mod-97), `gen.valid_bsn() -> str` (eleven-test), `gen.valid_card() -> str` (Luhn).

**Tests:** `tests/policy/test_codes.py` is the shared, table-driven code test.

- Each case is `(code, mutation, expected_line)`. The mutation is applied to `valid_base()`, which is the template with the placeholders filled and the generated sections re-rendered.
- The test asserts that the validator returns exactly `[code]` at `expected_line`.
- This task adds the cases for E-ENCODING (BOM, and an invalid byte), E-LINE-ENDINGS, E-FINAL-NEWLINE (none, and two), E-FILE-SIZE (65,537 bytes), E-FILENAME, E-HIDDEN-CHAR (U+200B, U+202E, U+E0041, U+00A0, TAB), E-PLACEHOLDER (`REPLACE_ME_X`, `TODO`, `TBD`, `FIXME`), E-SECRET (one case per pattern) and E-BANK-DETAILS / E-ID-NUMBER (generated values).

Plus:

- `test_content_findings_never_contain_value`: the text line, the JSON output and both messages contain no generated value.
- `test_placeholder_skips_other_checks_for_that_field`.

**Commit:** `feat(policy): file format and content-safety checks`

### Task 1.3: Front matter (validator-spec §3.2)

**Files:**

- Create: `src/aiven/policy/frontmatter.py`
- Test: cases in `tests/policy/test_codes.py`, plus `tests/policy/test_frontmatter.py`

**Interfaces (produces):**

- `split(data: bytes) -> tuple[str, str, int]`: front matter text, body text, and the body's first line number.
- `load(fm_text: str) -> tuple[dict | None, list[Finding]]`. It uses ruamel.yaml (YAML 1.2, duplicate keys rejected). It walks the composed node graph to reject anchors, aliases, merge keys, explicit tags, complex keys and multiple documents. Integers must match `^(0|[1-9][0-9]*)$` on their raw scalar text.

**Tests:**

- Cases for E-FM-MISSING, E-YAML, E-YAML-FEATURE (anchor, alias, `<<`, `!!str`, a second document), E-YAML-DUPLICATE-KEY (reported at the second key's line), E-FM-NON-ASCII (a Cyrillic `е` in `drive.dеlete`), E-FIELD-MISSING, E-FIELD-UNKNOWN (`Max_class`) and E-FIELD-TYPE (`"300"`, `0x12C`, `5:00`, `+5`, `on`), plus E-LIST-DUPLICATE.
- `test_sexagesimal_is_not_an_integer`: `max_runtime_s: 5:00` gives E-FIELD-TYPE.

**Commit:** `feat(policy): strict front matter loading`

### Task 1.4: Fields, tools, limits, scope (validator-spec §3.3–§3.5)

**Files:**

- Create: `src/aiven/policy/{model.py,fields.py,tools.py,limits_scope.py}`
- Test: cases in `tests/policy/test_codes.py`

**Interfaces (produces):**

- `Limits(emails_per_day: int, records_per_run: int, spend_eur_per_run: int, max_runtime_s: int, runs_per_day: int)`
- `Scope(drive_folder_id: str | None, drive_folder_path: str | None, email_to: tuple[str, ...])`
- `Policy(agent, version, principal, max_class, tools: tuple[str, ...], forbidden: tuple[str, ...], untrusted_input: Literal["strict","taint"], limits: Limits, scope: Scope, shadow_min_runs: int, sha256: str)`. All are frozen dataclasses.
- `build_policy(fm: dict, data: bytes, cfg: PlatformConfig, catalog: Catalog) -> tuple[Policy | None, list[Finding]]`

**Tests:** one case per code:

- E-SCHEMA, E-AGENT-ID (`ab`, `admin`, a 25-character id), E-PRINCIPAL, E-MAX-CLASS-R3, E-MAX-CLASS-R4, E-UNTRUSTED-INPUT, E-RANGE (each ceiling and its boundary, with `runs_per_day: 11` failing and `10` passing)
- E-TOOL-UNKNOWN, E-TOOL-WILDCARD, E-TOOL-R3, E-TOOL-R4, E-TOOL-ABOVE-MAX-CLASS, E-TOOL-FORBIDDEN, E-FORBIDDEN-PATTERN, E-FORBIDDEN-UNKNOWN (`paymnets.*`), E-FORBIDDEN-BASELINE
- E-LIMIT-SPEND, E-LIMIT-CONFLICT, E-SCOPE-MISSING, E-SCOPE-SANDBOX, E-SCOPE-EMAIL (`@Aivenstudios.com`, `*@x.nl`), E-SCOPE-EMAIL-PUBLIC (`@gmail.com`), E-SCOPE-EMAIL-EXTERNAL (`@client.nl`)
- W-MAX-CLASS-SLACK, W-TOOL-NOT-LIVE (from catalog `planned`), W-LIMIT-UNUSED, W-SCOPE-UNUSED, W-SHADOW-LOW, W-UNTRUSTED-TAINT

`test_valid_base_has_no_errors` asserts that `valid_base()` gives only W-TOOL-NOT-LIVE warnings.

**Commit:** `feat(policy): field, tool, limit and scope rules`

### Task 1.5: Body and renderer (validator-spec §3.7, §7)

**Files:**

- Create: `src/aiven/policy/{body.py,render.py}`
- Test: `tests/policy/test_render.py`, plus cases in `tests/policy/test_codes.py`

**Interfaces (produces):**

- `render_generated(p: Policy, catalog: Catalog) -> tuple[str, str]`: the "Enforced rules (generated)" and "Sign-off (generated)" sections, each including its `##` heading.
- `rewrite(data: bytes, p: Policy, catalog: Catalog) -> bytes`: replaces only those two sections.
- `check_body(body: str, first_line: int, p: Policy, catalog: Catalog) -> list[Finding]`: markdown-it-py with tables enabled, and headings inside code fences ignored.

**Tests:**

- `test_render_template_golden` (V-3): rendering the template's own front matter gives its generated sections byte for byte.
- `test_render_strict_and_taint_text`: uses the fixed sentence and the two mode suffixes from §7.
- `test_render_scope_none`: gives `- None: this agent has no Drive or email tools.`
- `test_render_min_runs_singular`: `min_runs: 1` gives "the first run only proposes" and "After 1 run".
- `test_rewrite_changes_only_generated_sections`.
- Cases for E-BODY-TITLE, E-BODY-SECTIONS (missing, out of order, an extra `##`), E-BODY-EMPTY, E-BODY-TOOL-UNEXPLAINED, E-BODY-TOOL-EXTRA, E-BODY-DRIFT (with the first differing line), E-BODY-HTML (`<!-- x -->`, `<b>`) and E-BODY-LINK (a `[a](b)` link, an image, a bare `https://`).

**Commit:** `feat(policy): body checks and generated sections`

### Task 1.6: Widening and policy-set checks (validator-spec §3.6, §3.9)

**Files:**

- Create: `src/aiven/policy/{widening.py,policyset.py}`
- Test: `tests/policy/test_widening.py`, `tests/policy/test_policyset.py`

**Interfaces (produces):**

- `widening(prev: Policy, new: Policy) -> tuple[list[str], bool]`: the changes, and whether shadow restarts.
- `check_duplicates(items: list[tuple[Path, Policy]]) -> list[Finding]` and `check_history(path: Path, policy: Policy, previous: Policy | None) -> list[Finding]` (split during M1, ruling R91: the gateway loader runs the duplicate check over the whole set and the history check per file, only where the history is known)

**Tests:**

- `test_added_tool_restarts_shadow`
- `test_raised_max_class_restarts_shadow`
- `test_raised_limit_widens_without_restart`
- `test_strict_to_taint_widens`
- `test_removed_tool_is_not_widening`
- E-AGENT-DUPLICATE, E-PRINCIPAL-DUPLICATE
- E-VERSION-ORDER: version not equal to the previous version + 1, and a new agent not starting at 1.

**Commit:** `feat(policy): widening and cross-policy checks`

### Task 1.7: Signature and load-time verify (validator-spec §2, §3.10)

**Files:**

- Create: `src/aiven/policy/verify.py`
- Test: `tests/policy/test_verify.py`

**Interfaces (produces):**

- `ActiveVersion(version: int, sha256: str)`
- `verify(path: Path, data: bytes, sig: bytes | None, allowed_signers: Path, active: ActiveVersion | None, wrapper_live: Callable[[str, str], bool], folder_check: Callable[[str, str | None], bool], cfg: PlatformConfig, catalog: Catalog) -> tuple[Policy | None, list[Finding]]`. It runs `ssh-keygen -Y verify -f <allowed_signers> -I matthijs -n aiven-policy-v1 -s <sig>` with the file on stdin. Its arguments come from the parameters only, never from the file.

**Tests:** each test generates a throwaway ed25519 key in `tmp_path`, so no key is stored.

- `test_valid_signature_loads`
- `test_one_byte_change_fails` (E-SIG-INVALID)
- `test_git_namespace_signature_fails` (E-SIG-INVALID)
- `test_missing_sig` (E-SIG-MISSING)
- `test_older_version_refused` and `test_same_version_other_hash_refused` (E-VERSION-ORDER)
- `test_wrapper_not_live_for_agent` (E-TOOL-NOT-LIVE)
- `test_folder_outside_sandbox` (E-SCOPE-NOT-IN-SANDBOX)

**Commit:** `feat(policy): signature and load-time verification`

### Task 1.8: CLI, template self-test, CI

**Files:**

- Create: `src/aiven/policy/cli.py`. The entry point is `aiven-policy` in `pyproject.toml`.
- Test: `tests/policy/test_cli.py`, `tests/policy/test_coverage_of_codes.py`

**Interfaces (produces):**

- `aiven-policy validate <files...> [--json] [--previous-ref <git-ref>]`
- `aiven-policy render <file>`
- `aiven-policy verify <file> --sig <sig> --allowed-signers <path>`
- Exit codes: 0 valid, 1 errors, 2 crash (E-INTERNAL).

**Tests:**

- `test_template_self_test_matches_spec_section_9` (V-1): parse the §9 table. The CLI's codes, lines and order equal it exactly, and the exit code is 1.
- `test_json_output_has_en_and_nl`
- `test_crash_exits_2_with_e_internal`
- `test_every_code_has_a_failing_case`: the set of codes in `en.json` minus the codes covered in `test_codes.py` and the verify tests is empty.
- Coverage gate: `uv run pytest tests/policy --cov=aiven.policy --cov-branch --cov-fail-under=95`.

**CI:** ruff, pytest, and `aiven-policy validate templates/policy-template.md` (expects exit 1 with the §9 output).

**Commit:** `feat(policy): aiven-policy CLI and template self-test`

**M1 review gate:** review the validator against every row of validator-spec §3 and appendix A.

---

## M2. Platform infrastructure (`docs/gateway-design.md` §2, §3, §5, §9, §10, §14)

### Task 2.0: Platform config guard (added at the M1 review)

`config/platform.yaml` and `infra/terraform/terraform.tfvars` hold IDs and addresses only: project IDs, the organisation ID, the billing account ID, the drive ID, account addresses. They never hold credentials, keys or tokens.

**Files:**

- Create: `src/aiven/common/config_guard.py`, with the console script `aiven-check-config <files...>`
- Test: `tests/common/test_config_guard.py`
- Modify: `.github/workflows/ci.yml` (run the guard on every push and pull request)

**Rules:**

- Only known keys are allowed: the `PlatformConfig` fields, and the variables declared in `infra/terraform/variables.tf`.
- A key whose name suggests a secret is refused.
- A value with the wrong shape for its key is refused: a project ID, an email address, a drive ID.
- Any value or line that the validator's content scanner flags is refused.
- The values found are never printed.

**Commit:** `feat(common): config guard refuses secrets in platform config and tfvars`

### Task 2.1: Terraform foundation and IAM

**Files:**

- Create: `infra/terraform/{versions.tf,providers.tf,variables.tf,main.tf,terraform.tfvars.example}`
- Create: `infra/terraform/modules/{control,gateway,agents}/*.tf`
- Create: CI job `terraform fmt -check && terraform validate`

**Resources:**

- Org policies:
  - `iam.disableServiceAccountKeyCreation`
  - `iam.automaticIamGrantsForDefaultServiceAccounts`
- APIs enabled per project. Drive, Sheets and Gmail stay **disabled** in agents.
- Service accounts:
  - `gateway`
  - `control-ui`
  - `budget-stop`
  - `credit-reminder`
  - `agent-<id>`, one per entry of `var.agents`
- IAM exactly as in gateway-design §3. That includes `datastore.viewer` on the gateway project for `control-ui`.
- Terraform state in a versioned bucket in control.

**Done when:** `terraform validate` passes and Matthijs has reviewed and applied `terraform plan`.

**Commit:** `infra: projects, service accounts and IAM`

### Task 2.2: Control stores and audit log

**Resources:**

- Bucket `<control-project>-policies`: versioned, uniform access, public access prevented. Bucket names are global, so they carry the project ID (ruling R125).
- Bucket `<control-project>-snapshots`: 30-day retention, lifecycle delete at 30 days.
- Log bucket `aiven-audit`: 365 days, with a sink for log `aiven-audit` and an exclusion from `_Default`.
- Firestore databases `control` (control project) and `gateway` (gateway project), with TTL on `runs` and `calls` (90 days).

Locking `aiven-audit` (`locked = true`) can't be undone. **Do not apply it until Matthijs explicitly confirms in the conversation.** The task ships with `locked = false`, and the lock is a separate one-line change that waits for that confirmation.

**Test:** `scripts/deploy_check.py stores` checks the retentions, the lock, versioning and the exclusion.

**Commit:** `infra: control stores and audit log (lock waits for confirmation)`

### Task 2.3: Shared audit writer, budgets and budget stop (runbook budget-stop.md)

**Files:**

- Create: `src/aiven/common/audit.py`, `src/aiven/functions/budget_stop.py`
- Create: `infra/terraform/modules/control/budgets.tf`
- Test: `tests/common/test_audit.py`, `tests/functions/test_budget_stop.py`

**Interfaces (produces):**

- `AuditEntry` holds only the fields of gateway-design §5; unknown fields raise `ValueError`.
- `AuditLog(project: str).write(e: AuditEntry) -> None` writes synchronously with `google.cloud.logging` to log `aiven-audit` in control, and raises `AuditWriteFailed`. The gateway, the control UI and both functions use this one writer.
- `BillingApi` protocol:
  - `billing_enabled(project: str) -> bool`
  - `unlink(project: str) -> None`

  The real implementation uses `google.cloud.billing_v1.CloudBillingClient`: `get_project_billing_info`, and `update_project_billing_info` with `billing_account_name=""`.
- `StopConfig(budget_name: str = "aiven-stop", projects: tuple[str, ...], enabled: bool)`, plus `currency`, `actor` and `audit_project`, read from the function's environment (ruling R135).
- `handle(notification: dict, cfg: StopConfig, billing: BillingApi, audit: AuditLog) -> Literal["ignored","below","already_stopped","stopped","disabled"]`

**Audit tests:**

- `test_audit_entry_rejects_extra_fields`
- `test_write_failure_raises`

**Budgets** (Terraform `google_billing_budget`): `aiven-alert` and `aiven-stop`, with amounts and currency from tfvars, `credit_types_treatment = "EXCLUDE_ALL_CREDITS"`, and the three projects. The alert budget has thresholds 0.5, 0.9 and 1.0. The stop budget has threshold 1.0 and Pub/Sub topic `budget-stop`.

**Tests:**

- `test_below_amount_does_nothing` (BD-2, €24.99)
- `test_other_budget_ignored`
- `test_at_amount_unlinks_each_project`
- `test_duplicate_notification_is_idempotent`
- `test_disabled_does_nothing`
- `test_every_notification_logged`
- `test_stop_writes_budget_stop_entry_with_alert`

**Verification:** run drill BD-1 on the scratch project as in the runbook, and record the timings for the report. Then `scripts/deploy_check.py budgets` (BD-3) must pass.

**Commit:** `feat(functions): budget hard stop with gross-cost budgets`

### Task 2.4: Alerts and credit reminder

**Files:**

- Create: `src/aiven/functions/credit_reminder.py`
- Create: `infra/terraform/modules/control/alerts.tf`
- Test: `tests/functions/test_credit_reminder.py`

**Resources:**

- A log-based alert in control on `jsonPayload.alert=true`, with an email channel to Matthijs.
- A second alert that fires when `jsonPayload.reason="CONTROL_UNREACHABLE"` refusals continue for more than 1 minute.
- Cloud Scheduler job `credit-reminder`, running once at 2026-12-20 09:00 Europe/Amsterdam (`credit_alert_date` in tfvars). It calls `credit-reminder` with OIDC.
- `credit-reminder` writes a `control` audit entry with `alert: true` and the text "Google Cloud credit expires on 2027-01-04 (€252.56 at the upgrade). Check what is left; from then on all usage is billed."

**Tests:** `test_reminder_writes_alert_entry`. Manually: `gcloud scheduler jobs run credit-reminder` must deliver the email.

**Commit:** `feat(functions): alert policies and credit-expiry reminder`

### Task 2.5: Deploy checks

**Files:**

- Create: `scripts/deploy_check.py`, a shim for `src/aiven/deploy_check.py` (console script `aiven-deploy-check`; ruling R144)
- Test: `tests/scripts/test_deploy_check.py` (with fake clients)

**Interfaces (produces):** `aiven-deploy-check <group>...`. The groups are `keys`, `apis`, `iam`, `stores`, `budgets`, `drive` and `all`. It prints `PASS|FAIL <check>`, and exits 1 on any FAIL. These are the checks in gateway-design §11 and BD-3:

- no user-managed keys;
- Drive, Sheets and Gmail disabled in agents;
- agent roles exactly `run.invoker` + `aiplatform.user`;
- Sandbox members exactly Matthijs (organizer) and the gateway (writer, which is Contributor);
- drive restriction `driveMembersOnly: true`;
- both budgets gross, with the right amounts, currency and topic.

**Commit:** `feat(scripts): deploy checks`

**M2 review gate.**

---

## M3. Gateway core (`docs/gateway-design.md` §4–§8, §13; validator-spec §4)

> **Updated after the M2 review:** `docs/plans/2026-10-13-m3-gateway.md` adds to this section: the four M1 flags decided (#1 to #4), a fallback alert when the gateway fails closed and the audit log fails too, what M2 hands over, and two new tasks (3.0 and 3.5b). Where the two differ, that document wins.

### Task 3.1: Types and store

**Files:**

- Create: `src/aiven/gateway/{types.py,store.py,store_firestore.py}`
- Create: `tests/gateway/fakes.py` (an in-memory `Store`)

**Interfaces (produces):**

- `Class = Literal["R0","R1","R2","R3","R4"]`, with `rank(c: Class) -> int`.
- `RunState(run_id: str, agent: str, policy_sha256: str, started_at: datetime, deadline: datetime, status: Literal["open","ended","stopped"], stop_reason: str | None, shadow: bool, tainted: bool, taint_sources: tuple[str, ...], records_used: int, refusals: int)`
- `Refusal(reason: str, alert: bool)`
- `StoredCall(call_id: str, outcome: str, reason: str | None, result: dict | None)`
- `RunSummary(run_id: str, calls_by_outcome: dict[str, int], records_used: int, tainted: bool, cost_estimate_eur: Decimal | None)`
- `Store` protocol:
  - `create_run(...)`
  - `get_run(run_id)`
  - `reserve(run_id, agent, day, records, recipients, limits) -> bool`, transactional
  - `reserve_run(agent, day, runs_per_day) -> bool`
  - `get_call(run_id, request_id)` and `put_call(...)`
  - `put_confirm` / `get_confirm` / `close_confirm`
  - `put_proposal`
  - `get_shadow` / `inc_shadow_runs`
  - `get_active` / `set_active`
  - `update_run(run_id, **fields)`

**Tests:** `test_store_contract` runs one contract test-suite against the fake and against the Firestore emulator.

**Commit:** `feat(gateway): types and store`

### Task 3.2: The decision function

**Files:**

- Create: `src/aiven/gateway/decide.py`
- Test: `tests/gateway/test_decide.py`

**Interfaces (produces):**

- `Classification(action: str, cls: Class | None, effective_cls: Class | None, in_scope: bool, records: int, email_recipients: int, taint_sources: tuple[str, ...], reserved: bool)`. Here `action` is the id after reclassification: a smuggled trash becomes `"drive.delete"`.
- `ControlSnapshot(kill_global: bool, kill_agent: bool, wrapper_enabled: bool)`
- `DayCounters(runs: int, email_recipients: int)`
- `Decision(outcome: Literal["execute","propose","queue","refuse"], reason: str | None, cls: Class | None, alert: bool, end_run: bool, snapshot: bool)`
- `decide(p: Policy, ctl: ControlSnapshot, run: RunState, c: Classification, day: DayCounters, now: datetime) -> Decision`. The first matching step wins:
  1. Kill switch: `KILL_SWITCH`.
  2. Run not open: `RUN_CLOSED`. Past the deadline: `LIMIT_RUNTIME`, end run.
  3. Reserved: `RESERVED_R4`, alert. Forbidden match: `FORBIDDEN`, alert.
  4. Not in `tools`: `NOT_GRANTED`.
  5. Wrapper off: `WRAPPER_DISABLED`.
  6. R3: `R3_DISABLED`.
  7. Above `max_class`: `ABOVE_MAX_CLASS`.
  8. Out of scope: `OUT_OF_SCOPE`.
  9. Over records: `LIMIT_RECORDS`, end run. Over emails: `LIMIT_EMAILS`, end run.
  10. Shadow and R1 or higher: propose.
  11. Otherwise:
      - R0: execute.
      - R1: queue if `strict` and the run is tainted; otherwise execute with a snapshot.
      - R2: queue.

  The third policy refusal in a run sets `end_run` and `alert`. The policy refusals are reasons 3, 4, 6, 7 and 8.

**Tests:**

- A table of cases covering every branch.
- `test_first_match_wins` (kill switch plus forbidden)
- `test_forbidden_beats_not_granted`
- `test_smuggled_trash_is_forbidden_with_alert`
- `test_shared_file_escalates_to_queue`
- `test_escalation_above_max_class_refused`
- `test_shadow_proposes_r1_r2_executes_r0`
- `test_strict_tainted_r1_queues`
- `test_taint_mode_tainted_r1_executes`
- `test_third_policy_refusal_ends_run_and_alerts`

**Done when:** `uv run pytest tests/gateway/test_decide.py --cov=aiven.gateway.decide --cov-branch --cov-fail-under=100` passes.

**Commit:** `feat(gateway): decision function`

### Task 3.3: HTTP API and identity

**Files:**

- Create: `src/aiven/gateway/{app.py,auth.py,api_models.py}`
- Test: `tests/gateway/test_api.py`

**Interfaces (produces):**

- `caller(request) -> Caller(email: str, kind: Literal["agent","control"])`. It uses `google.oauth2.id_token.verify_oauth2_token(token, Request(), audience=GATEWAY_URL)` and requires `email_verified`.
- Routes as in gateway-design §4. Pydantic models use `extra="forbid"`. Bodies are limited to 2 MiB.
- An HTTP 200 carries an `outcome`. The other statuses are 400, 401/403, 409, 413 and 503.

**Tests:**

- `test_identity_comes_only_from_token` (AT-BYP-4)
- `test_control_routes_reject_agents` (AT-BYP-2)
- `test_oversized_body_413`
- `test_unknown_fields_400`
- `test_non_utf8_400`
- `test_unmapped_principal_no_policy_alert`

**Commit:** `feat(gateway): API and caller identity`

### Task 3.4: Control reads, call pipeline, fail closed

**Files:**

- Create: `src/aiven/gateway/{control.py,pipeline.py}`
- Test: `tests/gateway/test_control_pipeline.py`

**Interfaces:**

- Consumes: `AuditLog` and `AuditEntry` (Task 2.3), and `decide` (Task 3.2).
- Produces:
  - `ControlReader.read(agent: str, wrapper: str) -> ControlSnapshot`. It does a direct Firestore read on every call, and raises `ControlUnavailable` on any error.
  - `handle_call(run_id: str, action: str, args: dict, request_id: str, caller: Caller) -> dict`:
    1. Idempotency.
    2. Control read.
    3. Classify (wrapper).
    4. `decide`.
    5. Write `call_start`.
    6. Execute, propose or queue.
    7. Write `call`.

**Tests:**

- `test_audit_failure_refuses_and_never_executes` (G-4)
- `test_control_failure_503_and_never_executes` (G-5)
- `test_kill_switch_read_on_every_call`
- `test_call_start_written_before_execute`

**Commit:** `feat(gateway): control reads and audit log`

### Task 3.5: Policy registry

**Files:**

- Create: `src/aiven/gateway/policies.py`
- Test: `tests/gateway/test_policies.py`

**Interfaces (produces):**

- `load_signed_catalog(bucket, allowed_signers: Path) -> Catalog`. The catalog is verified like a policy, and the gateway won't start without a valid signature.
- `PolicyRegistry(bucket, catalog, cfg, verify_fn, audit, store).refresh(now) -> None` and `.for_principal(email: str) -> Policy | None`. The registry:
  - reloads when the last load is more than 60 s old, or on `policies:reload`;
  - keeps the active version when a new one fails, and alerts;
  - writes a `policy_load` entry for each load.

**Tests:**

- `test_unsigned_catalog_refuses_to_start`
- `test_tampered_file_keeps_active_and_alerts` (AT-SELF-5)
- `test_older_version_refused_and_alerts` (AT-SELF-6)
- `test_gmail_policy_not_loaded_while_email_disabled`
- `test_refresh_waits_60s`
- `test_folder_path_with_slash_in_name_verifies_by_id`

**Tracked from the M1 review** (issues p4z5w2y56p-lgtm/Aiven-architecture#1, #2, #3):

- **Durable active version (#1).** Pass `ActiveVersion` to every `verify` call, taken from a record that survives a restart and a rebuild of the gateway's working database. Firestore `gateway` is working state today and may be rebuilt empty, so the durable record can't live only there. Decide the store in this task: for example a `policy_versions/{agent}` document in control, written when Matthijs publishes and read by the gateway. If the record can't be read, refuse and alert. Tests: an older signed version is refused after a restart, and a failed read gives a refusal.
- **Catalog signature (#2).** This is `load_signed_catalog` above. It verifies with `ssh-keygen -Y verify`, checks the size and the signature before parsing, and the gateway won't start without a valid signature. Decided at the M2 review: its own namespace, `aiven-catalog-v1`.
- **Byte limit (#3).** Read at most `MAX_FILE_BYTES + 1` bytes of a policy, the catalog, `allowed_signers` or the pricing file, and at most `MAX_SIG_BYTES + 1` bytes of a signature. Use a ranged read, or check the object's size first. An object that is too large is refused with an alert, without reading the rest.

**Commit:** `feat(gateway): signed policy registry`

### Task 3.6: Runs, limits, idempotency

**Files:**

- Create: `src/aiven/gateway/runs.py`
- Test: `tests/gateway/test_runs.py`, `tests/gateway/test_runs_emulator.py`

**Interfaces (produces):**

- `amsterdam_day(now: datetime) -> str`
- `start_run(store, p: Policy, shadow: bool, now) -> RunState | Refusal`
- `end_run(store, run_id, usage: list[Usage], end_reason: Literal["done","model_refusal","max_turns","error"], now) -> RunSummary`
- `idempotent(store, run_id, request_id) -> StoredCall | None`

**Tests:**

- `test_runs_per_day_limit` (G-2)
- `test_each_limit_refuses_and_ends_run`
- `test_counters_use_amsterdam_date_at_request_time`: covers 23:59 and 00:01, and the DST dates 2026-10-25 and 2027-03-28.
- `test_same_request_id_executes_once` (G-3)
- `test_end_reason_logged_on_run_end`
- `test_parallel_reservations_never_exceed_limit`: Firestore emulator, 20 concurrent reservations against a limit of 10; exactly 10 succeed.

**Commit:** `feat(gateway): runs, limits and idempotency`

### Task 3.7: R2 confirm flow, previews, taint state

**Files:**

- Create: `src/aiven/gateway/{preview.py,confirm.py,taint.py}`
- Create: `src/aiven/gateway/i18n/{en.json,nl.json}`
- Test: `tests/gateway/test_confirm.py`

**Interfaces (produces):**

- `Preview(en: str, nl: str, sha256: str)`
- `build_preview(action: str, args: dict, target: dict, agent_text: dict[str, str], taint_sources: tuple[str, ...]) -> Preview`. The hash is SHA-256 over canonical JSON (sorted keys) of action, args and both texts.
- `ConfirmQueue.enqueue(run, call_id, c, args, preview) -> str`
- `ConfirmQueue.apply(confirm_id, now) -> Literal["executed","rejected","expired","refused"]`
- `mark_tainted(store, run_id, sources)`

**Tests:**

- `test_hash_mismatch_refused`
- `test_changed_target_stale`
- `test_expired_after_24h`
- `test_kill_switch_at_apply_refused` (G-7, KS-3)
- `test_agent_text_quoted_and_labelled_en_nl`
- `test_tainted_preview_lists_sources`
- `test_decision_must_exist_in_control` (AT-SELF-3)

**Commit:** `feat(gateway): confirm queue and previews`

### Task 3.8: Shadow mode

**Files:**

- Create: `src/aiven/gateway/shadow.py`
- Test: `tests/gateway/test_shadow.py`

**Interfaces:**

- Consumes: `Preview` (Task 3.7).
- Produces:
  - `in_shadow(p: Policy, signoff: dict | None) -> bool`. The agent is signed off only if `p.tools` ⊆ `signoff.tools` and `rank(p.max_class)` ≤ `rank(signoff.max_class)`.
  - `record_proposal(store, run: RunState, call_id: str, preview: Preview) -> None`
  - `count_shadow_run(store, agent: str) -> int`

**Tests:**

- `test_new_agent_in_shadow`
- `test_added_tool_back_in_shadow`
- `test_removed_tool_stays_signed_off` (SH-3)
- `test_proposals_count_toward_limits` (SH-4)

**Commit:** `feat(gateway): shadow mode`

### Task 3.9: Cost per run

**Files:**

- Create: `src/aiven/gateway/pricing.py`
- Test: `tests/gateway/test_pricing.py`

**Interfaces (produces):**

- `Usage(model: str, input_tokens: int, output_tokens: int)`. This is the same shape as the agent runtime's `Usage` in Task 7.1.
- `Pricing.load(data: bytes) -> Pricing`, read from `pricing/models.yaml`.
- `Pricing.estimate(usage: list[Usage]) -> Decimal | None`. It returns None when a model is missing.
- `run_end` gets `usage`, `cost_estimate_eur` and `end_reason`.

**Tests:**

- `test_estimate_sums_models` (CR-1)
- `test_missing_model_logs_none_not_error`

**Commit:** `feat(gateway): cost per run`

### Task 3.10: Deploy the gateway

**Files:**

- Create: `Dockerfile`
- Create: `infra/terraform/modules/gateway/run.tf` (Cloud Run v2: min 0, max 2, invokers = agents + control-ui)
- Create: `scripts/smoke.py`

**Before deploying:** Matthijs signs `catalog/catalog-v1.yaml` and uploads it with its `.sig` and `allowed_signers` to the policy bucket.

**Done when:**

- `scripts/smoke.py` gets a 403 `NO_POLICY` for an agent with no loaded policy. No wrapper is live yet.
- `deploy_check.py all` passes.

**Tracked from the M1 review** (issue p4z5w2y56p-lgtm/Aiven-architecture#4): install OpenSSH at a fixed version in the image. The gateway calls `ssh-keygen` by its absolute path, or with a pinned `PATH` set once at startup. At startup it checks that the binary exists, is owned by root and can't be written by the service user; if any check fails, it loads no policy and alerts. It gets a private, writable temporary folder.

**Commit:** `infra: deploy gateway`

**M3 review gate.**

---

## M4. Drive wrapper (`docs/drive-wrapper.md`)

### Task 4.1: Reads, target check, listing

**Files:**

- Create: `src/aiven/gateway/wrappers/{base.py,drive.py,drive_paths.py}`
- Test: `tests/gateway/test_drive_reads.py` (fake Drive and Sheets services)

**Interfaces (produces):**

- `Wrapper` protocol:
  - `name`
  - `classify(p: Policy, action: str, args: dict) -> Classification`
  - `execute(p: Policy, run: RunState, call_id: str, c: Classification, args: dict) -> ExecResult`
  - `preview(c: Classification, args: dict) -> tuple[dict, dict]`: target and agent text.
- `ExecResult(outcome: Literal["executed","failed"], result: dict | None, snapshot: str | None, alert: bool)`
- `FolderResolver.is_within(file_id: str, folder_id: str) -> bool`: walks the parent chain, at most 20 levels, with a 60 s cache. It requires `driveId == SANDBOX_DRIVE_ID`.

**Tests:**

- `test_each_read_in_scope`
- `test_out_of_scope_cases`: another folder, another drive, a My Drive file shared with the gateway, a trashed file, a missing file. All give `OUT_OF_SCOPE` (D-1).
- `test_name_contains_escapes_quotes_and_backslashes` (D-3)
- `test_docs_export_plain_text`
- `test_unsupported_type_bad_args`

**Commit:** `feat(drive): reads and scope`

### Task 4.2: Writes and reclassification

**Files:**

- Modify: `src/aiven/gateway/wrappers/drive.py`
- Test: `tests/gateway/test_drive_writes.py`

**Tests:**

- `test_trashed_field_reclassified_as_delete`
- `test_parent_fields_reclassified_as_move`
- `test_permission_fields_reclassified_as_share` (D-2)
- `test_shared_file_escalates_r2`
- `test_formula_written_as_text` (D-4): `userEnteredValue.stringValue`
- `test_google_doc_content_update_bad_args` (D-8)
- `test_range_outside_grid_bad_args`
- `test_size_caps`: 1 MB write, 1,000 cells; one over each fails.
- `test_labels_set_on_every_write`

**Commit:** `feat(drive): writes with field allowlists`

### Task 4.3: Snapshots and manifest

**Files:**

- Create: `src/aiven/gateway/snapshots.py`
- Test: `tests/gateway/test_snapshots.py`

**Interfaces (produces):**

- `SnapshotWriter.put(agent, run_id, call_id, name: str, data: bytes) -> str`. It uses GCS `if_generation_match=0`, so it is create-only.
- `write_manifest(run, folder_id) -> str`

**Tests:**

- `test_snapshot_before_write` (D-6)
- `test_snapshot_failure_no_write`
- `test_md5_verified`
- `test_stale_target_refused` (D-7)
- `test_old_content_with_iban_blocked_no_snapshot` (D-5, with a generated IBAN)
- `test_new_content_with_bsn_blocked` (D-5, with a generated BSN)
- `test_snapshot_failure_alerts`
- `test_write_timeout_marks_failed_and_never_retries`
- `test_manifest_partial_over_500`

**Commit:** `feat(drive): snapshots and run manifest`

### Task 4.4: Taint provenance

**Files:**

- Create: `src/aiven/gateway/wrappers/drive_taint.py`
- Test: `tests/gateway/test_drive_taint.py`

**Interfaces (produces):** `taint_of(meta: dict, clears: dict, trusted: tuple[str, ...], gateway_email: str) -> str | None`. It returns a source label, or None when the file is trusted.

**Tests:**

- `test_rule1_label_taints_unless_cleared_version`
- `test_rule2_uploaded_file_taints`
- `test_rule3_untrusted_modifier_taints`
- `test_trusted_doc_clean`
- `test_listing_with_one_untrusted_name_taints` (G-8)

**Commit:** `feat(drive): taint provenance`

### Task 4.5: Wire Drive in and go live for test agents

**Steps:**

1. Register the wrapper.
2. Set catalog `wrapper_status.drive: built`; Matthijs re-signs the catalog.
3. Update validator-spec §9 and its test: drive tools no longer warn.
4. Add the test agents to `wrappers/drive.enabled_for`.

**Done when:** an L3 smoke run of `t-reader` listing `Test` works, and `deploy_check.py drive` passes.

**Commit:** `feat(drive): enable Drive wrapper`

**M4 review gate.**

---

## M5. Control UI (`docs/gateway-design.md` §7, §8; runbooks)

### Task 5.1: Skeleton, IAP, CSRF, NL/EN, policy view

**Files:**

- Create: `src/aiven/control_ui/{app.py,iap.py,csrf.py,i18n/en.json,i18n/nl.json,templates/*.html}`
- Test: `tests/control_ui/test_base.py`

**Interfaces (produces):** `iap_user(request) -> str`. It uses `google.oauth2.id_token.verify_token(jwt, Request(), audience=IAP_AUDIENCE, certs_url="https://www.gstatic.com/iap/verify/public_key")`.

**Tests:**

- `test_missing_or_bad_iap_jwt_403`
- `test_post_without_csrf_403`
- `test_frames_denied`
- `test_all_keys_in_both_languages`
- `test_policy_view_shows_signed_file_and_nl_rendering`

**Commit:** `feat(control-ui): skeleton and policy view`

### Task 5.2: Confirm queue

**Files:**

- Modify: `src/aiven/control_ui/app.py`
- Create: `templates/queue.html`, `templates/confirm.html`
- Test: `tests/control_ui/test_queue.py`

**Tests:**

- `test_queue_lists_pending_with_taint_banner`
- `test_approve_writes_decision_with_iap_address_and_hash_then_applies`
- `test_approve_with_wrong_hash_refused`
- `test_no_batch_approve_for_tainted`

**Commit:** `feat(control-ui): confirm queue`

### Task 5.3: Kill switches, wrappers, shadow review, taint clears

**Files:**

- Modify: `src/aiven/control_ui/app.py`
- Create: `templates/{switches,shadow,taint}.html`
- Test: `tests/control_ui/test_switches.py`

**Tests:**

- `test_kill_switch_flip_writes_control_and_audit`
- `test_signoff_disabled_before_min_runs` (SH-2)
- `test_shadow_review_shows_cost_per_run` (CR-1)
- `test_wrapper_enabled_for_edit_audited`
- `test_taint_clear_binds_revision`

**Commit:** `feat(control-ui): switches, shadow review, taint clears`

### Task 5.4: Audit search, snapshots, record event; deploy

**Files:**

- Modify: `src/aiven/control_ui/app.py`
- Create: `templates/{audit,snapshots,event}.html`
- Create: `infra/terraform/modules/control/ui.tf`
- Test: `tests/control_ui/test_audit_events.py`

**Tests:**

- `test_audit_search_by_run`
- `test_snapshot_list_for_run`
- `test_record_event_writes_control_entry`

Deploy behind IAP for Matthijs only. `deploy_check.py iam` then confirms the IAP binding.

**Commit:** `feat(control-ui): audit, snapshots, events; deploy`

**M5 review gate.**

---

## M6. Email wrapper, switched off (`docs/email-wrapper.md`)

### Task 6.1: Wrapper with fake Gmail

**Files:**

- Create: `src/aiven/gateway/wrappers/{email.py,email_auth.py}`
- Test: `tests/gateway/test_email.py`

**Interfaces (produces):**

- `delegated_credentials(gateway_email: str, mailbox: str, scopes: list[str]) -> Credentials`: `google.auth.iam.Signer` plus `google.oauth2.service_account.Credentials(signer, gateway_email, token_uri, scopes=scopes, subject=mailbox)`.
- The actions follow email-wrapper §4.

**Tests:**

- `test_disabled_refuses_before_any_gmail_call` (G-10)
- `test_mailbox_pinned`
- `test_recipient_rules` (scope, aivenstudios.com, 4 recipients reclassified as `gmail.send_bulk`)
- `test_html_body_refused`
- `test_read_reveals_hidden_parts_and_taints`
- `test_send_only_own_draft`
- `test_send_preview_hash_binds_draft`
- AT-INJ-1 to AT-INJ-6 and AT-PASTE-1 at L2, with `t-obedient` and the fake Gmail.

**Commit:** `feat(email): wrapper, shipped disabled`

### Task 6.2: Ship disabled

**Steps:**

1. Deploy.
2. `wrappers/email.enabled_for` stays `[]`.
3. Set catalog `wrapper_status.email: built`; Matthijs re-signs.

**Done when:** an L3 check shows that a test policy with gmail tools fails to load with E-TOOL-NOT-LIVE. Enabling the wrapper waits for S8 and gate G2.

**Commit:** `feat(email): deploy disabled`

**M6 review gate.**

---

## M7. Agent runtime and model layer (gateway-design §15)

### Task 7.1: Provider-neutral model interface and Gemini adapter

**Files:**

- Create: `src/aiven/agent/model/{base.py,gemini.py}`
- Test: `tests/agent/model/test_gemini.py`, using recorded responses in `tests/agent/model/fixtures/gemini/`

**Interfaces (produces):**

- `ToolSpec(name, description, input_schema: dict)`
- `ToolCall(id, name, args: dict)`
- `ToolResult(call_id, name, content: dict, is_error: bool)`
- `Usage(model, input_tokens, output_tokens)`
- `Turn(text: str, tool_calls: list[ToolCall], stop: Literal["end","tool_calls","max_tokens","refusal"], usage: list[Usage])`
- `Conversation`: append-only. It holds provider-native history, and its tools are fixed at `start`.
- `ModelClient` protocol:
  - `start(system: str, tools: list[ToolSpec]) -> Conversation`
  - `send(conv: Conversation, user_text: str | None = None, tool_results: list[ToolResult] | None = None) -> Turn`
- `VertexGeminiModel(project: str, location: str, model_id: str, max_output_tokens: int)`:
  - Built on `genai.Client(vertexai=True, project=project, location=location)`.
  - Function declarations only, built from `input_schema`.
  - Automatic function calling is off.
  - The model's content is appended unchanged, which keeps thought signatures.
  - Usage comes from `usage_metadata`; thinking tokens count as output.
  - A safety block maps to `refusal`.

**Tests:**

- `test_request_has_only_function_tools` (no search or grounding; AT-BYP-7)
- `test_model_content_replayed_unchanged`
- `test_usage_mapped`
- `test_safety_block_is_refusal`

**Commit:** `feat(agent): model interface and Gemini adapter`

### Task 7.2: Claude adapter

**Files:**

- Create: `src/aiven/agent/model/claude.py`
- Test: `tests/agent/model/test_claude.py`, using recorded responses in `tests/agent/model/fixtures/claude/`

**Interfaces (produces):** `VertexClaudeModel(project: str, region: str, model_id: str, max_tokens: int, effort: str | None)`.

- **Client.** `anthropic.AnthropicVertex(project_id=project, region=region)`, authenticated with Google sign-in (no key).
- **Tools.**
  - Each tool is `{name, description, input_schema, strict: True}`, sent with `tool_choice` `auto` only, because forced tool choice is a 400 on current models.
  - Thinking is left at the model default, which is adaptive.
  - `effort` is set through `output_config` when configured.
- **History.**
  - The full `response.content` is appended unchanged (append-only, so preserved-thinking checks pass).
  - All tool results go in one user message, with `is_error` for refusals.
- **Stop reasons.**
  - `stop_reason == "refusal"` maps to `refusal`.
  - `pause_turn` triggers a resend.
- **Usage** is summed over `usage.iterations` when present.
- **Refusals.** A refusal is returned as `stop="refusal"` and is never retried on another model: no fallback middleware is used.

**Tests:**

- `test_tools_strict_and_choice_auto`
- `test_no_thinking_disable_param`
- `test_response_content_replayed_unchanged`
- `test_all_tool_results_in_one_message`
- `test_refusal_mapped`
- `test_iterations_usage_summed`
- `test_refusal_not_retried_on_another_model`

**Commit:** `feat(agent): Claude on Vertex adapter`

### Task 7.3: Config switch and conformance

**Files:**

- Create: `src/aiven/agent/{config.py,model/factory.py}`
- Test: `tests/agent/test_conformance.py`

**Interfaces (produces):**

- `ModelConfig(provider: Literal["vertex-gemini","vertex-claude"], model_id: str, region: str, max_output_tokens: int, effort: str | None = None)`
- `model_from_config(cfg: ModelConfig, project: str) -> ModelClient`

`runtime.yaml` example (Phase 1):

```yaml
model:
  provider: vertex-gemini
  model_id: <recorded in S7>
  region: europe-west4
  max_output_tokens: 8192
```

To switch an agent to Claude (available now), only these lines change:

```yaml
model:
  provider: vertex-claude
  model_id: <Claude model ID chosen in setup step S7>
  region: eu
  max_output_tokens: 16000
```

The switch also needs the model's price added to `pricing/models.yaml`.

**Tests:**

- `test_same_script_same_gateway_calls_for_both_providers`: the scripted conversation runs through both adapters on recorded fakes, and the gateway call sequences are identical.
- `test_switch_is_config_only`: two configs that differ only in `model.*` build different adapters, and the agent loop is unchanged.

**Commit:** `feat(agent): model config switch and conformance tests`

### Task 7.4: Gateway client, agent loop, test agents

**Files:**

- Create: `src/aiven/agent/{gateway_client.py,runtime.py,scripted.py}`
- Create: `agents/t-*/{policy.md,runtime.yaml}`
- Create: `infra/terraform/modules/agents/jobs.tf`
- Test: `tests/agent/test_runtime.py`

**Interfaces (produces):**

- `GatewayClient(base_url: str, audience: str)`, with methods `me()`, `start_run()`, `call(run_id, action, args, request_id)`, `call_status(run_id, call_id)` and `end_run(run_id, usage, end_reason)`. It gets ID tokens from `google.oauth2.id_token.fetch_id_token`.
- `run_agent(task: str, gateway: GatewayClient, model: ModelClient, max_turns: int = 30) -> dict`, returning the gateway's end-run summary. Tools come from `GET /v1/me` at run start. A refused call becomes an `is_error` tool result. A model refusal ends the run with `end_reason="model_refusal"`. The run's usage is reported at `end_run`.
- `scripted.py` holds `t-reader`, `t-writer`, `t-shadow`, `t-attacker` and `t-obedient`, as in test-plan §3.

**Tests:**

- `test_refusal_becomes_error_result`
- `test_model_refusal_ends_run_and_is_logged`
- `test_usage_reported_at_end` (CR-1)
- `test_max_turns_stops`

**Done when:** Matthijs signs the test-agent policies, the jobs are deployed, and `t-reader` and `t-llm` smoke runs work.

**Commit:** `feat(agent): runtime and test agents`

**M7 review gate.**

---

## M8. End-to-end tests, drills, report (`docs/test-plan.md` §6–§9)

### Task 8.1: L3 harness

**Files:**

- Create: `tests/l3/{harness.py,changes_feed.py,canaries.py,conftest.py}`

The harness:

- runs on Matthijs's machine under Matthijs's own login;
- starts jobs, flips switches, and reads the audit log and the Drive Changes feed (`changes.list` with `driveId`).

**Tests:** `test_harness_reads_changes_and_audit` (smoke).

**Commit:** `test(l3): harness`

### Task 8.2: Absolute criteria (A2–A5)

**Files:**

- Create: `tests/l3/test_audit.py` (AU-1 to AU-3)
- Create: `tests/l3/test_kill_switch.py` (KS-1 to KS-5; records timings)
- Create: `tests/l3/test_rollback.py` (RB-2, plus RB-1 setup and verification around Matthijs's manual rollback)
- Create: `tests/l3/test_shadow.py` (SH-1 to SH-4)

**Commit:** `test(l3): absolute criteria`

### Task 8.3: Attack set at L3

**Files:**

- Create: `tests/l3/test_attacks.py`: AT-DEL-1 to AT-DEL-7, AT-BYP-1 to AT-BYP-8, AT-SELF-1 to AT-SELF-6, and AT-PASTE-1 to AT-PASTE-3 (L3 parts).
- Create: the probe jobs AT-DEL-7 and RB-2, which are deleted after the run.

AT-INJ at L3 waits for gate G2.

**Commit:** `test(l3): basic attack set`

### Task 8.4: Drills, A1 check, report

**Files:**

- Create: `tests/l3/report.py`, which writes `test-reports/<date>.md` with the test-plan §9 fields.

**Steps:**

1. BD-1, BD-2 and BD-4 (budget runbook drill).
2. KS-5 break glass.
3. The A1 computation over the attack window.
4. CR-2 reconciliation (monthly).

**Done when:** gate G1 is met. After that, DN-1 runs with AIVEN's first real agents (10 shadow runs, sign-off, then 10 live runs). Gate G3 follows when the full suite passes on that release.

**Commit:** `test(l3): drills and report`

**M8 review gate**, then the whole-branch review.

---

## Coverage map (self-review)

| Spec | Tasks |
|---|---|
| validator-spec §1–§3, §7, §9, appendix A | 1.1–1.8 |
| validator-spec §4 (reading order) | 3.2 |
| gateway-design §2, §3, §11 | S4–S5, 2.1, 2.5 |
| gateway-design §4 | 3.3, 3.8 |
| gateway-design §5 | 2.2, 2.3 (audit writer), 3.1, 3.4 |
| gateway-design §6 | 3.2, 3.4, 3.6, 3.8 |
| gateway-design §7 | 3.7, 5.2 |
| gateway-design §8 | 3.4, 5.3, 8.2 |
| gateway-design §9 | S2, 2.3, 3.9 |
| gateway-design §10 | 2.4 |
| gateway-design §12 | M6 |
| gateway-design §14 | S1–S3, the credit calendar, 2.4 |
| gateway-design §15 | M7 |
| drive-wrapper §1–§7 | S5, 4.1–4.5 |
| email-wrapper §1–§7 | S8, 6.1–6.2 |
| runbooks | 2.3 (drill), 8.2 (RB-1), 8.4 |
| test-plan §5 (L1/L2) | inside M1–M7 |
| test-plan §6–§9 (L3, drills, report) | M8 |
