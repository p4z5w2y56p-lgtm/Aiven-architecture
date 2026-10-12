# Policy validator: spec v1

Status: draft for review (Phase 1, step 1). It covers `aiven-policy/v1` files such as `templates/policy-template.md`.
Policy files are written in English. Validator messages come in English and Dutch (appendix A) because the UI is bilingual.

## 1. What it does

The validator decides whether a policy file may be signed and whether the gateway may load it. The same build runs in three places:

| Where | Command | An error blocks |
|---|---|---|
| CI, on every change in Git | `aiven-policy validate` | the merge |
| Matthijs's machine, before signing | `aiven-policy validate`, then `ssh-keygen -Y sign` | the signature |
| Gateway, on every load | `aiven-policy verify` (validate plus 3.9 and 3.10) | loading, so the agent gets no tools |

- **Fail closed.** Any error, or a validator crash (E-INTERNAL, exit 2), makes the file invalid.
- **The gateway wins.** The gateway enforces "R3 off", "R4 refused", the catalog classes and the ceilings itself. The validator stops a bad file early; it does not do the enforcing.
- **Report everything,** sorted by line. If the front matter cannot be parsed, the checks that need it are skipped. The file, hidden-character, placeholder and content-safety checks still run.
- **Never print sensitive values.** Content-safety findings give the kind and the line, not the value.

Each finding is one line: `<severity> <CODE> <path>[:<line>]: <message>`. With `--json` the output also includes the column, the parameters and the Dutch text for the UI. Exit codes: 0 means valid (warnings allowed), 1 means errors, 2 means the validator could not run.
`aiven-policy render <file>` rewrites the two generated body sections from the front matter. It changes nothing else.

## 2. Hash and signature

- **Policy hash:** `sha256:` followed by the hex SHA-256 of the file's exact bytes. The format rules in 3.1 make those bytes canonical, so nothing is normalised before hashing. Logs carry the full hash; the UI shows the first 12 characters.
- **Signature:** a detached `<agent>.md.sig` next to the file, made with SSH signing under namespace `aiven-policy-v1`. The namespace stops a Git commit signature from being reused as a policy signature.
- **Key:** a hardware security key (`ed25519-sk`, touch to sign). The private key never leaves the device, so nothing secret is stored in Git or Google Cloud.
- **Trust anchor:** an `allowed_signers` file with one line, `matthijs namespaces="aiven-policy-v1" <public key>`. The gateway trusts only the copy in the control project.
- A file never contains its own hash or signature.

```sh
aiven-policy validate policies/invoice-reminder.md        # must exit 0
ssh-keygen -Y sign -f ~/.ssh/aiven_policy_sk -n aiven-policy-v1 policies/invoice-reminder.md
ssh-keygen -Y verify -f allowed_signers -I matthijs -n aiven-policy-v1 \
  -s policies/invoice-reminder.md.sig < policies/invoice-reminder.md
```

## 3. Checks

`E-` codes are errors and `W-` codes are warnings. Every message is listed in appendix A.

### 3.1 File

| Code | Fails when |
|---|---|
| E-ENCODING | The file is not valid UTF-8, or it starts with a byte-order mark |
| E-LINE-ENDINGS | It contains a CR |
| E-FINAL-NEWLINE | It does not end with exactly one LF |
| E-FILE-SIZE | It is larger than 64 KiB |
| E-FILENAME | The name is not `<agent>.md` |
| E-HIDDEN-CHAR | A hidden character (listed below) appears anywhere |
| E-PLACEHOLDER | `REPLACE_ME…`, `TODO`, `TBD` or `FIXME` appears anywhere. A field that holds a placeholder skips its other checks. |

Hidden characters are Unicode Cc except LF (so TAB is included), Cf (zero-width characters, bidi controls, soft hyphen, tag characters U+E0000–E007F), Zl, Zp, Zs except the normal space, and also U+034F, U+115F, U+1160, U+3164, U+FFA0, U+FE00–FE0F and U+E0100–E01EF. They can hide text from the signer, or smuggle instructions to a model that reads the file.

### 3.2 Front matter

| Code | Fails when |
|---|---|
| E-FM-MISSING | Line 1 is not `---`, or the block has no closing `---` |
| E-YAML | The front matter cannot be parsed |
| E-YAML-FEATURE | It uses an anchor, alias, merge key (`<<`), tag (`!`), directive or complex key, or contains more than one document |
| E-YAML-DUPLICATE-KEY | A key appears twice in one mapping. Most parsers silently keep one of the two values. |
| E-FM-NON-ASCII | A non-ASCII character appears in the front matter, comments included (look-alike letters) |
| E-FIELD-MISSING | A required field from 3.3 is absent |
| E-FIELD-UNKNOWN | A field is not in 3.3. Names are case-sensitive, and unknown fields are never ignored. |
| E-FIELD-TYPE | A value has the wrong type or is not one of the allowed values. Integers must be plain digits, with no quotes, sign, leading zero, `_` or `0x`, and not `5:00` (YAML 1.1 reads that as 300). |
| E-LIST-DUPLICATE | An entry repeats in `tools`, `forbidden` or `scope.email_to` |

### 3.3 Fields

Every front matter field is enforced, or used to enforce something; none is decorative. All fields are required except `scope.*`, which is required only alongside the tools named below.

| Field | Rule | Codes |
|---|---|---|
| `schema` | `aiven-policy/v1` | E-SCHEMA |
| `agent` | 3–24 characters matching `^[a-z][a-z0-9]*(-[a-z0-9]+)*$`, not a reserved id (see 6) | E-AGENT-ID |
| `version` | 1–9999. A new agent starts at 1; after that, exactly the previous signed version + 1. | E-RANGE, E-VERSION-ORDER |
| `principal` | `agent-<agent>@<agents project>.iam.gserviceaccount.com`, unique across all policies | E-PRINCIPAL, E-PRINCIPAL-DUPLICATE |
| `max_class` | `R0`, `R1` or `R2` | E-MAX-CLASS-R3, E-MAX-CLASS-R4, E-FIELD-TYPE |
| `tools` | 1–20 exact catalog names | see 3.4 |
| `forbidden` | Exact names or `namespace.*`, including the baseline | see 3.4 |
| `untrusted_input` | `taint` or `strict` | E-UNTRUSTED-INPUT |
| `limits.emails_per_day` | 0–50 | E-RANGE, E-LIMIT-CONFLICT |
| `limits.records_per_run` | 0–200 | E-RANGE, E-LIMIT-CONFLICT |
| `limits.spend_eur_per_run` | 0 | E-LIMIT-SPEND |
| `limits.max_runtime_s` | 30–900 | E-RANGE |
| `limits.runs_per_day` | 1–24 | E-RANGE |
| `scope.drive_folder_id` | Required with any `drive.*` or `sheets.*` tool. Matches `^[A-Za-z0-9_-]{10,100}$`. | E-SCOPE-MISSING, E-FIELD-TYPE |
| `scope.drive_folder_path` | Required with the folder ID. `AIVEN Architecture / Sandbox`, optionally followed by more ` / <folder>` parts. | E-SCOPE-MISSING, E-SCOPE-SANDBOX |
| `scope.email_to` | Required with `gmail.draft` or `gmail.send`. 1–50 lowercase entries, each `name@domain.tld` or `@domain.tld`. A domain entry matches that exact domain, not its subdomains. | E-SCOPE-MISSING, E-SCOPE-EMAIL, E-SCOPE-EMAIL-PUBLIC |
| `shadow.min_runs` | 1–100 | E-RANGE, W-SHADOW-LOW |

What the gateway does with each field:

- **`principal`:** the gateway authenticates every call and applies only the policy whose principal matches the caller. Each agent has its own identity.
- **`max_class`:** caps the effective class of a call after any runtime escalation (for example, an edit to a shared file becomes R2). A call above the cap is refused, not queued.
- **`forbidden`:** an attempt is refused, logged and alerted. A tool that is simply not listed is refused and logged, without an alert.
- **`untrusted_input`:**
  - `taint`: each R2 action from a tainted run is confirmed on its own, and the preview shows the untrusted sources the run read.
  - `strict`: in a tainted run, R1 actions also wait for a confirm.
- **`limits`:** the call that would cross a limit is refused, and the run ends.
  - A day is a calendar day in Europe/Amsterdam.
  - Emails are counted per recipient (To, Cc and Bcc) at the moment the send is requested.
  - Records are the items changed by R1+ actions: a file, a draft, a sheet row or an agent. Sends count as emails, not as records.
  - Shadow-mode proposals count toward the limits.
  - Spend is money that actions commit to, not the agent's compute cost.
- **`scope`:** every Drive call is checked against the folder through the file's parent chain. Every draft and every send is checked against `email_to`.
- **`shadow.min_runs`:** see 3.6.

### 3.4 Tools and forbidden

| Code | Fails when |
|---|---|
| E-TOOL-UNKNOWN | A tool is not in the catalog (section 5) |
| E-TOOL-WILDCARD | A tool contains `*` |
| E-TOOL-R3 | A tool's class is R3 |
| E-TOOL-R4 | A tool's class is R4, or the tool is in a reserved namespace |
| E-TOOL-ABOVE-MAX-CLASS | A tool's class is higher than `max_class` |
| E-TOOL-FORBIDDEN | A tool matches a `forbidden` entry |
| E-FORBIDDEN-PATTERN | An entry is neither an exact name nor `namespace.*` |
| E-FORBIDDEN-UNKNOWN | An entry matches nothing in the catalog or the reserved list. A typo protects nothing. |
| E-FORBIDDEN-BASELINE | One of `payments.*`, `drive.delete`, `drive.share` or `gmail.send_bulk` is missing |
| W-MAX-CLASS-SLACK | `max_class` is higher than the highest tool class |
| W-TOOL-NOT-LIVE | The tool's wrapper is not live yet. At load this becomes E-TOOL-NOT-LIVE. |

### 3.5 Limits and scope

| Code | Fails when |
|---|---|
| E-RANGE | A number is outside its range in 3.3 |
| E-LIMIT-SPEND | `spend_eur_per_run` is not 0 |
| E-LIMIT-CONFLICT | `gmail.send` is listed but `emails_per_day` is 0, or an R1+ tool is listed but `records_per_run` is 0 |
| E-SCOPE-MISSING | A tool needs a scope field that is missing |
| E-SCOPE-SANDBOX | `drive_folder_path` is not the Sandbox or a folder inside it |
| E-SCOPE-EMAIL | An `email_to` entry is malformed, uppercase or has a wildcard |
| E-SCOPE-EMAIL-PUBLIC | An `@domain` entry is a public mail domain (see 6) |
| W-LIMIT-UNUSED | `emails_per_day` is above 0 without `gmail.send`, or `records_per_run` is above 0 without an R1+ tool |
| W-SCOPE-UNUSED | A scope field is set, but no tool uses it |

### 3.6 Shadow mode and widening

- A new agent starts in shadow mode. R0 calls run. R1 and higher calls are recorded as proposals and not executed, and the proposals count toward the limits.
- Once the agent has finished `min_runs` shadow runs, Matthijs can sign it off in the control UI. Until then it stays in shadow, and nothing promotes it automatically. The sign-off is logged with the policy hash.
- A version that adds a tool or raises `max_class` puts the agent back in shadow for `min_runs` runs.
- W-SHADOW-LOW fires when `min_runs` is below 10.
- W-WIDENS needs the previous signed version. It lists what the new version widens (tools, `max_class`, a limit, scope, `strict` to `taint`, a lower `min_runs`) and says whether shadow mode restarts.

### 3.7 Body

The body is parsed as CommonMark with tables. Headings inside code blocks do not count.

| Code | Fails when |
|---|---|
| E-BODY-TITLE | The first non-empty body line is not `# <agent>` |
| E-BODY-SECTIONS | The `##` sections are not exactly these, in this order: Purpose, Why each tool, Data and risks, Enforced rules (generated), Sign-off (generated). `###` headings are allowed inside the first three. |
| E-BODY-EMPTY | Purpose, Why each tool or Data and risks has fewer than 20 characters of text |
| E-BODY-TOOL-UNEXPLAINED | A tool has no ``- `tool`: reason`` bullet in Why each tool, or the reason is empty |
| E-BODY-TOOL-EXTRA | Why each tool explains a tool that is not in `tools` |
| E-BODY-DRIFT | A generated section differs from what `render` produces from the front matter (see 7) |
| E-BODY-HTML | Raw HTML or an HTML comment appears |
| E-BODY-LINK | A link, image or URL appears |

E-BODY-DRIFT closes a gap in the plan: you sign the body, but the gateway enforces the front matter. Rendering the body from the front matter and refusing any difference means the two always say the same thing.

### 3.8 Content safety (whole file, comments included)

| Code | Fails when |
|---|---|
| E-SECRET | The file contains a credential: a PEM private key; service-account key JSON (`"private_key"`); a Google API key (`AIza` plus 35 characters); an OAuth token (`ya29.`, `1//0`); a GitHub, Slack, Anthropic, OpenAI or AWS key prefix; a JWT; or `password`, `secret`, `token`, `api_key` or `client_secret` followed by `:` or `=` and a value |
| E-BANK-DETAILS | The file contains an IBAN (spaces allowed, mod-97 valid) or a card number (13–19 digits, Luhn valid) |
| E-ID-NUMBER | The file contains a 9-digit number that passes the BSN eleven-test |

### 3.9 Across all policies (CI and gateway)

| Code | Fails when |
|---|---|
| E-AGENT-DUPLICATE | Two files declare the same `agent` |
| E-PRINCIPAL-DUPLICATE | Two policies share a `principal` |
| E-VERSION-ORDER | `version` is not the previous signed version + 1. In CI, "previous" comes from Git history; at load it is the active version. |

### 3.10 At load only (`verify`)

| Code | Fails when |
|---|---|
| E-SIG-MISSING | There is no `<agent>.md.sig` |
| E-SIG-INVALID | `ssh-keygen -Y verify` fails against the control project's `allowed_signers` |
| E-VERSION-ORDER | The version is lower than the active one, or equal to it with a different hash. Old versions can never come back. |
| E-TOOL-NOT-LIVE | A tool's wrapper is not live |
| E-SCOPE-NOT-IN-SANDBOX | Following the folder ID's parent chain does not reach the Sandbox, or the folder's real path differs from `drive_folder_path` |

If a new version fails `verify`, the gateway keeps the active version and alerts Matthijs. If the active version fails (for example, its file changed), the agent is stopped and Matthijs is alerted.

## 4. How the gateway reads a policy

The validator assumes this order; the full gateway design follows in step 2. For each call, the first matching step decides the outcome:

1. The kill switch is on, globally or for this agent: refuse.
2. The caller is not the `principal` of a loaded policy: refuse, log, alert.
3. Classify the call with the catalog. This includes runtime escalation and smuggled fields, so a Drive update that trashes a file counts as `drive.delete`.
4. The call is reserved R4 or matches `forbidden`: refuse, log, alert.
5. The tool is not in `tools`: refuse, log (default deny).
6. The class is R3: refuse, log (R3 is disabled in v1).
7. The class is above `max_class`: refuse, log.
8. The call is outside `scope`: refuse, log.
9. The call would cross a limit: refuse, end the run, log.
10. The agent is in shadow mode and the class is R1 or higher: record the call as a proposal and do not execute it.
11. Apply the gate:
    - R0 runs.
    - R1 takes a snapshot, then runs. With `strict`, in a tainted run, R1 is handled as R2.
    - R2 goes to the confirm queue.

Every outcome is logged with the actor, class, approver, policy hash, catalog hash, run and taint state.

## 5. Action catalog v1 (owned by the gateway)

Classes are defined here and nowhere else. A policy grants tools, but it can never set or lower a class. The catalog is reviewed and signed like a policy, and its hash goes on every log line next to the policy hash. Because one wrong class here affects every agent, it is now the biggest single risk, and step 3 tests every row.

| Action | Class | Wrapper | Gateway rule | Undo text (rendered) |
|---|---|---|---|---|
| `drive.list` | R0 | Drive | Lists items in the scope folder; anything outside scope is dropped | nothing to undo (read only). |
| `drive.read` | R0 | Drive | Reads one file's content and metadata in scope | nothing to undo (read only). |
| `sheets.read` | R0 | Drive | Reads the cells of a Sheet in scope | nothing to undo (read only). |
| `drive.create` | R1 | Drive | Creates a file or folder in scope | remove the new file by hand (agents cannot delete). |
| `drive.update` | R1, or R2 if the file is shared beyond Matthijs and the gateway | Drive | Changes content or name only | restore the previous version from its snapshot (kept 30 days). |
| `sheets.write` | R1, or R2 if shared (as above) | Drive | Writes or appends cells in a Sheet in scope | restore the previous cell values from the snapshot (kept 30 days). |
| `drive.move` | R3 | Drive | A move changes who inherits access | (not grantable) |
| `drive.share` | R3 | Drive | Any change to permissions, link sharing or sharing settings | (not grantable) |
| `drive.delete` | R3 | Drive | Trash, delete, empty trash | (not grantable) |
| `gmail.read` | R0 | Email | Reads a message in the wrapped mailbox | nothing to undo (read only). |
| `gmail.draft` | R1 | Email | Creates or edits a draft with at most 3 recipients, all in `scope.email_to` | restore or remove the draft from its snapshot (kept 30 days). |
| `gmail.send` | R2 | Email | Sends one draft this agent created; each recipient counts toward `emails_per_day` | a sent email cannot be recalled; follow up by hand. |
| `gmail.send_bulk` | R3 | Email | Any message to more than 3 recipients | (not grantable) |
| `agentbuilder.read` | R0 | Agent Builder | Reads agent definitions | nothing to undo (read only). |
| `agentbuilder.create` | R1 | Agent Builder | Creates an unpublished agent whose only tool is the gateway. It has no access until Matthijs signs its policy. | remove the unpublished agent by hand. |
| `agentbuilder.publish` | R2 | Agent Builder | Publishes an agent | unpublish by hand; anyone who used it in the meantime has seen it. |

These namespaces are reserved and count as R4 for every agent, whatever a file says (refused, logged, alerted): `payments.*`, `policy.*`, `audit.*`, `killswitch.*`, `iam.*`, `secrets.*`, `agentbuilder.permissions`.

Rules for every action:

- **Typed actions only.** The gateway never passes a raw API call through. Each action accepts a fixed set of fields. A Drive update that sets `trashed`, changes parents or touches permissions is classed as `drive.delete`, `drive.move` or `drive.share`.
- **Taint.** In v1, every R0 action taints the run, because file names, file content, cells, email and agent definitions can all carry injected instructions.
- **Content scan.** Every R1 and R2 payload is scanned with the patterns in 3.8, and a match refuses the write. This keeps bank details, ID numbers and credentials out of Drive, drafts and snapshots written through the gateway.
- **Wrapper status today:** all three wrappers (1 Drive, 2 Email, 3 Agent Builder) are `planned`.

## 6. Platform constants v1

Changing a constant means a new validator version, reviewed and signed the same way.

| Constant | v1 value |
|---|---|
| Schema | `aiven-policy/v1` |
| Signer | `matthijs` (Matthijs van Hoorn), the only signer. There is no second approver. |
| Signature namespace | `aiven-policy-v1` |
| Classes a policy may use | R0, R1, R2. R3 is disabled; R4 is never allowed. |
| Forbidden baseline | `payments.*`, `drive.delete`, `drive.share`, `gmail.send_bulk` |
| Drive root | `AIVEN Architecture / Sandbox`, with its folder ID set at deploy |
| Agents project | Set at deploy; used in `principal` |
| Day | Calendar day, Europe/Amsterdam |
| Bulk email | More than 3 recipients in one message |
| Shadow default | 10 runs |
| Retention | Snapshots: 30 days. Audit log: append-only, kept 1 year. |
| Ceilings | As listed in 3.3 |
| Reserved agent ids | `admin`, `all`, `audit`, `control`, `gateway`, `killswitch`, `matthijs`, `policy`, `system`, `template` |
| Public mail domains | `gmail.com`, `googlemail.com`, `outlook.com`, `hotmail.com`, `hotmail.nl`, `live.com`, `live.nl`, `msn.com`, `yahoo.com`, `icloud.com`, `me.com`, `proton.me`, `protonmail.com`, `gmx.com`, `gmx.net`, `aol.com`, `ziggo.nl`, `kpnmail.nl`, `planet.nl`, `home.nl`, `xs4all.nl` |

## 7. Rendering the generated sections

`render` writes "Enforced rules (generated)" and "Sign-off (generated)" exactly as they appear in `templates/policy-template.md`, with the values substituted. That file is the reference output.

- Lists keep the front matter order. The tools table has one row per tool.
- Class and gate columns:
  - R0: `R0 read` / `Runs at once, logged`
  - R1: `R1 reversible` / `Snapshot first, then runs at once, logged`
  - R2: `R2 costly to undo` / `Waits for Matthijs to confirm a plain-language preview`
- Untrusted input: `taint` renders the template's sentence. `strict` renders the same sentence followed by ` In a tainted run, R1 actions also wait for Matthijs to confirm.`
- Scope: a Drive bullet if `drive_folder_id` is set, and an Email bullet if `email_to` is set (entries in backticks, separated by commas). If neither is set: `- None: this agent has no Drive or email tools.`
- Undo: one bullet per tool, using the Undo text from the catalog.
- Spend renders as `€0`. When `min_runs` is 1, the shadow sentence uses the singular ("the first run only proposes", "after 1 run").
- The policy view shows the same sections in Dutch, rendered from the same values with fixed translations. Only the English file is signed.

## 8. What the validator cannot check

- **Whether the catalog classes are right.** Your review and step 3's per-action tests are the safeguard.
- **Whether Purpose, Why each tool and Data and risks are true and complete.** That is your review.
- **Anything that bypasses the gateway:**
  - built-in tools or web search on the agent platform
  - direct logins to Drive or Gmail
  - files someone shares with a service account by hand

  These need deployment checks, which come in step 2.
- **Disguised secrets, IBANs or BSNs** (split up, spelled out, or inside an image). An innocent 9-digit number can also be flagged by mistake.
- **Folder ancestry and wrapper status** until the gateway loads the file.
- **Whether a policy is wise.** Warnings point at slack, but least privilege stays your decision.

## 9. Template self-test

Today no wrapper is live, so `aiven-policy validate templates/policy-template.md` must print exactly these findings, in this order, and exit 1:

| Severity | Code | Line | About |
|---|---|---|---|
| error | E-FILENAME | (file) | `policy-template.md` should be `invoice-reminder.md` |
| error | E-PLACEHOLDER | 6 | `REPLACE_ME_AGENTS_PROJECT` |
| warning | W-TOOL-NOT-LIVE | 9 | `sheets.read` (Drive) |
| warning | W-TOOL-NOT-LIVE | 10 | `gmail.draft` (Email) |
| warning | W-TOOL-NOT-LIVE | 11 | `gmail.send` (Email) |
| error | E-PLACEHOLDER | 25 | `REPLACE_ME_FOLDER_ID` |
| error | E-PLACEHOLDER | 28 | `REPLACE_ME_CLIENT_DOMAIN` |
| error | E-PLACEHOLDER | 56 | `REPLACE_ME_AGENTS_PROJECT` |
| error | E-PLACEHOLDER | 84 | `REPLACE_ME_FOLDER_ID` |
| error | E-PLACEHOLDER | 85 | `REPLACE_ME_CLIENT_DOMAIN` |

To turn the template into a real policy, fill in the three values in the front matter, run `aiven-policy render`, and save the file as `policies/invoice-reminder.md`. After that only the three warnings remain (exit 0), and they disappear once the Drive and Email wrappers are live.

## Appendix A. Messages (EN + NL)

Values in `{braces}` are parameters. The UI translates parameters that are words (`{expected}`, `{kind}`, `{feature}`, `{wrapper}`); codes, field names and values stay as they are. The UI shows the line number in its own column, so messages do not repeat it.

| Code | EN | NL |
|---|---|---|
| E-ENCODING | File is not plain UTF-8 (invalid bytes or a byte-order mark). Save it as UTF-8 without BOM. | Bestand is geen zuivere UTF-8 (ongeldige bytes of een BOM). Sla het op als UTF-8 zonder BOM. |
| E-LINE-ENDINGS | Windows line ending (CR) found. Use LF only; the hash depends on the exact bytes. | Windows-regeleinde (CR) gevonden. Gebruik alleen LF; de hash hangt af van de exacte bytes. |
| E-FINAL-NEWLINE | The file must end with exactly one newline. | Het bestand moet eindigen op precies één regeleinde. |
| E-FILE-SIZE | File is {size} bytes; the maximum is 65536. | Bestand is {size} bytes; het maximum is 65536. |
| E-FILENAME | File name {name} must be {agent}.md. | Bestandsnaam {name} moet {agent}.md zijn. |
| E-HIDDEN-CHAR | Invisible or direction-changing character {codepoint} at column {col}. It can hide text from the signer; remove it. | Onzichtbaar of richtingveranderend teken {codepoint} in kolom {col}. Het kan tekst verbergen voor de ondertekenaar; verwijder het. |
| E-PLACEHOLDER | Placeholder {token} is still there. Fill it in before signing. | Placeholder {token} staat er nog. Vul die in vóór het ondertekenen. |
| E-FM-MISSING | No front matter. Line 1 must be --- and the block must end with ---. | Geen front matter. Regel 1 moet --- zijn en het blok moet eindigen met ---. |
| E-YAML | Front matter is not valid YAML (column {col}): {detail}. | Front matter is geen geldige YAML (kolom {col}): {detail}. |
| E-YAML-FEATURE | YAML {feature} is not allowed. Write every value out in full. | YAML-{feature} is niet toegestaan. Schrijf elke waarde voluit. |
| E-YAML-DUPLICATE-KEY | Key {key} appears twice. You would read one value while the gateway may use the other. Keep one. | Sleutel {key} staat er twee keer. Jij leest de ene waarde, de gateway gebruikt mogelijk de andere. Houd er één. |
| E-FM-NON-ASCII | Non-ASCII character at column {col}. Letters that look like others can disguise a name. Use plain ASCII (punycode for international domains). | Niet-ASCII-teken in kolom {col}. Letters die op andere letters lijken kunnen een naam vermommen. Gebruik gewone ASCII (punycode voor internationale domeinen). |
| E-FIELD-MISSING | Required field {field} is missing. | Verplicht veld {field} ontbreekt. |
| E-FIELD-UNKNOWN | Unknown field {field}. Remove it or fix the spelling; unknown fields are never ignored. | Onbekend veld {field}. Verwijder het of verbeter de spelling; onbekende velden worden nooit genegeerd. |
| E-FIELD-TYPE | {field} must be {expected}; found {found}. | {field} moet {expected} zijn; gevonden: {found}. |
| E-LIST-DUPLICATE | {list} lists {entry} more than once. | {list} bevat {entry} meer dan één keer. |
| E-SCHEMA | schema is {found}; this validator accepts only aiven-policy/v1. | schema is {found}; deze validator accepteert alleen aiven-policy/v1. |
| E-AGENT-ID | agent {value} is not a valid id: use 3 to 24 lowercase letters, digits and single hyphens, start with a letter, and avoid reserved names. | agent {value} is geen geldige id: gebruik 3 tot 24 kleine letters, cijfers en losse koppeltekens, begin met een letter en vermijd gereserveerde namen. |
| E-PRINCIPAL | principal must be agent-{agent}@{project}.iam.gserviceaccount.com, this agent's own service account; found {value}. | principal moet agent-{agent}@{project}.iam.gserviceaccount.com zijn, het eigen serviceaccount van deze agent; gevonden: {value}. |
| E-MAX-CLASS-R3 | max_class R3 is not allowed: R3 is disabled in v1 because there is only one signer. | max_class R3 is niet toegestaan: R3 staat uit in v1 omdat er maar één ondertekenaar is. |
| E-MAX-CLASS-R4 | max_class R4 is never allowed: R4 actions are refused for every agent. | max_class R4 is nooit toegestaan: R4-acties worden voor elke agent geweigerd. |
| E-UNTRUSTED-INPUT | untrusted_input must be taint or strict. Taint tracking cannot be switched off. | untrusted_input moet taint of strict zijn. Taint-tracking kan niet uit. |
| E-RANGE | {field} is {value}; allowed in v1: {min} to {max}. | {field} is {value}; toegestaan in v1: {min} tot en met {max}. |
| E-TOOL-UNKNOWN | Tool {tool} is not in the action catalog. Only catalog actions can be granted. | Tool {tool} staat niet in de actiecatalogus. Alleen catalogusacties kunnen worden toegekend. |
| E-TOOL-WILDCARD | Tool {tool} contains a wildcard. Name every tool exactly. | Tool {tool} bevat een wildcard. Noem elke tool bij de exacte naam. |
| E-TOOL-R3 | Tool {tool} is R3 (cannot be undone). R3 is disabled in v1. | Tool {tool} is R3 (niet terug te draaien). R3 staat uit in v1. |
| E-TOOL-R4 | Tool {tool} is R4 (forbidden for every agent) and can never be granted. | Tool {tool} is R4 (verboden voor elke agent) en kan nooit worden toegekend. |
| E-TOOL-ABOVE-MAX-CLASS | Tool {tool} is {class}, above max_class {max}. Raise max_class or remove the tool. | Tool {tool} is {class}, boven max_class {max}. Verhoog max_class of verwijder de tool. |
| E-TOOL-FORBIDDEN | Tool {tool} is also matched by forbidden item {pattern}. A tool cannot be granted and forbidden at once. | Tool {tool} valt ook onder verboden item {pattern}. Een tool kan niet tegelijk toegestaan en verboden zijn. |
| E-FORBIDDEN-PATTERN | Forbidden item {entry} is not valid. Use an exact action (drive.delete) or a namespace ending in .* (payments.*). | Verboden item {entry} is ongeldig. Gebruik een exacte actie (drive.delete) of een namespace die eindigt op .* (payments.*). |
| E-FORBIDDEN-UNKNOWN | Forbidden item {entry} matches nothing in the catalog or the reserved list. Check the spelling: a typo here protects nothing. | Verboden item {entry} komt met niets in de catalogus of de gereserveerde lijst overeen. Controleer de spelling: een typfout beschermt niets. |
| E-FORBIDDEN-BASELINE | forbidden is missing {missing}. Every v1 policy forbids payments.*, drive.delete, drive.share and gmail.send_bulk. | forbidden mist {missing}. Elke v1-policy verbiedt payments.*, drive.delete, drive.share en gmail.send_bulk. |
| E-LIMIT-SPEND | limits.spend_eur_per_run must be 0 in v1. No agent may spend money. | limits.spend_eur_per_run moet 0 zijn in v1. Geen enkele agent mag geld uitgeven. |
| E-LIMIT-CONFLICT | limits.{limit} is 0, but tool {tool} needs at least 1. | limits.{limit} is 0, maar tool {tool} heeft minstens 1 nodig. |
| E-SCOPE-MISSING | scope.{field} is required because tools include {tool}. | scope.{field} is verplicht omdat tools {tool} bevat. |
| E-SCOPE-SANDBOX | scope.drive_folder_path must be AIVEN Architecture / Sandbox or a folder inside it. The gateway can reach nothing else. | scope.drive_folder_path moet AIVEN Architecture / Sandbox zijn of een map daarbinnen. De gateway kan nergens anders bij. |
| E-SCOPE-EMAIL | email_to item {entry} is invalid. Use a full address (name@domain.nl) or a domain (@domain.nl), lowercase, without wildcards. | email_to-item {entry} is ongeldig. Gebruik een volledig adres (naam@domein.nl) of een domein (@domein.nl), in kleine letters, zonder wildcards. |
| E-SCOPE-EMAIL-PUBLIC | email_to item {entry} would allow every user of a public mail service. List exact addresses instead. | email_to-item {entry} zou elke gebruiker van een publieke maildienst toestaan. Noem in plaats daarvan exacte adressen. |
| E-BODY-TITLE | The body must start with: # {agent} | De body moet beginnen met: # {agent} |
| E-BODY-SECTIONS | Sections must be exactly, in order: Purpose, Why each tool, Data and risks, Enforced rules (generated), Sign-off (generated). Found: {found}. | De secties moeten precies deze zijn, in deze volgorde: Purpose, Why each tool, Data and risks, Enforced rules (generated), Sign-off (generated). Gevonden: {found}. |
| E-BODY-EMPTY | Section {section} is empty. Write at least one full sentence. | Sectie {section} is leeg. Schrijf minstens één volledige zin. |
| E-BODY-TOOL-UNEXPLAINED | Tool {tool} is not explained in Why each tool. Add a bullet: - `{tool}`: why it is needed. | Tool {tool} wordt niet uitgelegd in Why each tool. Voeg een bullet toe: - `{tool}`: waarom die nodig is. |
| E-BODY-TOOL-EXTRA | Why each tool explains {tool}, which is not in tools. Remove the bullet or add the tool. | Why each tool legt {tool} uit, maar die staat niet in tools. Verwijder de bullet of voeg de tool toe. |
| E-BODY-DRIFT | Section {section} does not match the front matter (first difference at line {diff_line}). Run aiven-policy render and read the result before signing. | Sectie {section} komt niet overeen met de front matter (eerste verschil op regel {diff_line}). Voer aiven-policy render uit en lees het resultaat vóór het ondertekenen. |
| E-BODY-HTML | HTML or an HTML comment. A policy may not contain text the reader cannot see. | HTML of een HTML-commentaar. Een policy mag geen tekst bevatten die de lezer niet ziet. |
| E-BODY-LINK | Link, image or URL. A policy must be complete on its own. | Link, afbeelding of URL. Een policy moet op zichzelf compleet zijn. |
| E-SECRET | This looks like a credential ({kind}). Remove it, and revoke it if it is real. The value is not shown. | Dit lijkt op een inloggegeven ({kind}). Verwijder het en trek het in als het echt is. De waarde wordt niet getoond. |
| E-BANK-DETAILS | This looks like bank or card details ({kind}). Remove them; bank details are never stored. The value is not shown. | Dit lijkt op bank- of kaartgegevens ({kind}). Verwijder ze; bankgegevens worden nooit opgeslagen. De waarde wordt niet getoond. |
| E-ID-NUMBER | This looks like a BSN. Remove it; ID numbers are never stored. The value is not shown. | Dit lijkt op een BSN. Verwijder het; identiteitsnummers worden nooit opgeslagen. De waarde wordt niet getoond. |
| E-AGENT-DUPLICATE | Agent {agent} is defined in more than one file: {files}. | Agent {agent} staat in meer dan één bestand: {files}. |
| E-PRINCIPAL-DUPLICATE | principal {principal} is also used by {other}. Each agent needs its own identity, or one could act with the other's rights. | principal {principal} wordt ook gebruikt door {other}. Elke agent heeft een eigen identiteit nodig, anders kan de ene met de rechten van de andere handelen. |
| E-SIG-MISSING | No signature file {agent}.md.sig. Unsigned policies are never loaded. | Geen handtekeningbestand {agent}.md.sig. Niet-ondertekende policies worden nooit geladen. |
| E-SIG-INVALID | The signature does not verify for signer matthijs (namespace aiven-policy-v1). The file changed after signing, or another key signed it. | De handtekening klopt niet voor ondertekenaar matthijs (namespace aiven-policy-v1). Het bestand is na ondertekening gewijzigd, of een andere sleutel heeft getekend. |
| E-VERSION-ORDER | version is {value}, but the next version must be {next}. Older versions can never come back. | version is {value}, maar de volgende versie moet {next} zijn. Oudere versies kunnen nooit terugkomen. |
| E-TOOL-NOT-LIVE | Tool {tool} needs the {wrapper} wrapper, which is not live. The agent cannot load until it is. | Tool {tool} heeft de {wrapper}-wrapper nodig, die niet live is. De agent kan pas laden als die live is. |
| E-SCOPE-NOT-IN-SANDBOX | Drive folder {id} is not inside AIVEN Architecture / Sandbox, or its real path is not {path}. | Drive-map {id} ligt niet in AIVEN Architecture / Sandbox, of het echte pad is niet {path}. |
| E-INTERNAL | The validator could not finish ({detail}). The file counts as invalid. | De validator kon niet afronden ({detail}). Het bestand geldt als ongeldig. |
| W-MAX-CLASS-SLACK | max_class is {max} but the highest tool is {highest}. Calls that escalate at runtime (such as an edit to a shared file) will wait for your confirm instead of being refused. Lower max_class if you don't want that. | max_class is {max} maar de hoogste tool is {highest}. Acties die tijdens de run hoger uitvallen (zoals een wijziging in een gedeeld bestand) wachten dan op jouw bevestiging in plaats van geweigerd te worden. Verlaag max_class als je dat niet wilt. |
| W-TOOL-NOT-LIVE | Tool {tool} needs the {wrapper} wrapper, which is not live yet. You can sign now; the gateway loads the agent once the wrapper is live. | Tool {tool} heeft de {wrapper}-wrapper nodig, die nog niet live is. Ondertekenen kan nu; de gateway laadt de agent zodra de wrapper live is. |
| W-LIMIT-UNUSED | limits.{limit} is {value} but no tool uses it. Set it to 0. | limits.{limit} is {value} maar geen tool gebruikt het. Zet het op 0. |
| W-SCOPE-UNUSED | scope.{field} is set but no tool uses it. Remove it. | scope.{field} is ingesteld maar geen tool gebruikt het. Verwijder het. |
| W-SHADOW-LOW | shadow.min_runs is {value}, below the default of 10. | shadow.min_runs is {value}, lager dan de standaard van 10. |
| W-WIDENS | This version gives the agent more room: {changes}.{restart} | Deze versie geeft de agent meer ruimte: {changes}.{restart} |

For W-WIDENS, `{restart}` is " Shadow mode starts again for {n} runs." (NL: " De schaduwmodus begint opnieuw voor {n} runs.") when a tool is added or `max_class` rises; otherwise it is empty.
