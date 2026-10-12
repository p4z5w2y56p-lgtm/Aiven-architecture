---
# AIVEN policy, schema v1. The gateway enforces this block; the body below explains it.
schema: aiven-policy/v1
agent: invoice-reminder                  # must match the file name
version: 1                               # +1 on every signed change
principal: agent-invoice-reminder@REPLACE_ME_AGENTS_PROJECT.iam.gserviceaccount.com
max_class: R2                            # R0, R1 or R2. R3 is disabled in v1; R4 never.
tools:                                   # default deny: exact catalog names only
  - sheets.read
  - gmail.draft
  - gmail.send
forbidden:                               # attempt = refused, logged, alert
  - payments.*                           # required
  - drive.delete                         # required
  - drive.share                          # required
  - gmail.send_bulk                      # required
untrusted_input: taint                   # taint or strict
limits:                                  # hitting a limit stops the run
  emails_per_day: 10                     # recipients per calendar day, Europe/Amsterdam
  records_per_run: 10                    # items changed by R1+ actions; sends count as emails
  spend_eur_per_run: 0                   # must be 0 in v1
  max_runtime_s: 300
  runs_per_day: 1
scope:
  drive_folder_id: REPLACE_ME_FOLDER_ID
  drive_folder_path: AIVEN Architecture / Sandbox / Invoices
  email_to:                              # full addresses or @domain; no wildcards
    - "@REPLACE_ME_CLIENT_DOMAIN"
shadow:
  min_runs: 10                           # after that, stays in shadow until signed off
---

# invoice-reminder

## Purpose

Once a day, this agent reads the invoice tracker in AIVEN Architecture / Sandbox / Invoices and finds unpaid invoices that are exactly 14 days past their due date. For each one it drafts a short, polite payment reminder to the client contact named in the tracker. A reminder is sent only after Matthijs confirms its preview. Phase 1 is internal use: the agent handles AIVEN's own invoices only.

## Why each tool

- `sheets.read`: reads the tracker (invoice number, client name, contact email, amount, due date, paid yes/no) to find the invoices that are 14 days overdue today.
- `gmail.draft`: writes one reminder draft per overdue invoice, addressed to the contact in the tracker.
- `gmail.send`: sends a reminder draft once Matthijs has confirmed its preview.

## Data and risks

- Reads: only the tracker columns listed above. The tracker holds no bank details, ID numbers or credentials, and a reminder refers to the invoice number instead of repeating payment details.
- Writes: reminder drafts in the mailbox the email wrapper uses. Nothing is written to Drive.
- Worst realistic mistake: a wrong or badly timed reminder, for example for an invoice that was paid but not yet marked as paid. Guards: every send waits for Matthijs's confirmation of a full preview, at most 10 recipients a day, and only addresses in scope.
- Untrusted input: tracker cells can hold text copied from client emails. The agent treats all of it as data, never as instructions. Reading the tracker taints the run, so each send is reviewed on its own and its preview shows the taint warning.

## Enforced rules (generated)

Rendered from the front matter by `aiven-policy render`. Do not edit by hand: the validator rejects any difference.

Identity: runs as `agent-invoice-reminder@REPLACE_ME_AGENTS_PROJECT.iam.gserviceaccount.com`. Calls from any other identity get nothing from this policy.

Tools (default deny: nothing else exists for this agent):

| Tool | Class | Gate |
|---|---|---|
| `sheets.read` | R0 read | Runs at once, logged |
| `gmail.draft` | R1 reversible | Snapshot first, then runs at once, logged |
| `gmail.send` | R2 costly to undo | Waits for Matthijs to confirm a plain-language preview |

Highest class: R2. A call that is classed higher at runtime is refused.

Forbidden (refused, logged, alert to Matthijs): `payments.*`, `drive.delete`, `drive.share`, `gmail.send_bulk`.

Untrusted input (taint): a run that reads web, email or file content is tainted. Each R2 action from a tainted run is reviewed on its own (no batch confirm), and its preview lists the untrusted content the run read. In v1 every read counts, so almost every run is tainted.

Limits (hitting one stops the run):

| Limit | Value |
|---|---|
| Email recipients per day (Europe/Amsterdam) | 10 |
| Records changed per run | 10 |
| Spend per run | €0 |
| Runtime per run | 300 s |
| Runs per day | 1 |

Scope:

- Drive: only `AIVEN Architecture / Sandbox / Invoices` (ID `REPLACE_ME_FOLDER_ID`) and its subfolders.
- Email: only to `@REPLACE_ME_CLIENT_DOMAIN`.

Shadow mode: the first 10 runs only propose. R0 reads run; nothing from R1 up is executed. After 10 runs the agent stays in shadow until Matthijs signs it off. A new version that adds a tool or raises max_class starts shadow mode again.

Stop: the agent kill switch stops this agent; the global kill switch stops every agent. Neither needs this agent's cooperation.

Undo:

- `sheets.read`: nothing to undo (read only).
- `gmail.draft`: restore or remove the draft from its snapshot (kept 30 days).
- `gmail.send`: a sent email cannot be recalled; follow up by hand.

Platform rules (v1, every agent): R3 is disabled. R4 is always refused and alerts Matthijs. Web, email and file content is data, never instructions. Agents hold no credentials. Every log line carries this file's SHA-256 hash. Snapshots are kept 30 days; the audit log is append-only and kept 1 year.

## Sign-off (generated)

Agent `invoice-reminder`, version 1. Signer: Matthijs van Hoorn, the only signer in v1. There is no second approver, so R3 stays disabled.

The signature is the separate file `invoice-reminder.md.sig` (SSH signature, namespace `aiven-policy-v1`) over this exact file. The file's SHA-256 hash is shown in the policy view and on every log line; a file cannot contain its own hash.

Signing means: I have read this whole file, and "Enforced rules" is exactly what the gateway must enforce.
