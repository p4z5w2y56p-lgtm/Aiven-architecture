# Gateway design (Phase 1)

Status: draft for review (Phase 1, step 2). Nothing here is built yet.
It builds on `docs/validator-spec.md`, which defines the policy format, the action catalog (§5) and the gateway's reading order (§4). The Drive specifics are in `docs/drive-wrapper.md`, and the procedures are in `docs/runbooks/`.

## 1. Decisions this design follows

| Decision | Source |
|---|---|
| Phase 1 is internal only. Only Matthijs signs. R3 is disabled. | Locked |
| Three Google Cloud projects: agents, gateway, control | Your go |
| Google Workspace. The Sandbox is a Shared Drive, and the gateway service account is a Contributor on it. | Your go |
| Agents run on Google Cloud, with one identity each. | Your go |
| Email goes through a dedicated agent mailbox, never Matthijs's personal mailbox. Phase 1 email goes only to @aivenstudios.com. | Your go |
| The agent mailbox lives in a separate small Workspace (option a). The email wrapper is built but stays disabled until that Workspace exists. | Your go (step 3) |
| `untrusted_input: strict` is the v1 default. | Your go |
| Budget alert at €10/month and hard stop at €25/month, both on gross cost (before credits). The stop may take the gateway down. | Your go (step 3) |
| Cost per run is logged during shadow mode. | Your go (step 3) |
| The billing account is paid since 2026-10-06, with €252.56 promotional credit valid until 2027-01-04 (section 14). | Your correction (M1 go) |
| Claude refusals end the run and are logged. There is no fallback model. | Your go (M1) |

## 2. Projects

| Project | Holds | Writes come from |
|---|---|---|
| `aiven-agents` | One Cloud Run job per agent, each with its own service account | Deploys only |
| `aiven-gateway` | The gateway (Cloud Run) and its working database (Firestore `gateway`) | The gateway account |
| `aiven-control` | Audit log, kill switches, R2 decisions, shadow sign-offs, signed policies and catalog, snapshot store, budget stop, alerts, control UI | Matthijs and the control UI. The gateway may only add audit entries and snapshot objects. |

- These names are used throughout the docs. Project IDs are globally unique, so the real IDs are set at deploy. All regional resources live in `europe-west4` (Netherlands).
- The agent side has no write access to control.
- Billing stops (section 9) hit agents and gateway only. Google may delete resources in a stopped project, so the snapshot store lives in control next to the audit log. The gateway can add snapshots there but can never read, change or delete them.
- Nothing irreplaceable lives in agents or gateway. Both can be rebuilt from Git.

## 3. Identities and scopes

| Identity | Can | Cannot |
|---|---|---|
| `agent-<id>@aiven-agents`, one per agent | Call the gateway (`run.invoker` on the gateway service). Call its model through Vertex AI (`aiplatform.user`). | Reach any Workspace data: the Drive, Sheets and Gmail APIs are disabled in `aiven-agents`, and no file is ever shared with an agent. Touch gateway or control. Hold keys. |
| `gateway@aiven-gateway` | Use the Drive and Sheets APIs with OAuth scope `drive`, as Contributor of the Sandbox drive only. Use Gmail as the agent mailbox only, through delegation in the separate agent Workspace (`signJwt` on its own account, no key; email-wrapper §1). Read and write its own Firestore. In control: write audit entries (`logging.logWriter`), create snapshot objects (`storage.objectCreator` on the snapshot bucket), read policies (`storage.objectViewer` on the policy bucket), and read kill switches, decisions and sign-offs (`datastore.viewer`). | Read, overwrite or delete snapshots. Read or delete the audit log. Change kill switches, decisions, sign-offs or policies. Trash, move or share Drive files (Google blocks this, see the Drive wrapper). Use Drive files outside the Sandbox (`driveId` check on every call). |
| `control-ui@aiven-control` | Serve the control UI behind IAP, to Matthijs only. Write kill switches, decisions, sign-offs, wrapper switches and taint clears. Read the audit log, the policies and the snapshot list. Read the gateway's working database (`datastore.viewer` on `aiven-gateway`) for pending confirms, proposals and runs. Call the gateway's control endpoints. | Drive, Gmail, billing, and writing the gateway's database |
| `budget-stop@aiven-control` | Read and unlink the billing of `aiven-agents` and `aiven-gateway` (`billing.projectManager` and `browser` on each). Write audit entries. | Anything else |
| `function-builder@aiven-control` | Build the functions `budget-stop` and `credit-reminder`: read their source, write their image and build logs (ruling R134). | Anything else |
| Matthijs | Owns the three projects. Is Manager of the Sandbox drive. Signs policies with the hardware key, publishes them to the policy bucket, and restores snapshots by hand. | |

- **Organisation policies** for all three projects: no service-account keys (`iam.disableServiceAccountKeyCreation`), and no automatic Editor role for default service accounts (`iam.automaticIamGrantsForDefaultServiceAccounts`).
- **Why the `drive` scope.** Google has no folder-level or drive-level OAuth scope, and `drive.file` can't see files the gateway didn't create. The real limit is membership: the gateway account belongs to the Sandbox drive only, and every call checks the file's `driveId`.
- **Models** are reached through Vertex AI with IAM, because a model API key would be a stored credential.
- **`budget-stop` roles.** It gets `billing.projectManager` and `browser` on the two projects, which is what Google's guide to disabling billing names. `billing.projectManager` unlinks billing. `browser` gives `resourcemanager.projects.get`, which reading a project's billing needs first. Verified at setup: the first drill, with `billing.projectManager` alone, failed on that read (ruling R167). No role on the billing account is needed.
- **Email** (wrap 2) is decided as option (a), and the wrapper ships disabled. See section 12 and `docs/email-wrapper.md`.

## 4. Endpoints

Every call is HTTPS to the gateway's Cloud Run URL, carrying a Google-signed ID token (audience = the gateway URL) minted from the caller's attached service account. Cloud Run rejects callers that lack `run.invoker`. The gateway then maps the token's email either to a policy's `principal` (agent API) or to `control-ui` (control API). Requests are JSON only, and unknown fields are refused.

### Agent API

| Method and path | Does | Returns |
|---|---|---|
| `GET /v1/me` | Shows this agent's active policy | Agent, policy version and hash, catalog hash, tools with class, limits, shadow, kill switch state |
| `POST /v1/runs` | Starts a run. Checks the kill switches, a verified policy and `runs_per_day`. | `run_id`, `deadline`, `shadow`, `policy_hash` |
| `POST /v1/runs/{run_id}/calls` | Requests one action: `{action, args, request_id}` | `call_id`, `outcome` (`executed`, `proposed`, `queued`, `refused`), `class`, `reason`, `result`, `confirm_id`, `tainted` |
| `GET /v1/runs/{run_id}/calls/{call_id}` | Gives the status of a call, for example a queued R2 | Outcome, status, result |
| `POST /v1/runs/{run_id}:end` | Ends the run. The body reports model usage and why the run ended: `{usage: [{model, input_tokens, output_tokens}], end_reason}`, where `end_reason` is `done`, `model_refusal`, `max_turns` or `error`. | Calls by outcome, records used, taint, cost estimate |

`request_id` is unique within a run. A retry with the same `request_id` gets the stored answer, so an action never executes twice.

### Control API (caller must be `control-ui`)

| Method and path | Does |
|---|---|
| `POST /v1/control/confirms/{confirm_id}:apply` | Reads the decision from control Firestore, then executes or closes the R2 request |
| `POST /v1/control/policies:reload` | Reloads policies and catalog now. Otherwise they are re-read when the last load is more than 60 s old. |

### Outcomes and errors

Policy decisions come back as HTTP 200 with an `outcome`. HTTP errors are only for these cases:

- 400: malformed request.
- 401 or 403: identity.
- 409: the run is closed.
- 503: failing closed because control is unreachable.

Reason codes the agent can see: `KILL_SWITCH`, `NO_POLICY`, `FORBIDDEN`, `RESERVED_R4`, `NOT_GRANTED`, `R3_DISABLED`, `ABOVE_MAX_CLASS`, `OUT_OF_SCOPE`, `LIMIT_RUNS`, `LIMIT_RUNTIME`, `LIMIT_RECORDS`, `LIMIT_EMAILS`, `LIMIT_SPEND`, `CONTENT_BLOCKED`, `SNAPSHOT_FAILED`, `STALE_TARGET`, `BAD_ARGS`, `RUN_CLOSED`, `TOO_MANY_REFUSALS`, `CONTROL_UNREACHABLE`, `WRAPPER_DISABLED`.

## 5. Data model

### Control project (`aiven-control`)

| Store | Contents | Written by | Read by |
|---|---|---|---|
| Firestore `control`: `killswitch/global`, `killswitch_agents/{agent}` | `{on, by, at, reason}` | Control UI | Gateway, control UI |
| Firestore `control`: `decisions/{confirm_id}` | `{decision: approve or reject, preview_sha256, by, at}` | Control UI | Gateway |
| Firestore `control`: `signoffs/{agent}` | `{tools, max_class, policy_hash, shadow_runs_seen, by, at}` | Control UI | Gateway |
| Firestore `control`: `taint_clears/{file_id}` | `{revision, by, at}`: clears the taint label of one file version | Control UI | Gateway |
| Firestore `control`: `wrappers/{name}` | `{enabled_for: [agents], by, at}`. An empty list means the wrapper is off. Email starts empty. | Control UI | Gateway |
| Bucket `<control-project>-policies` (versioned) | `policies/<agent>.md` + `.sig`, `catalog/catalog-v1.yaml` + `.sig` (the machine form of validator-spec §5), `allowed_signers`, `pricing/models.yaml` (EUR per million tokens, for cost estimates) | Matthijs | Gateway, control UI |
| Bucket `<control-project>-snapshots` (30-day retention, then deleted) | Per run: `manifest.json`. Per call: `before.json`, `before.bin` or `before-cells.json`, `after.json` | Gateway (create only) | Matthijs, control UI (list) |
| Log bucket `aiven-audit` (365 days, retention locked) | One entry per event (see below) | Gateway, control UI, budget stop (write only) | Matthijs, control UI |

Bucket names are global, like project IDs, so the buckets are named after the control project's ID (ruling R125).

### Gateway project (`aiven-gateway`), Firestore `gateway`

This is working state: if it is lost, it is rebuilt empty.

| Collection | Contents |
|---|---|
| `runs/{run_id}` | Agent, policy and catalog hash, start, deadline, status (`open`, `ended`, or `stopped` with a reason), shadow, tainted, taint sources, records used, refusals |
| `calls/{call_id}` | Run, `request_id`, action, base and effective class, args hash, outcome, reason, snapshot path, `confirm_id`, approver, times. No content. |
| `confirms/{confirm_id}` | Run, call, action, args, preview (EN and NL), preview hash, taint sources, status (`pending`, `approved`, `rejected`, `expired`, `executed`, `failed`), expiry. Args and previews are erased 7 days after the confirm closes. |
| `proposals/{call_id}` | Shadow-mode proposals: preview (EN and NL), for the shadow review. Erased 30 days after sign-off. |
| `counters/{agent}_{date}` | Runs and email recipients for the day (Europe/Amsterdam) |
| `shadow/{agent}` | Shadow runs done, and the capability (tools, `max_class`) they cover |
| `active/{agent}` | Active policy version and hash, used to refuse older versions |

Runs and calls expire after 90 days (Firestore TTL on their field `expire_at`, which the gateway sets; ruling R106). The audit log is the permanent record.

### Audit entry

Each entry is a Cloud Logging `jsonPayload` in log `aiven-audit` in control:

```json
{
  "event": "call",
  "ts": "2026-10-12T09:15:02.123Z",
  "agent": "invoice-reminder",
  "actor": "agent-invoice-reminder@<agents-project>.iam.gserviceaccount.com",
  "run_id": "r_01JA...",
  "call_id": "c_01JA...",
  "action": "gmail.draft",
  "class": "R1",
  "outcome": "executed",
  "reason": null,
  "approver": "policy",
  "policy_hash": "sha256:...",
  "catalog_hash": "sha256:...",
  "tainted": false,
  "taint_sources": [],
  "snapshot": "gs://<control-project>-snapshots/invoice-reminder/r_01JA.../c_01JA.../",
  "confirm_id": null,
  "args_sha256": "...",
  "alert": false
}
```

- `event` is one of `run_start`, `call_start`, `call`, `decision`, `run_end`, `policy_load`, `control` (kill switch, sign-off, taint clear, wrapper switch, rollback or restart record) and `budget_stop`.
- `run_end` adds `usage` (model, input and output tokens, as reported by the agent), `cost_estimate_eur` and `end_reason`. A model refusal is logged as `end_reason: model_refusal`.
- `approver` is `policy` for R0 or R1 under the signed policy, the confirming person's address for R2, and `none` for refused or proposed calls.
- Entries hold IDs and hashes only, never file content, file names or email text. That keeps the log free of personal data, bank details and credentials.

## 6. How each class is enforced

Each call goes through the gates in the order of validator-spec §4, and the first match decides. The table shows what the gateway does at each gate, and what still holds if the gateway code is wrong.

| Gate | Gateway does | Backstop outside the gateway | Logged as |
|---|---|---|---|
| Kill switch | Reads both switches from control on every call, and before every confirmed R2. If the read fails, it refuses. | Remove the gateway from the Sandbox drive (section 8) | refused, `KILL_SWITCH` |
| Identity | The token email must be the `principal` of a verified policy | The Cloud Run invoker list | refused, alert |
| R4 and forbidden | Matches reserved namespaces and `forbidden`, after classifying (so a smuggled trash counts as `drive.delete`) | No identity in gateway or agents can change policies, logs, kill switches or IAM | refused, alert |
| Default deny | The action must be in `tools`. No raw API pass-through. | Agents have no Workspace access of their own | refused |
| R3 | No code path executes an R3 action | Drive: a Contributor can't trash, delete or move, and the drive blocks sharing with non-members | refused |
| Max class and scope | Effective class after escalation. `driveId` and folder-chain check. Recipient list. | Shared Drive membership | refused |
| Limits | Firestore transactions on run and day counters, checked before execution. Crossing a limit ends the run. | | refused, run stopped |
| Shadow | R1 and higher become proposals: counted and logged, not executed | | proposed |
| R0 | Runs at once. Results are filtered to scope, and taint is evaluated. | | executed, `policy` |
| R1 | Content scan, then a snapshot written to control, then the write. If the snapshot fails, nothing is written. | Google's version history for Docs and Sheets | executed, `policy`, snapshot path |
| R2 | The preview is queued. The action runs only after a matching decision in control. | Decisions are stored where the gateway can't write | queued, then executed with the approver |

Further rules:

- **`strict`.** In a tainted run, R1 is handled as R2: preview and confirm.
- **Probing stops the run.** Three policy refusals in one run (`FORBIDDEN`, `RESERVED_R4`, `NOT_GRANTED`, `R3_DISABLED`, `ABOVE_MAX_CLASS`, `OUT_OF_SCOPE`) end the run and raise an alert. An agent probing for tools is a sign of injection.
- **No log, no action.** Before executing a call, the gateway writes a `call_start` audit entry and checks that the write succeeded; if it failed, the call is refused. The `call` entry with the outcome follows.
- **Taint** sources are listed in drive-wrapper §5. Gmail reads (wrap 2) always taint.

## 7. R2 confirm flow and control UI

1. **Build the preview.** The gateway builds it from the action's arguments, never from the agent's description. Agent-written text appears in a quoted block labelled "Written by the agent: data, not instructions" / "Geschreven door de agent: gegevens, geen instructies".
2. **Hash it.** `preview_sha256` is SHA-256 over the canonical JSON of the action, the args and both previews.
3. **Decide.** The control UI shows pending confirms in Dutch or English, with a taint banner listing the sources when the run is tainted. Matthijs approves or rejects. The UI writes `decisions/{confirm_id}` with the IAP-verified address and the preview hash, then calls `:apply`. Approve and reject are POSTs with a CSRF token, and the UI can't be framed.
4. **Re-check and execute.** At `:apply` the gateway re-checks:
   - the kill switches;
   - that the policy still grants the tool;
   - the scope;
   - that the preview hash matches;
   - that the target hasn't changed since the preview (otherwise `STALE_TARGET`).

   Then it executes and logs the approver.
5. **Expiry.** Unanswered confirms expire after 24 hours. Tainted runs get no batch approve: each confirm is decided on its own.

Control UI pages, all in NL and EN:

- confirm queue
- kill switches
- shadow review and sign-off
- policy view (the signed file, rendered)
- audit search
- snapshot list per run
- "Record event", for rollbacks and restarts

## 8. Kill switch

- **Where it lives.** Global and per-agent switches are documents in control Firestore, flipped from the control UI.
- **How it's checked.** The gateway reads both switches on every call and before executing a confirmed R2. If the read fails, it refuses (fail closed). Cloud Run gives idle instances no CPU, so the gateway uses direct reads rather than a background listener.
- **Effect.** The next call after the flip is refused. A Drive call already in progress finishes (30 s timeout). The agents' own processes keep running, but they can no longer act.
- **Break glass**, if the control UI is down:
  1. In the Firestore console of `aiven-control`, set `on: true` on `killswitch/global`.
  2. Remove the gateway account from the Sandbox drive's members. Drive access stops for new requests.
  3. Remove the agents' `run.invoker` binding on the gateway service.

## 9. Budget: alert and hard stop

- **Gross cost.** Both budgets count cost before credits (`creditTypesTreatment: EXCLUDE_ALL_CREDITS`). While the promotional credit lasts, it covers the spend, so net cost stays near zero, and budgets that subtract credits would never fire (section 14).
- **Alert.** Budget `aiven-alert` is €10/month across the three projects. It sends email at 50 %, 90 % and 100 % of actual cost.
- **Hard stop.** Budget `aiven-stop` is €25/month across the same three projects. At 100 % it publishes to Pub/Sub topic `budget-stop` in control. The `budget-stop` function then:
  - acts only on notifications from `aiven-stop` where `costAmount >= budgetAmount`;
  - unlinks billing from `aiven-agents` and `aiven-gateway` (the list is configurable for drills);
  - writes a `budget_stop` audit entry and raises an alert;
  - is idempotent;
  - logs every notification it receives, so the wiring can be checked without a stop.
- **Control keeps running.** The control project stays billed, so the audit log, snapshots, kill switch and control UI keep working during an incident.
- **What a stop does.** Every billable service in agents and gateway stops. Google warns that some resources may be deleted and not be recoverable, which is why both projects must be rebuildable from Git.
- **It isn't a precise cap.** Cost data and notifications arrive hours late, so spend can pass €25 before the stop fires. Google's guide says the same.
- **Cost per run.** When an agent ends a run, it reports its model usage. The gateway turns that into an estimate using `pricing/models.yaml`, logs it on `run_end`, and the shadow review shows it for each run. The figure is the agent's own report: good enough for budgeting, not for security. Reconcile it monthly against the billing report (test CR-2).
- **Restarting** follows `docs/runbooks/budget-stop.md`.

## 10. Alerts

Log-based alert policies in control send Matthijs an email for every audit entry with `alert: true`, and for a function's own log line with `alert: true`, which it writes when the audit log did not take its entry (ruling R130). That covers:

- R4 or forbidden attempts
- unknown callers
- three-refusal stops
- policy load failures
- snapshot failures
- fail-closed refusals (control unreachable), at most one email per 5 minutes (ruling R165)
- the budget stop

## 11. Deployment checks (what no policy file can enforce)

These are checked at every deploy, and again in step 3:

- No user-managed service account keys exist in any project.
- The Drive, Sheets and Gmail APIs are disabled in `aiven-agents`. Agent accounts hold only `run.invoker` on the gateway and `aiplatform.user`.
- The Sandbox drive's members are exactly Matthijs (Manager) and the gateway account (Contributor), and sharing with non-members is off.
- Agents run without built-in web, search or file tools, and with model grounding off: their only tool is the gateway. Limiting egress from `aiven-agents` to Google APIs is recommended.
- The control UI admits only Matthijs through IAP.
- The audit log bucket is locked at 365 days, and the snapshot bucket keeps 30 days.

## 12. Email (wrap 2): decided

The choice is option (a): the agent mailbox lives in a separate small Workspace. Delegation there can reach only agent mailboxes, so Google itself enforces "never my personal mailbox", and restricting delivery to aivenstudios.com enforces the Phase 1 recipient rule. The wrapper is built with the gateway but stays disabled (`wrappers/email.enabled_for` is empty) until that Workspace exists and gate G2 in the test plan passes. Details are in `docs/email-wrapper.md`.

## 13. Gateway constants

| Constant | Value |
|---|---|
| Region | `europe-west4` |
| Cloud Run instances | min 0, max 2 |
| Policy refresh | When the last load is more than 60 s old, or on `policies:reload` |
| Confirm expiry | 24 h |
| Policy refusals per run before stop | 3 |
| Drive call timeout | 30 s |
| Working data TTL (runs, calls) | 90 days |
| Confirm args and previews erased | 7 days after closing |

## 14. Billing account and credit

The billing account is paid: it was upgraded from the free trial on 2026-10-06. The remaining promotional credit was €252.56, valid until 2027-01-04.

- **Budgets count gross cost.** While the credit lasts it pays for usage, so net cost stays near zero. Budgets that subtract credits, which is Google's default, would never fire. Both budgets therefore exclude all credits (section 9). After the credit ends nothing changes: gross cost is then also what is billed.
- **No trial restrictions remain.** Third-party models on Vertex AI (Claude) and quota increases are available.
- **Credit reminder.** On 2026-12-20 an alert email says the credit is about to run out (plan Task 2.4), and a calendar entry backs it up.
- **Check first** (setup steps S1–S3 in `docs/plans/2026-10-12-phase1-implementation.md`):
  - The project quota. The design needs 4 projects: 3, plus 1 scratch project for the budget drill.
  - The billing currency. The budgets use it: €10/€25, or $11/$27.
- **Not covered by Google Cloud billing:** the agent Workspace (email option a) is its own Workspace subscription.

## 15. Agent runtime and model layer

Agents run as Cloud Run jobs in `aiven-agents`, using the `aiven.agent` runtime. The gateway is their only tool. The model is behind a provider-neutral interface, so moving from Gemini to Claude on Vertex AI changes configuration only, never code.

- **One interface.** `ModelClient.start(system, tools)` and `send(...)` work with neutral tool specs, tool calls, tool results and usage. Tool specs are built from the same JSON Schemas the gateway validates against (`catalog/schemas/`), and they are fixed for the whole run.
- **Two adapters.**
  - Gemini on Vertex AI (`google-genai`, `vertexai=True`), the Phase 1 default.
  - Claude on Vertex AI (`anthropic[vertex]`, `AnthropicVertex`), available now that the account is paid.

  Both use the agent's own service account, so no API key is involved.
- **Append-only history.** Each adapter keeps the provider's own reply content and sends it back unchanged on the next turn. Claude's thinking blocks and Gemini's thought signatures must be returned exactly as received. Switching provider happens between runs, never inside one.
- **Gateway tools only.** Adapters send function or tool definitions only: no Google Search grounding, no web search, no other built-in tools (deployment check, AT-BYP-7).
- **The switch** is a change in `agents/<id>/runtime.yaml`:
  - `provider` from `vertex-gemini` to `vertex-claude`;
  - `model_id`, the Claude model chosen in setup step S7;
  - `region`, for example `eu` to keep processing in the EU.

  It also needs a price entry in `pricing/models.yaml`, and the model enabled in Model Garden. A conformance test runs one scripted conversation through both adapters and expects the same gateway calls.
- **Claude specifics** handled inside the adapter:
  - Forced tool choice isn't allowed on current models, so the adapter uses `auto`.
  - Thinking stays at the model default.
  - A refusal ends the run and is logged (`end_reason: model_refusal`). It is never retried on another model.
  - Usage is summed over every attempt, so cost per run stays right.
