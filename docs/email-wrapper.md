# Email wrapper (wrap 2)

Status: draft for review (Phase 1, step 3). Nothing here is built yet. It gets built together with the gateway, but ships **disabled**: it stays off until the agent Workspace exists and the checks in §6 pass.
Classes come from the catalog in `docs/validator-spec.md` §5, and the gateway flow is described in `docs/gateway-design.md`.

## 1. Setup (option a, decided)

1. **Create the agent Workspace.** It is a separate, small Google Workspace on its own domain (for example a second domain AIVEN owns) and holds only agent mailboxes. It is billed as its own Workspace subscription, not by Google Cloud.
2. **Create the agent mailbox,** for example `agents@<agent-domain>`, and set it in the gateway config as `AGENT_MAILBOX`.
3. **Set up delegation.** In that Workspace's Admin console, give the gateway account domain-wide delegation for `https://www.googleapis.com/auth/gmail.compose` only. Add `gmail.readonly` only once a policy needs `gmail.read`.
4. **Restrict delivery.** In the same Admin console, limit the mailbox's mail exchange (Gmail compliance, "Restrict delivery") to `aivenstudios.com`. Check at setup that the Workspace edition offers this setting.
5. **Turn the wrapper on per agent** in the control UI (`wrappers/email.enabled_for`), and only after §6 passes.

No key is stored: the gateway signs the delegation assertion through the IAM Credentials API (`signJwt` on its own account).

What Google then enforces, even if the gateway has a bug:

- The gateway can act only as mailboxes in the agent Workspace, never as an aivenstudios.com mailbox, so never as Matthijs's.
- The agent mailbox can exchange mail only with aivenstudios.com. That covers the Phase 1 recipient rule, and it also keeps outside senders from mailing injected instructions to it.

## 2. Disabled state

- `wrappers/email` in control Firestore holds `enabled_for`, a list of agents, written only by the control UI. An empty list means the wrapper is disabled.
- While an agent isn't on the list, every `gmail.*` call from it is refused with `WRAPPER_DISABLED` before any Gmail API call is made.
- A policy that lists `gmail.*` tools also fails to load for an agent that isn't on the list (`E-TOOL-NOT-LIVE`). The second check is defence in depth.
- Rollout order:
  1. Empty list (now).
  2. Test agents only, for the step 3 email tests.
  3. Real agents.

## 3. Rules for every email action

- **Mailbox pinned.** The gateway delegates only as `AGENT_MAILBOX`. Any other mailbox is refused in code, and Google's tenant boundary backs that up.
- **Recipients.** Every To, Cc and Bcc address must match `scope.email_to`, and in Phase 1 every address must be in aivenstudios.com. A message has at most 3 recipients; more makes it `gmail.send_bulk` (R3).
- **Plain text only.** No attachments in v1. An HTML body is refused.
- **Reading.** `gmail.read` returns plain text. Hidden parts of an HTML mail, such as comments, white text and zero-width characters, are made visible rather than dropped, and the run is always tainted.
- **Content scan.** Every draft is scanned with the patterns in validator-spec §3.8.
- **Own drafts only.** The gateway records each draft ID it creates in Firestore `calls`. `gmail.send` accepts only a draft that this agent created.
- **No raw search strings.** Agents never pass a raw Gmail query. The gateway builds it from fields (`from`, `subject_contains`, `newer_than_days`).

## 4. Actions

| Action | Class | Arguments | Gmail API | Snapshot | Counts |
|---|---|---|---|---|---|
| `gmail.read` | R0 | `message_id`, or search fields | `users.messages.get` / `list` | | Always taints the run |
| `gmail.draft` | R1 | `to`, `cc`, `bcc`, `subject`, `body`, and optionally `draft_id` of a draft this agent created | `users.drafts.create` / `update` | `before.json` (the previous draft when editing), `after.json` (draft ID) | 1 record |
| `gmail.send` | R2 | `draft_id` (a draft this agent created) | `users.drafts.send` after confirm | | Recipients count toward `emails_per_day` when the send is requested |
| `gmail.send_bulk` | R3 | | Never called | | |

## 5. Preview for `gmail.send` (R2)

The preview is in NL and EN. It shows:

- the sender (agent mailbox);
- To, Cc and Bcc;
- the subject;
- the full body as plain text, inside the agent-text block ("data, not instructions");
- the run that wrote the draft;
- the taint banner with its sources.

The preview hash covers the exact draft. If the draft changes after the preview, the send is refused with `STALE_TARGET`.

## 6. Checks before enabling

- The agent Workspace exists, and `AGENT_MAILBOX` lives in it.
- The gateway account's delegation lists only the scopes in §1.
- A probe job (not an agent) sends a message from the agent mailbox to an outside address, and Google refuses it.
- Enabling for test agents comes first. The email tests in the test plan (AT-INJ, AT-PASTE-1) must pass at L3 before any real agent is added to `enabled_for`.

## 7. Undo

- **Drafts:** delete the draft named in `after.json` from the agent mailbox, or restore its text from `before.json`. Matthijs administers the agent Workspace.
- **Sent mail:** it can't be undone. The audit log and the sent folder show what went out.
