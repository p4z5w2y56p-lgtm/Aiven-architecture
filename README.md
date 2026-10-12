# AIVEN Architecture

AIVEN STUDIOS' safety layer for agents. Every agent action passes through a gateway that enforces a signed policy file per agent, so no agent can do damage that cannot be undone.

Status: Phase 1 (internal only), step 1 of 3. This step covers the policy template and the validator spec, and it is waiting for review.

| Path | Contents |
|---|---|
| `templates/policy-template.md` | Policy template, filled in for the example agent `invoice-reminder` |
| `docs/validator-spec.md` | What the validator checks: action catalog v1, platform constants, error messages (EN + NL) |

Next steps, after "go":

- **Step 2:** gateway design (endpoints, data model, class enforcement, service account scopes), then the Drive wrapper.
- **Step 3:** test plan and the basic attack set.

Open before step 2:

- Is AIVEN on Google Workspace? It is needed for a Shared Drive Sandbox and for Gmail access.
- Where do Phase 1 agents run? The template assumes one service account per agent on Google Cloud.
- Which mailbox does the email wrapper use?
- Billing: is an alert at EUR 10/month enough, or is a hard stop needed?
