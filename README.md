# AIVEN Architecture

AIVEN STUDIOS' safety layer for agents. Every agent action passes through a gateway that enforces a signed policy file per agent, so no agent can do damage that cannot be undone.

Status: Phase 1 (internal only), step 3 of 3 is waiting for review. Nothing is built yet; these are the specs and the tests the build must pass.

| Path | Contents |
|---|---|
| `templates/policy-template.md` | Policy template, filled in for the example agent `invoice-reminder` |
| `docs/validator-spec.md` | What the validator checks: action catalog v1, platform constants, error messages (EN + NL) |
| `docs/gateway-design.md` | Projects, identities and scopes, endpoints, data model, class enforcement, kill switch, budgets, free trial |
| `docs/drive-wrapper.md` | Wrap 1: Shared Drive setup, Drive actions, snapshots, taint rules |
| `docs/email-wrapper.md` | Wrap 2: separate agent Workspace; built, but disabled until that Workspace exists |
| `docs/test-plan.md` | Gates, the "absolute" criteria as tests, functional tests, the basic attack set, budget drill |
| `docs/runbooks/rollback.md` | Manual rollback of agent writes |
| `docs/runbooks/budget-stop.md` | Budgets (€10 alert, €25 stop, gross cost), what the stop does, how to restart, the drill |

Before the build starts:

- **Free trial.** Check how many projects the trial billing account can hold (3, plus 1 scratch project for the drill), and its currency.
- **Claude on Vertex AI** needs the paid upgrade. On the trial, agents can only use Gemini.
- **Upgrade** before the trial ends. Otherwise every project, including the audit log, is deleted 30 days later.

Check at setup:

- Shared Drive setting labels.
- The `budget-stop` role.
- Whether the agent Workspace edition supports restricted delivery.
