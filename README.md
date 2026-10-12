# AIVEN Architecture

AIVEN STUDIOS' safety layer for agents. Every agent action passes through a gateway that enforces a signed policy file per agent, so no agent can do damage that cannot be undone.

Status: Phase 1 (internal only). The specs and the test plan are done. The implementation plan is waiting for review; no code is written yet.

| Path | Contents |
|---|---|
| `docs/plans/2026-10-12-phase1-implementation.md` | Implementation plan: setup steps, credit calendar, milestones M1–M8 |
| `templates/policy-template.md` | Policy template, filled in for the example agent `invoice-reminder` |
| `docs/validator-spec.md` | What the validator checks: action catalog v1, platform constants, error messages (EN + NL) |
| `docs/gateway-design.md` | Projects, identities, endpoints, data model, class enforcement, kill switch, budgets, billing and credit, model layer |
| `docs/drive-wrapper.md` | Wrap 1: Shared Drive setup, Drive actions, snapshots, taint rules |
| `docs/email-wrapper.md` | Wrap 2: separate agent Workspace; built, but disabled until that Workspace exists |
| `docs/test-plan.md` | Gates, the "absolute" criteria as tests, functional tests, the basic attack set, budget drill |
| `docs/runbooks/rollback.md` | Manual rollback of agent writes |
| `docs/runbooks/budget-stop.md` | Budgets (€10 alert, €25 stop, gross cost), what the stop does, how to restart, the drill |

First setup steps (plan section S):

1. Check the project quota: 4 projects are needed.
2. Check the billing currency, and set the budgets in it.
3. Note the credit expiry: the alert fires on 2026-12-20, and the credit ends on 2027-01-04.
