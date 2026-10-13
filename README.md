# AIVEN Architecture

AIVEN STUDIOS' safety layer for agents. Every agent action passes through a gateway that enforces a signed policy file per agent, so no agent can do damage that cannot be undone.

Status: Phase 1 (internal only). Milestone M1 is built: the policy validator `aiven-policy`, with every check of `docs/validator-spec.md` and a failing test for each of its 65 codes. It is waiting for review; M2 (platform infrastructure) starts after that.

| Path | Contents |
|---|---|
| `docs/plans/2026-10-12-phase1-implementation.md` | Implementation plan: setup steps, credit calendar, milestones M1–M8 |
| `src/aiven/policy/` | The policy validator: `aiven-policy validate`, `render` and `verify` |
| `tests/` | The validator's tests, including the template self-test against spec section 9 |
| `catalog/` | Action catalog v1 and the argument schema of each grantable action |
| `config/platform.example.yaml` | Example platform values; the real `config/platform.yaml` (no credentials) comes with M2 |
| `docs/decisions/m1-validator-rulings.md` | The decisions taken while building M1, where the spec was silent |
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

Using the validator (Python 3.12 and uv):

```sh
uv sync
uv run aiven-policy validate policies/invoice-reminder.md   # 0 valid, 1 errors, 2 could not run
uv run aiven-policy render policies/invoice-reminder.md     # rewrites the two generated sections
ssh-keygen -Y sign -f ~/.ssh/aiven_policy_sk -n aiven-policy-v1 policies/invoice-reminder.md
uv run aiven-policy verify policies/invoice-reminder.md \
  --sig policies/invoice-reminder.md.sig --allowed-signers allowed_signers
```
