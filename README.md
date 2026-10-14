# AIVEN Architecture

AIVEN STUDIOS' safety layer for agents. Every agent action passes through a gateway that enforces a signed policy file per agent, so no agent can do damage that cannot be undone.

Status: Phase 1 (internal only). M1, the policy validator `aiven-policy`, is done and reviewed. M2, the platform infrastructure, is built and reviewed: Terraform for the agents, gateway and control projects, the audit log writer, the budget stop, the alerts and the credit reminder, the config guard and the deploy checks. It is applied (2026-10-14, `bash scripts/m2-oneclick.sh`, runbook `docs/runbooks/m2-apply.md`): budget-stop drills BD-1 and BD-2 passed, and the deploy check shows every line PASS apart from the two NOTEs expected in M2 (no gateway service yet; the audit log lock waits for Matthijs's word). The results are in `m2-result.txt`, the values in `config/platform.yaml` and `infra/terraform/terraform.tfvars`. M3, the gateway core, is planned (`docs/plans/2026-10-13-m3-gateway.md`) and starts when Matthijs says go.

| Path | Contents |
|---|---|
| `docs/plans/2026-10-12-phase1-implementation.md` | Implementation plan: setup steps, credit calendar, milestones M1–M8 |
| `src/aiven/policy/` | The policy validator: `aiven-policy validate`, `render` and `verify` |
| `src/aiven/common/` | The audit log writer, and the config guard `aiven-check-config` |
| `src/aiven/functions/` | The Cloud Run functions of the control project: the budget stop and the credit reminder |
| `src/aiven/deploy_check.py` | The deploy checks `aiven-deploy-check` (gateway-design section 11, drill BD-3) |
| `scripts/m2-oneclick.sh` | M2 in one command on a Mac: tools, logins, values, bootstrap, plan, one question, apply, drills, checks, `m2-result.txt` (helpers in `src/aiven/m2_oneclick.py`) |
| `infra/terraform/` | Terraform for the three projects: policies, APIs, accounts and roles, stores, budgets, functions, alerts |
| `tests/` | The tests: the validator (with the template self-test against spec section 9), the config guard, the functions, the deploy checks and the guards on the Terraform; `infra/terraform/tests/` holds Terraform's own |
| `catalog/` | Action catalog v1 and the argument schema of each grantable Drive and Email action |
| `config/platform.example.yaml` | Example platform values; the real `config/platform.yaml` (no credentials) comes with M2 |
| `docs/decisions/rulings.md` | The decisions taken while building each milestone, where the spec was silent |
| `templates/policy-template.md` | Policy template, filled in for the example agent `invoice-reminder` |
| `docs/validator-spec.md` | What the validator checks: action catalog v1, platform constants, error messages (EN + NL) |
| `docs/gateway-design.md` | Projects, identities, endpoints, data model, class enforcement, kill switch, budgets, billing and credit, model layer |
| `docs/drive-wrapper.md` | Wrap 1: Shared Drive setup, Drive actions, snapshots, taint rules |
| `docs/email-wrapper.md` | Wrap 2: separate agent Workspace; built, but disabled until that Workspace exists |
| `docs/test-plan.md` | Gates, the "absolute" criteria as tests, functional tests, the basic attack set, budget drill |
| `docs/runbooks/rollback.md` | Manual rollback of agent writes |
| `docs/runbooks/budget-stop.md` | Budgets (€10 alert, €25 stop, gross cost), what the stop does, how to restart, the drill |
| `docs/runbooks/m2-apply.md` | Applying M2: the one command, and each step by hand: what the plan must show, the drills, the checks, what to send back |
| `docs/plans/2026-10-13-m3-gateway.md` | M3, the gateway core: the plan, with the four M1 flags and the fallback for an unreachable audit log |

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

Applying M2 (on a Mac; `--dry-run` stops after the plan and changes nothing in Google Cloud):

```sh
bash scripts/m2-oneclick.sh
```

Checking the platform values and the deployment:

```sh
uv run aiven-check-config          # IDs and addresses only in the platform and Terraform values (CI runs it)
uv run aiven-deploy-check all      # after the apply, with your own login; it only reads
```

Optional: the same config guard as a pre-commit hook, so a secret in the platform or Terraform values
is refused before it is committed, not after. CI stays the gate, with or without the hook. Once per
clone (it needs uv on the PATH that Git sees):

```sh
git config core.hooksPath .githooks       # Git then runs .githooks/pre-commit: aiven-check-config --staged
git config --unset core.hooksPath         # turns it off again
```
