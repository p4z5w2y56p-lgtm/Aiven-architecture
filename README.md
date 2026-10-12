# AIVEN Architecture

AIVEN STUDIOS' safety layer for agents. Every agent action passes through a gateway that enforces a signed policy file per agent, so no agent can do damage that cannot be undone.

Status: Phase 1 (internal only), step 2 of 3 is waiting for review. Nothing is built yet; these are the specs to build from.

| Path | Contents |
|---|---|
| `templates/policy-template.md` | Policy template, filled in for the example agent `invoice-reminder` |
| `docs/validator-spec.md` | What the validator checks: action catalog v1, platform constants, error messages (EN + NL) |
| `docs/gateway-design.md` | Projects, identities and scopes, endpoints, data model, how each class is enforced, kill switch, budget stop |
| `docs/drive-wrapper.md` | Wrap 1: Shared Drive setup, Drive actions, snapshots, taint rules |
| `docs/runbooks/rollback.md` | Manual rollback of agent writes |
| `docs/runbooks/budget-stop.md` | What the budget hard stop does and how to restart |

Next, after "go": step 3, the test plan and the basic attack set.

Open decisions:

- **Email access (wrap 2).** Option (a): a separate small Workspace for the agent mailbox, recommended. Option (b): delegation inside aivenstudios.com. See gateway-design §12.
- **Model costs.** Model use counts toward the €10 hard stop. Measure cost per run during shadow mode.

Check at setup:

- Shared Drive setting labels.
- The `budget-stop` role.
- Whether domain-wide delegation can be limited to one mailbox.
