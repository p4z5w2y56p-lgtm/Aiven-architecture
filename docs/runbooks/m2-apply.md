# Runbook: applying M2 (platform infrastructure)

These are Matthijs's steps. Agents never apply Terraform and hold no credentials (ruling R97):
Terraform runs on your machine, with your own login. CI only checks the code (format, validate,
`terraform test` on a mock provider). Work through the parts in order. Each one says what to check
before you go on.

## 0. What you need

- The gcloud CLI, logged in with your AIVEN account.
- Terraform **1.16.4** exactly: `infra/terraform/versions.tf` refuses any other version. Download the
  zip for your machine from `https://releases.hashicorp.com/terraform/1.16.4/` and check it before
  you unpack it:

  | Machine | File | SHA-256 |
  |---|---|---|
  | Mac, Apple silicon | `terraform_1.16.4_darwin_arm64.zip` | `42cfdf97ad722f79085fe2279b06d4b8680172de3534b22eeddd9a0fbbe7b8f1` |
  | Mac, Intel | `terraform_1.16.4_darwin_amd64.zip` | `2ee4b62064086e4b24b0d6cf2e61718fbaf0556feba990f708a5e32557554b3b` |
  | Linux | `terraform_1.16.4_linux_amd64.zip` | `dc94af0eef1147718ad7c8daea792ed199e3e0492eec180d0adafa2a65a879df` |
  | Windows | `terraform_1.16.4_windows_amd64.zip` | `5c736ed6b0f13e98bc5029fe159574cca33634c3477466c56442c28b513a7054` |

  ```sh
  shasum -a 256 terraform_1.16.4_darwin_arm64.zip   # must print the hash in the table
  ```

- The IDs from setup steps S1 to S4: the organisation ID (`gcloud organizations list`), the
  billing account ID (`gcloud billing accounts list`) and its currency, and the project IDs of
  agents, gateway, control and scratch.
- Billing Account Administrator on the billing account, for the budgets.

## 1. The values (IDs and addresses only)

1. Copy `infra/terraform/terraform.tfvars.example` to `infra/terraform/terraform.tfvars`, and fill in
   the four project IDs, the billing account ID, the currency and the two budgets (10 and 25 in
   EUR, 11 and 27 in USD), the address for the alerts (an @aivenstudios.com one), the two credit
   dates (2026-12-20 and 2027-01-04), and the agent IDs.
2. Copy `config/platform.example.yaml` to `config/platform.yaml`, and fill in the agents project,
   your address as the trusted author, and the gateway's account
   (`gateway@<gateway-project>.iam.gserviceaccount.com`).
3. Commit both files. They hold IDs and addresses only. CI refuses anything else in them
   (`aiven-check-config`). If it ever refuses a secret, that secret is already in the Git history:
   revoke it, don't just delete it.

Or send the IDs, and the files come back filled in for your review.

## 2. Organization Policy Administrator (once)

The two organisation policies (no service account keys, no Editor role for default service
accounts) are set on each project, and that needs this role on the organisation (ruling R104):

```sh
gcloud organizations add-iam-policy-binding <ORG_ID> \
  --member=user:<you>@aivenstudios.com --role=roles/orgpolicy.policyAdmin
```

If this is refused, grant the role as a Workspace super admin in the Console: IAM, with the
organisation selected.

## 3. Bootstrap the control project (once)

Terraform bills its calls to the control project, and keeps its state in a bucket there (ruling
R100). Both have to exist before the first `terraform init`:

```sh
CONTROL=<control-project-id>
gcloud services enable serviceusage.googleapis.com cloudresourcemanager.googleapis.com \
  orgpolicy.googleapis.com storage.googleapis.com --project="$CONTROL"
gcloud storage buckets create "gs://$CONTROL-tfstate" --project="$CONTROL" \
  --location=europe-west4 --uniform-bucket-level-access --public-access-prevention
gcloud storage buckets update "gs://$CONTROL-tfstate" --versioning
```

Check: `gcloud storage buckets describe "gs://$CONTROL-tfstate" --format="value(location,versioning_enabled)"`
prints `EUROPE-WEST4` and `True`.

## 4. Plan

```sh
CONTROL=<control-project-id>
gcloud auth application-default login     # your own login, for Terraform; no key
cd infra/terraform
terraform init -backend-config="bucket=$CONTROL-tfstate" -backend-config="prefix=aiven"
terraform plan -out=m2.tfplan
```

What the plan must show, part by part:

- **Foundation (Task 2.1)**
  - Six organisation policies, two per project: `iam.disableServiceAccountKeyCreation` and
    `iam.automaticIamGrantsForDefaultServiceAccounts`, each `enforce = "TRUE"`.
  - The APIs: 17 in control, 5 in agents, 7 in gateway. Drive, Sheets and Gmail are never among
    those of agents.
  - The service accounts: `gateway`, `control-ui`, `budget-stop`, `credit-reminder`,
    `function-builder` (it builds the two functions), and `agent-<id>` for each agent.
  - Twelve roles on the projects, plus one `aiplatform.user` per agent; every member is written
    out in full. No role is granted to a person.
- **Stores (Task 2.2)**
  - Buckets `<control>-policies` (versioned) and `<control>-snapshots` (retention 30 days, not
    locked; deleted at 30 days). Both in europe-west4, uniform access, public access prevented.
    Bucket names are global, so they carry the project ID instead of `aiven-control-*`.
  - Log bucket `aiven-audit`: 365 days, `locked = false`. A sink routes log `aiven-audit` there,
    and an exclusion keeps it out of `_Default`.
  - Firestore `control` (control) and `gateway` (gateway): native mode, europe-west4, delete
    protection on. Runs and calls expire by their field `expire_at`.
  - Roles on the stores: the gateway reads the policies and may only add snapshots; the control
    UI reads the policies and the audit log, and lists the snapshots.
- **Budgets and the budget stop (Task 2.3)**
  - Budgets `aiven-alert` (10) and `aiven-stop` (25) in your currency, both
    `EXCLUDE_ALL_CREDITS`, per month, over the agents, gateway and control projects. The alert has
    thresholds 0.5, 0.9 and 1.0; the stop has 1.0 and topic `budget-stop`.
  - Topic `budget-stop`, which `billing-budget-alert@system.gserviceaccount.com` may publish to.
  - Bucket `<control>-functions` with the zip of the function, named by its SHA-256.
  - Function `budget-stop`: Python 3.12, europe-west4, internal only, one instance, as
    `budget-stop`, with `STOP_PROJECTS` the agents and gateway projects and `STOP_ENABLED=true`;
    Eventarc delivers the topic to it, again after a failure. `budget-stop` may invoke it, and has
    Project Billing Manager on the agents and gateway projects.
- **Alerts and the credit reminder (Task 2.4)**
  - An email channel to your alert address (Monitoring, then Alerting, then notification
    channels, shows it).
  - Alert policy "an audit entry with an alert": every entry of log `aiven-audit` with
    `jsonPayload.alert=true`, and the functions' own log lines with `alert: true`.
  - Alert policy "the gateway fails closed for more than a minute", on the log-based metric
    `aiven/control-unreachable` (refusals with reason `CONTROL_UNREACHABLE` in the audit log).
  - Function `credit-reminder` (as `credit-reminder`, internal only, `CREDIT_EXPIRY=2027-01-04`),
    and Cloud Scheduler job `credit-reminder` at `0 9 20 12 *`, Europe/Amsterdam, with an OIDC
    token of `credit-reminder`. Only `credit-reminder` may invoke the function.
- Nowhere in the plan: a `google_service_account_key`, or `locked = true` / `is_locked = true`.

`terraform show m2.tfplan` shows the plan again. Stop at anything that is not on this list.

## 5. Apply

```sh
terraform apply m2.tfplan
terraform output service_accounts
```

If the apply stops at an organisation policy with `Permission 'orgpolicy.policies.create' denied`,
part 2 is missing: do it, then plan and apply again. Nothing else is made before the policies.

## 6. After the apply: the drills

1. **The alert path.** Run the credit reminder by hand:
   `gcloud scheduler jobs run credit-reminder --location=europe-west4 --project=<control-project>`.
   Within a few minutes the email "Google Cloud credit expires on 2027-01-04 ..." arrives. That
   proves the function, the audit log, the alert policy and the email channel in one go. (After
   2027-01-04 a run writes nothing; the yearly schedule then stays silent.)
2. **BD-1 and BD-2**, the budget stop, on the scratch project only: runbook `budget-stop.md`,
   section Drill. Write down the time from publishing to the unlink, for the report.

## Later, and only when you confirm it: the audit log lock

Locking `aiven-audit` fixes its 365-day retention for good: it cannot be undone, and the bucket can
then only be deleted when it is empty. It is not part of M2. When you confirm it in the
conversation, it comes as one commit that sets `locked = true` and lifts the guard that refuses it
(ruling R105); you then plan and apply that change on its own.
