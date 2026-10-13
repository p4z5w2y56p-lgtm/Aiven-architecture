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

- The IDs from setup steps S1 to S4: the organisation ID (`gcloud organizations list`), and the
  project IDs of agents, gateway, control and scratch.

## 1. The values (IDs and addresses only)

1. Copy `infra/terraform/terraform.tfvars.example` to `infra/terraform/terraform.tfvars`, and fill in
   the three project IDs and the agent IDs.
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
  - The service accounts: `gateway`, `control-ui`, `budget-stop`, `credit-reminder`, and
    `agent-<id>` for each agent.
  - Ten roles on the projects, plus one `aiplatform.user` per agent; every member is written out
    in full. No role is granted to a person.
- Nowhere in the plan: a `google_service_account_key`, or an audit log bucket with `locked = true`.

`terraform show m2.tfplan` shows the plan again. Stop at anything that is not on this list.

## 5. Apply

```sh
terraform apply m2.tfplan
terraform output service_accounts
```

If the apply stops at an organisation policy with `Permission 'orgpolicy.policies.create' denied`,
part 2 is missing: do it, then plan and apply again. Nothing else is made before the policies.
