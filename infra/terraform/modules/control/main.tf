# aiven-control (gateway-design sections 2, 3 and 5): the service accounts of the control UI and the
# two functions, and the roles on this project. The gateway may only add audit entries and read the
# switches here; its roles on the buckets come with the buckets (Task 2.2, ruling R101). The APIs
# of this project are turned on in the root module, before any module (see main.tf).

locals {
  accounts = {
    "control-ui"      = "The control UI: kill switches, decisions, sign-offs and taint clears; it reads the audit log."
    "budget-stop"     = "The budget stop: unlinks billing from the agents and gateway projects, and writes audit entries."
    "credit-reminder" = "The credit reminder: one audit entry with an alert, before the credit runs out."
  }

  # Written from the account ID, the way Google makes the email (see modules/agents).
  members = {
    for name, account in google_service_account.account :
    name => "serviceAccount:${account.account_id}@${var.project}.iam.gserviceaccount.com"
  }

  project_iam = {
    # The audit log (log `aiven-audit`, Task 2.2) takes entries from the gateway, the control UI and
    # both functions. Reading it is a role on its log bucket, given with the bucket.
    "roles/logging.logWriter gateway" = {
      role   = "roles/logging.logWriter"
      member = var.gateway_member
    }
    "roles/logging.logWriter control-ui" = {
      role   = "roles/logging.logWriter"
      member = local.members["control-ui"]
    }
    "roles/logging.logWriter budget-stop" = {
      role   = "roles/logging.logWriter"
      member = local.members["budget-stop"]
    }
    "roles/logging.logWriter credit-reminder" = {
      role   = "roles/logging.logWriter"
      member = local.members["credit-reminder"]
    }
    # Kill switches, decisions, sign-offs, taint clears and wrapper switches (Firestore `control`):
    # the control UI writes them, and the gateway reads them.
    "roles/datastore.user control-ui" = {
      role   = "roles/datastore.user"
      member = local.members["control-ui"]
    }
    "roles/datastore.viewer gateway" = {
      role   = "roles/datastore.viewer"
      member = var.gateway_member
    }
  }
}

resource "google_service_account" "account" {
  for_each = local.accounts

  project      = var.project
  account_id   = each.key
  display_name = "AIVEN ${each.key}"
  description  = each.value
}

resource "google_project_iam_member" "project" {
  for_each = local.project_iam

  project = var.project
  role    = each.value.role
  member  = each.value.member
}
