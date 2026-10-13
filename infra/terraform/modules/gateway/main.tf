# aiven-gateway (gateway-design sections 2 and 3): the gateway's service account, and the APIs of the
# gateway and its wrappers. Its roles in control are granted there (modules/control); the ones on a
# bucket or a service come with that resource (ruling R101).

locals {
  apis = [
    "artifactregistry.googleapis.com", # the gateway's image (M3)
    "drive.googleapis.com",            # the Drive wrapper, as Contributor of the Sandbox drive (M4)
    "firestore.googleapis.com",        # the working database `gateway` (Task 2.2)
    "iam.googleapis.com",
    "logging.googleapis.com",
    "run.googleapis.com",    # the gateway service (M3)
    "sheets.googleapis.com", # the Drive wrapper's sheet actions (M4)
  ]

  # Written from the account ID, the way Google makes the email (see modules/agents).
  members = {
    gateway = "serviceAccount:${google_service_account.gateway.account_id}@${var.project}.iam.gserviceaccount.com"
  }

  project_iam = {
    # Its own working database, to read and write.
    "roles/datastore.user gateway" = {
      role   = "roles/datastore.user"
      member = local.members.gateway
    }
    # The control UI reads the working database: pending confirms, proposals and runs.
    "roles/datastore.viewer control-ui" = {
      role   = "roles/datastore.viewer"
      member = var.control_ui_member
    }
    # The budget stop unlinks billing from this project (gateway-design section 9).
    "roles/billing.projectManager budget-stop" = {
      role   = "roles/billing.projectManager"
      member = var.budget_stop_member
    }
  }
}

resource "google_project_service" "api" {
  for_each = toset(local.apis)

  project            = var.project
  service            = each.key
  disable_on_destroy = false
}

resource "google_service_account" "gateway" {
  project      = var.project
  account_id   = "gateway"
  display_name = "AIVEN gateway"
  description  = "The gateway: the only identity that acts on Drive, and only in the Sandbox drive."

  depends_on = [google_project_service.api]
}

resource "google_project_iam_member" "project" {
  for_each = local.project_iam

  project = var.project
  role    = each.value.role
  member  = each.value.member
}
