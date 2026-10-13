# aiven-agents (gateway-design sections 2 and 3): one service account per agent, and the APIs that
# an agent needs. The Drive, Sheets and Gmail APIs are never enabled here: an agent reaches
# Workspace data only through the gateway (ruling R103, deploy check `apis`).

locals {
  apis = [
    "aiplatform.googleapis.com",       # the model, through Vertex AI with IAM: no API key
    "artifactregistry.googleapis.com", # the agents' images
    "iam.googleapis.com",
    "logging.googleapis.com",
    "run.googleapis.com", # one Cloud Run job per agent
  ]

  # The member of each service account, written from its account ID the way Google makes the
  # email, so that a plan shows every binding in full.
  members = {
    for agent, account in google_service_account.agent :
    "agent-${agent}" => "serviceAccount:${account.account_id}@${var.project}.iam.gserviceaccount.com"
  }

  # The roles on this project. An agent's other role, run.invoker on the gateway service, comes
  # with that service (Task 3.10, ruling R101).
  project_iam = merge(
    {
      for name, member in local.members :
      "roles/aiplatform.user ${name}" => { role = "roles/aiplatform.user", member = member }
    },
    {
      # The budget stop reads and unlinks the billing of this project (gateway-design sections 3
      # and 9): Google's guide to disabling billing takes both roles (ruling R167).
      for role in ["roles/billing.projectManager", "roles/browser"] :
      "${role} budget-stop" => { role = role, member = var.budget_stop_member }
    },
  )
}

resource "google_project_service" "api" {
  for_each = toset(local.apis)

  project            = var.project
  service            = each.key
  disable_on_destroy = false
}

resource "google_service_account" "agent" {
  for_each = toset(var.agents)

  project      = var.project
  account_id   = "agent-${each.key}"
  display_name = "Agent ${each.key}"
  description  = "The identity of agent ${each.key}: it calls the gateway and its model, and nothing else."

  depends_on = [google_project_service.api]
}

resource "google_project_iam_member" "project" {
  for_each = local.project_iam

  project = var.project
  role    = each.value.role
  member  = each.value.member
}
