# The three projects of gateway-design section 2. Terraform does not make them: Matthijs does, in
# setup step S1 (ruling R99). It takes their IDs, and sets up what is in them.

locals {
  projects = {
    agents  = var.agents_project
    gateway = var.gateway_project
    control = var.control_project
  }

  # gateway-design section 3: no service account keys, and no Editor role for the default service
  # accounts that Google makes when some APIs are enabled.
  constraints = [
    "iam.disableServiceAccountKeyCreation",
    "iam.automaticIamGrantsForDefaultServiceAccounts",
  ]

  # The APIs of the control project. Terraform bills its calls to this project (providers.tf), so
  # an API that it calls in any project must be on here first.
  control_apis = [
    "billingbudgets.googleapis.com", # the two budgets (Task 2.3)
    "cloudbilling.googleapis.com",   # the budget stop unlinks billing (Task 2.3)
    "cloudresourcemanager.googleapis.com",
    "firestore.googleapis.com", # kill switches, decisions and sign-offs (Task 2.2)
    "iam.googleapis.com",
    "logging.googleapis.com",    # the audit log (Task 2.2)
    "monitoring.googleapis.com", # the alert policies (Task 2.4)
    "orgpolicy.googleapis.com",  # the organisation policies of the three projects
    "serviceusage.googleapis.com",
    "storage.googleapis.com", # policies, snapshots and the Terraform state (Task 2.2)
    # The functions budget-stop and credit-reminder (Tasks 2.3 and 2.4): Cloud Run functions, built
    # by Cloud Build, started through Pub/Sub and Eventarc, or by Cloud Scheduler.
    "artifactregistry.googleapis.com",
    "cloudbuild.googleapis.com",
    "cloudfunctions.googleapis.com",
    "cloudscheduler.googleapis.com",
    "eventarc.googleapis.com",
    "pubsub.googleapis.com",
    "run.googleapis.com",
  ]
}

# The order of a first apply: the organisation policies, then the APIs of the control project, then
# the modules. The bootstrap turns on the APIs that the first two steps call (runbook m2-apply.md).

# Setting these needs Organization Policy Administrator on the organisation (ruling R104). They come
# before anything else in the projects, so that no default service account is made without them,
# and Terraform refuses to remove them (deletion_policy).
resource "google_org_policy_policy" "baseline" {
  for_each = {
    for pair in setproduct(keys(local.projects), local.constraints) :
    "${pair[0]}/${pair[1]}" => { project = local.projects[pair[0]], constraint = pair[1] }
  }

  name            = "projects/${each.value.project}/policies/${each.value.constraint}"
  parent          = "projects/${each.value.project}"
  deletion_policy = "PREVENT"

  spec {
    rules {
      enforce = "TRUE"
    }
  }
}

resource "google_project_service" "control" {
  for_each = toset(local.control_apis)

  project            = var.control_project
  service            = each.key
  disable_on_destroy = false

  depends_on = [google_org_policy_policy.baseline]
}

module "agents" {
  source = "./modules/agents"

  project            = var.agents_project
  agents             = var.agents
  budget_stop_member = module.control.members["budget-stop"]

  depends_on = [google_org_policy_policy.baseline, google_project_service.control]
}

module "gateway" {
  source = "./modules/gateway"

  project            = var.gateway_project
  region             = var.region
  control_ui_member  = module.control.members["control-ui"]
  budget_stop_member = module.control.members["budget-stop"]

  depends_on = [google_org_policy_policy.baseline, google_project_service.control]
}

module "control" {
  source = "./modules/control"

  project        = var.control_project
  region         = var.region
  gateway_member = module.gateway.members["gateway"]

  depends_on = [google_org_policy_policy.baseline, google_project_service.control]
}
