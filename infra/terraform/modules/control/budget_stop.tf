# Budgets and the budget stop (gateway-design section 9, runbook budget-stop.md, Task 2.3).
#
# Both budgets count gross cost (credits excluded) of the agents, gateway and control projects, per
# calendar month, in the billing account's currency. aiven-alert emails the billing account's
# administrators at 50, 90 and 100 %. aiven-stop publishes to topic budget-stop, and the function
# budget-stop unlinks billing from the agents and gateway projects (src/aiven/functions).

data "google_project" "budget" {
  for_each = toset(var.budget_projects)

  project_id = each.key
}

locals {
  # A budget names its projects by number.
  budget_projects = [for project in var.budget_projects : "projects/${data.google_project.budget[project].number}"]

  # The budget stop, and while var.budget_stop_drill is on its copy for drill BD-1: the same code,
  # a topic of its own, and the scratch project only (runbook budget-stop.md, Drill).
  stops = merge(
    { "budget-stop" = { topic = "budget-stop", projects = var.stop_projects } },
    var.budget_stop_drill ? {
      "budget-stop-drill" = { topic = "budget-stop-drill", projects = [var.scratch_project] }
    } : {},
  )
}

resource "google_billing_budget" "alert" {
  billing_account = var.billing_account
  display_name    = "aiven-alert"

  budget_filter {
    projects               = local.budget_projects
    credit_types_treatment = "EXCLUDE_ALL_CREDITS"
    calendar_period        = "MONTH"
  }

  amount {
    specified_amount {
      currency_code = var.budget_currency
      units         = tostring(var.budget_alert_amount)
    }
  }

  dynamic "threshold_rules" {
    for_each = [0.5, 0.9, 1.0]
    content {
      threshold_percent = threshold_rules.value
      spend_basis       = "CURRENT_SPEND"
    }
  }
}

resource "google_billing_budget" "stop" {
  billing_account = var.billing_account
  display_name    = "aiven-stop"

  budget_filter {
    projects               = local.budget_projects
    credit_types_treatment = "EXCLUDE_ALL_CREDITS"
    calendar_period        = "MONTH"
  }

  amount {
    specified_amount {
      currency_code = var.budget_currency
      units         = tostring(var.budget_stop_amount)
    }
  }

  threshold_rules {
    threshold_percent = 1.0
    spend_basis       = "CURRENT_SPEND"
  }

  # Cloud Billing sends every update of the budget to the topic, several times a day, whatever
  # the cost; the function acts at 100 % only.
  all_updates_rule {
    pubsub_topic   = google_pubsub_topic.stop["budget-stop"].id
    schema_version = "1.0"
  }

  # Billing checks that it may publish to the topic when the budget is made.
  depends_on = [google_pubsub_topic_iam_member.billing_publishes]
}

resource "google_pubsub_topic" "stop" {
  for_each = local.stops

  project = var.project
  name    = each.value.topic
}

# Cloud Billing publishes a budget's notifications as this Google account.
resource "google_pubsub_topic_iam_member" "billing_publishes" {
  project = var.project
  topic   = google_pubsub_topic.stop["budget-stop"].name
  role    = "roles/pubsub.publisher"
  member  = "serviceAccount:billing-budget-alert@system.gserviceaccount.com"
}

resource "google_cloudfunctions2_function" "stop" {
  for_each = local.stops

  project     = var.project
  name        = each.key
  location    = var.region
  description = "Unlinks billing from ${join(", ", each.value.projects)} when budget aiven-stop is reached."

  build_config {
    runtime         = "python312"
    entry_point     = "main"
    service_account = google_service_account.account["function-builder"].id

    source {
      storage_source {
        bucket = google_storage_bucket.functions.name
        object = google_storage_bucket_object.function["budget-stop"].name
      }
    }
  }

  service_config {
    available_memory                 = "256M"
    timeout_seconds                  = 60
    min_instance_count               = 0
    max_instance_count               = 1
    max_instance_request_concurrency = 1
    ingress_settings                 = "ALLOW_INTERNAL_ONLY"
    all_traffic_on_latest_revision   = true
    service_account_email            = google_service_account.account["budget-stop"].email

    environment_variables = {
      STOP_PROJECTS   = join(",", each.value.projects)
      STOP_ENABLED    = tostring(var.budget_stop_enabled)
      BUDGET_CURRENCY = var.budget_currency
      AUDIT_PROJECT   = var.project
      AUDIT_ACTOR     = google_service_account.account["budget-stop"].email
    }
  }

  # A notification that failed (StopFailed) is delivered again.
  event_trigger {
    trigger_region        = var.region
    event_type            = "google.cloud.pubsub.topic.v1.messagePublished"
    pubsub_topic          = google_pubsub_topic.stop[each.key].id
    retry_policy          = "RETRY_POLICY_RETRY"
    service_account_email = google_service_account.account["budget-stop"].email
  }

  # The builder reads the source from Cloud Functions' staging bucket (functions.tf).
  depends_on = [google_project_iam_member.builder_reads_staging]
}

# Eventarc calls the function as budget-stop; nothing else may.
resource "google_cloud_run_v2_service_iam_member" "stop_invoker" {
  for_each = local.stops

  project  = var.project
  location = var.region
  name     = google_cloudfunctions2_function.stop[each.key].name
  role     = "roles/run.invoker"
  member   = local.members["budget-stop"]
}

# While the drill is on, the budget stop may unlink billing from the scratch project as well.
resource "google_project_iam_member" "drill" {
  count = var.budget_stop_drill ? 1 : 0

  project = var.scratch_project
  role    = "roles/billing.projectManager"
  member  = local.members["budget-stop"]
}
