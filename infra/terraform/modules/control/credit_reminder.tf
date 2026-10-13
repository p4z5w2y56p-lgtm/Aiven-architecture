# The credit reminder (gateway-design section 14, Task 2.4, ruling R109): Cloud Scheduler calls the
# function at 09:00 Europe/Amsterdam on the day of credit_alert_date, and it writes an audit entry
# with an alert while the credit lasts.

locals {
  credit_alert = split("-", var.credit_alert_date) # year, month, day
}

resource "google_cloudfunctions2_function" "credit_reminder" {
  project     = var.project
  name        = "credit-reminder"
  location    = var.region
  description = "Writes the credit reminder, an audit entry with an alert, until the credit ends on ${var.credit_expiry_date}."

  build_config {
    runtime         = "python312"
    entry_point     = "main"
    service_account = google_service_account.account["function-builder"].id

    source {
      storage_source {
        bucket = google_storage_bucket.functions.name
        object = google_storage_bucket_object.function["credit-reminder"].name
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
    service_account_email            = google_service_account.account["credit-reminder"].email

    environment_variables = {
      CREDIT_EXPIRY = var.credit_expiry_date
      AUDIT_PROJECT = var.project
      AUDIT_ACTOR   = google_service_account.account["credit-reminder"].email
    }
  }

  # After the stop: the first function makes Cloud Functions' staging bucket, and two at once would
  # both try (one gets 409). The builder must be able to read that bucket first.
  depends_on = [google_cloudfunctions2_function.stop, google_project_iam_member.builder_reads_staging]
}

# Cloud Scheduler calls the function as credit-reminder; nothing else may.
resource "google_cloud_run_v2_service_iam_member" "credit_reminder_invoker" {
  project  = var.project
  location = var.region
  name     = google_cloudfunctions2_function.credit_reminder.name
  role     = "roles/run.invoker"
  member   = local.members["credit-reminder"]
}

# A cron schedule comes back every year; after the credit ended, the function writes nothing.
resource "google_cloud_scheduler_job" "credit_reminder" {
  project          = var.project
  region           = var.region
  name             = "credit-reminder"
  description      = "The credit reminder, 09:00 Europe/Amsterdam on ${var.credit_alert_date}."
  schedule         = "0 9 ${tonumber(local.credit_alert[2])} ${tonumber(local.credit_alert[1])} *"
  time_zone        = "Europe/Amsterdam"
  attempt_deadline = "60s"

  retry_config {
    retry_count = 2
  }

  http_target {
    http_method = "POST"
    uri         = google_cloudfunctions2_function.credit_reminder.service_config[0].uri

    oidc_token {
      service_account_email = google_service_account.account["credit-reminder"].email
      audience              = google_cloudfunctions2_function.credit_reminder.service_config[0].uri
    }
  }
}
