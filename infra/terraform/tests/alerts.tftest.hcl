# Task 2.4 checked offline: the alerts and the credit reminder of the control module. Google is a
# mock; the archive provider is real, so the zips of the functions are built from the repository.

mock_provider "google" {}

variables {
  project             = "aiven-control-test"
  region              = "europe-west4"
  gateway_member      = "serviceAccount:gateway@aiven-gateway-test.iam.gserviceaccount.com"
  billing_account     = "01ABCD-23EF45-6789AB"
  budget_currency     = "EUR"
  budget_alert_amount = 10
  budget_stop_amount  = 25
  budget_projects     = ["aiven-agents-test", "aiven-gateway-test", "aiven-control-test"]
  stop_projects       = ["aiven-agents-test", "aiven-gateway-test"]
  budget_stop_enabled = true
  scratch_project     = "aiven-scratch-test"
  budget_stop_drill   = false
  python_src          = "../../src"
  alert_email         = "alerts@aivenstudios.com"
  credit_alert_date   = "2026-12-20"
  credit_expiry_date  = "2027-01-04"
}

run "every_alert_entry_is_emailed" {
  module {
    source = "./modules/control"
  }

  assert {
    condition = alltrue([
      google_monitoring_notification_channel.email.type == "email",
      google_monitoring_notification_channel.email.labels.email_address == "alerts@aivenstudios.com",
      google_monitoring_alert_policy.alert_entries.notification_channels == tolist([google_monitoring_notification_channel.email.id]),
      google_monitoring_alert_policy.control_unreachable.notification_channels == tolist([google_monitoring_notification_channel.email.id]),
    ])
    error_message = "Both alert policies email the alert address."
  }

  assert {
    condition = google_monitoring_alert_policy.alert_entries.conditions[0].condition_matched_log[0].filter == join(" ", [
      "jsonPayload.alert=true AND",
      "(logName=\"projects/aiven-control-test/logs/aiven-audit\" OR",
      "(resource.type=\"cloud_run_revision\" AND resource.labels.service_name=(\"budget-stop\" OR \"credit-reminder\")))",
    ])
    error_message = "Policy 1 matches every audit entry with alert: true, and the functions' own alert lines (rulings R111, R130)."
  }

  assert {
    condition     = google_monitoring_alert_policy.alert_entries.alert_strategy[0].notification_rate_limit[0].period == "300s"
    error_message = "A log-based alert has a notification rate limit."
  }
}

run "the_drill_copy_can_raise_an_alert_too" {
  module {
    source = "./modules/control"
  }

  variables {
    budget_stop_drill = true
  }

  assert {
    condition     = strcontains(google_monitoring_alert_policy.alert_entries.conditions[0].condition_matched_log[0].filter, "\"budget-stop-drill\"")
    error_message = "While the drill is on, its own alert lines are emailed as well."
  }
}

run "failing_closed_for_more_than_a_minute_is_emailed" {
  module {
    source = "./modules/control"
  }

  assert {
    condition = alltrue([
      google_logging_metric.control_unreachable.filter == "jsonPayload.reason=\"CONTROL_UNREACHABLE\"",
      google_logging_metric.control_unreachable.bucket_name == "projects/aiven-control-test/locations/europe-west4/buckets/aiven-audit",
      google_logging_metric.control_unreachable.metric_descriptor[0].metric_kind == "DELTA",
    ])
    error_message = "The metric counts the CONTROL_UNREACHABLE refusals in the audit log bucket (ruling R139)."
  }

  assert {
    condition = alltrue([
      google_monitoring_alert_policy.control_unreachable.conditions[0].condition_matched_log[0].filter == "logName=\"projects/aiven-control-test/logs/aiven-audit\" AND jsonPayload.reason=\"CONTROL_UNREACHABLE\"",
      google_monitoring_alert_policy.control_unreachable.alert_strategy[0].notification_rate_limit[0].period == "300s",
    ])
    error_message = "Policy 2 emails a CONTROL_UNREACHABLE refusal in the audit log, at most once per 5 minutes (rulings R111, R165)."
  }
}

run "the_credit_reminder" {
  module {
    source = "./modules/control"
  }

  assert {
    condition = alltrue([
      google_cloud_scheduler_job.credit_reminder.name == "credit-reminder",
      google_cloud_scheduler_job.credit_reminder.region == "europe-west4",
      google_cloud_scheduler_job.credit_reminder.schedule == "0 9 20 12 *",
      google_cloud_scheduler_job.credit_reminder.time_zone == "Europe/Amsterdam",
      google_cloud_scheduler_job.credit_reminder.http_target[0].http_method == "POST",
      google_cloud_scheduler_job.credit_reminder.http_target[0].uri == google_cloudfunctions2_function.credit_reminder.service_config[0].uri,
      google_cloud_scheduler_job.credit_reminder.http_target[0].oidc_token[0].service_account_email == google_service_account.account["credit-reminder"].email,
    ])
    error_message = "At 09:00 Europe/Amsterdam on 20 December, Cloud Scheduler calls the function with an OIDC token of credit-reminder (ruling R109)."
  }

  assert {
    condition = alltrue([
      google_cloudfunctions2_function.credit_reminder.build_config[0].runtime == "python312",
      google_cloudfunctions2_function.credit_reminder.build_config[0].service_account == google_service_account.account["function-builder"].id,
      google_cloudfunctions2_function.credit_reminder.service_config[0].ingress_settings == "ALLOW_INTERNAL_ONLY",
      google_cloudfunctions2_function.credit_reminder.service_config[0].service_account_email == google_service_account.account["credit-reminder"].email,
      google_cloudfunctions2_function.credit_reminder.service_config[0].environment_variables == tomap({
        CREDIT_EXPIRY = "2027-01-04"
        AUDIT_PROJECT = "aiven-control-test"
        AUDIT_ACTOR   = google_service_account.account["credit-reminder"].email
      }),
      google_cloud_run_v2_service_iam_member.credit_reminder_invoker.member == "serviceAccount:credit-reminder@aiven-control-test.iam.gserviceaccount.com",
      google_cloud_run_v2_service_iam_member.credit_reminder_invoker.role == "roles/run.invoker",
    ])
    error_message = "credit-reminder runs as credit-reminder, internal only, knows the day the credit ends, and only credit-reminder may call it."
  }

  assert {
    condition     = google_storage_bucket_object.function["credit-reminder"].name == "credit-reminder/${data.archive_file.function["credit-reminder"].output_sha256}.zip"
    error_message = "The reminder's zip is stored under the hash of what is in it."
  }
}

run "a_reminder_on_another_day_moves_the_schedule" {
  module {
    source = "./modules/control"
  }

  variables {
    credit_alert_date = "2026-11-05"
  }

  assert {
    condition     = google_cloud_scheduler_job.credit_reminder.schedule == "0 9 5 11 *"
    error_message = "The schedule follows credit_alert_date, without leading zeros."
  }
}

run "the_builder_reads_the_staging_buckets_of_cloud_functions_only" {
  module {
    source = "./modules/control"
  }

  assert {
    condition = alltrue([
      google_project_iam_member.builder_reads_staging.role == "roles/storage.objectViewer",
      google_project_iam_member.builder_reads_staging.member == "serviceAccount:function-builder@aiven-control-test.iam.gserviceaccount.com",
      google_project_iam_member.builder_reads_staging.condition[0].expression == "resource.name.startsWith(\"projects/_/buckets/gcf-v2-sources-\")",
    ])
    error_message = "function-builder reads Cloud Functions' staging buckets (gcf-v2-sources-*) and no other bucket of the project (ruling R164)."
  }
}
