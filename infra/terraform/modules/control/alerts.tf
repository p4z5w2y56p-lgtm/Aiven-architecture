# The alerts of gateway-design section 10 (Task 2.4, ruling R111): emails to Matthijs.
#
# 1. Every audit entry with alert: true: R4 or forbidden attempts, unknown callers, three-refusal
#    stops, policy load and snapshot failures, the budget stop, the credit reminder. Also a
#    function's own log line with alert: true, written when the audit log did not take its entry
#    (ruling R130). A log sink routes the audit entries to their bucket, and that is what the
#    alert reads (ruling R139).
# 2. The gateway failing closed for more than a minute: refusals with reason CONTROL_UNREACHABLE.

resource "google_monitoring_notification_channel" "email" {
  project      = var.project
  display_name = "AIVEN alerts"
  type         = "email"

  labels = {
    email_address = var.alert_email
  }
}

locals {
  # The functions of this project, whose own log lines can carry an alert.
  function_services = concat(keys(google_cloudfunctions2_function.stop), ["credit-reminder"])
}

resource "google_monitoring_alert_policy" "alert_entries" {
  project               = var.project
  display_name          = "AIVEN: an audit entry with an alert"
  combiner              = "OR"
  severity              = "CRITICAL"
  notification_channels = [google_monitoring_notification_channel.email.id]

  conditions {
    display_name = "jsonPayload.alert = true"

    condition_matched_log {
      filter = join(" ", [
        "jsonPayload.alert=true AND",
        "(logName=\"projects/${var.project}/logs/aiven-audit\" OR",
        "(resource.type=\"cloud_run_revision\" AND resource.labels.service_name=(${join(" OR ", [for name in local.function_services : "\"${name}\""])})))",
      ])
    }
  }

  # A log-based alert sends one email per 5 minutes at most, and its incident closes after 30.
  alert_strategy {
    notification_rate_limit {
      period = "300s"
    }
    auto_close = "1800s"
  }

  documentation {
    mime_type = "text/markdown"
    subject   = "AIVEN alert"
    content   = "An AIVEN audit entry with `alert: true`, or a function that could not write one. Open the log entry of this incident: its `event`, `reason` and `note` say what happened. The runbooks are in `docs/runbooks/`."
  }
}

resource "google_logging_metric" "control_unreachable" {
  project     = var.project
  name        = "aiven/control-unreachable"
  description = "Calls that the gateway refused because it could not read control (fail closed)."
  bucket_name = "projects/${var.project}/locations/${var.region}/buckets/${google_logging_project_bucket_config.audit.bucket_id}"
  filter      = "jsonPayload.reason=\"CONTROL_UNREACHABLE\""

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
  }
}

resource "google_monitoring_alert_policy" "control_unreachable" {
  project               = var.project
  display_name          = "AIVEN: the gateway fails closed for more than a minute"
  combiner              = "OR"
  severity              = "CRITICAL"
  notification_channels = [google_monitoring_notification_channel.email.id]

  conditions {
    display_name = "CONTROL_UNREACHABLE refusals for more than 60 s"

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.control_unreachable.name}\""
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      duration        = "60s"

      aggregations {
        alignment_period     = "60s"
        per_series_aligner   = "ALIGN_SUM"
        cross_series_reducer = "REDUCE_SUM"
      }

      trigger {
        count = 1
      }
    }
  }

  documentation {
    mime_type = "text/markdown"
    subject   = "AIVEN: the gateway fails closed"
    content   = "The gateway has refused calls for more than a minute because it could not read control (gateway-design section 8). Check Firestore `control` and the gateway's logs; the kill switch break glass is in gateway-design section 8."
  }
}
