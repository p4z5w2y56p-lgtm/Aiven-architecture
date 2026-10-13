# Task 2.3 checked offline: the budgets and the budget stop of the control module. Google is a mock;
# the archive provider is real, so the zip of the function is built from the repository.

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
}

run "the_two_budgets_count_gross_cost" {
  module {
    source = "./modules/control"
  }

  assert {
    condition = alltrue([
      for budget in [google_billing_budget.alert, google_billing_budget.stop] :
      budget.billing_account == "01ABCD-23EF45-6789AB"
      && budget.budget_filter[0].credit_types_treatment == "EXCLUDE_ALL_CREDITS"
      && budget.budget_filter[0].calendar_period == "MONTH"
      && length(budget.budget_filter[0].projects) == 3
      && budget.amount[0].specified_amount[0].currency_code == "EUR"
    ])
    error_message = "Both budgets: gross cost (credits excluded), per month, of the three projects, in the billing account's currency."
  }

  assert {
    condition = alltrue([
      google_billing_budget.alert.display_name == "aiven-alert",
      google_billing_budget.alert.amount[0].specified_amount[0].units == "10",
      [for rule in google_billing_budget.alert.threshold_rules : rule.threshold_percent] == [0.5, 0.9, 1.0],
      google_billing_budget.stop.display_name == "aiven-stop",
      google_billing_budget.stop.amount[0].specified_amount[0].units == "25",
      [for rule in google_billing_budget.stop.threshold_rules : rule.threshold_percent] == [1.0],
      google_billing_budget.stop.all_updates_rule[0].pubsub_topic == google_pubsub_topic.stop["budget-stop"].id,
    ])
    error_message = "aiven-alert emails at 50, 90 and 100 % of 10; aiven-stop publishes to topic budget-stop at 25."
  }

  assert {
    condition     = keys(google_pubsub_topic.stop) == ["budget-stop"] && google_pubsub_topic.stop["budget-stop"].name == "budget-stop"
    error_message = "One topic, budget-stop, while the drill is off."
  }

  assert {
    condition     = google_pubsub_topic_iam_member.billing_publishes.member == "serviceAccount:billing-budget-alert@system.gserviceaccount.com" && google_pubsub_topic_iam_member.billing_publishes.role == "roles/pubsub.publisher"
    error_message = "Cloud Billing may publish to topic budget-stop."
  }
}

run "the_function_budget_stop" {
  module {
    source = "./modules/control"
  }

  assert {
    condition = alltrue([
      keys(google_cloudfunctions2_function.stop) == ["budget-stop"],
      google_cloudfunctions2_function.stop["budget-stop"].location == "europe-west4",
      google_cloudfunctions2_function.stop["budget-stop"].build_config[0].runtime == "python312",
      google_cloudfunctions2_function.stop["budget-stop"].build_config[0].entry_point == "main",
      google_cloudfunctions2_function.stop["budget-stop"].build_config[0].service_account == google_service_account.account["function-builder"].id,
    ])
    error_message = "budget-stop: Python 3.12, entry point main, in europe-west4, built by function-builder."
  }

  assert {
    condition = alltrue([
      google_cloudfunctions2_function.stop["budget-stop"].service_config[0].ingress_settings == "ALLOW_INTERNAL_ONLY",
      google_cloudfunctions2_function.stop["budget-stop"].service_config[0].max_instance_count == 1,
      google_cloudfunctions2_function.stop["budget-stop"].service_config[0].service_account_email == google_service_account.account["budget-stop"].email,
      google_cloudfunctions2_function.stop["budget-stop"].service_config[0].environment_variables == tomap({
        STOP_PROJECTS   = "aiven-agents-test,aiven-gateway-test"
        STOP_ENABLED    = "true"
        BUDGET_CURRENCY = "EUR"
        AUDIT_PROJECT   = "aiven-control-test"
        AUDIT_ACTOR     = google_service_account.account["budget-stop"].email
      }),
    ])
    error_message = "budget-stop runs as budget-stop, internal only, one instance, and stops the agents and gateway projects."
  }

  assert {
    condition = alltrue([
      google_cloudfunctions2_function.stop["budget-stop"].event_trigger[0].pubsub_topic == google_pubsub_topic.stop["budget-stop"].id,
      google_cloudfunctions2_function.stop["budget-stop"].event_trigger[0].event_type == "google.cloud.pubsub.topic.v1.messagePublished",
      google_cloudfunctions2_function.stop["budget-stop"].event_trigger[0].retry_policy == "RETRY_POLICY_RETRY",
      google_cloudfunctions2_function.stop["budget-stop"].event_trigger[0].service_account_email == google_service_account.account["budget-stop"].email,
      google_cloud_run_v2_service_iam_member.stop_invoker["budget-stop"].role == "roles/run.invoker",
      google_cloud_run_v2_service_iam_member.stop_invoker["budget-stop"].member == "serviceAccount:budget-stop@aiven-control-test.iam.gserviceaccount.com",
    ])
    error_message = "Eventarc delivers topic budget-stop to the function as budget-stop, again after a failure."
  }

  assert {
    condition     = google_storage_bucket_object.function["budget-stop"].name == "budget-stop/${data.archive_file.function["budget-stop"].output_sha256}.zip"
    error_message = "The zip is stored under the hash of what is in it."
  }

  assert {
    condition     = length(google_project_iam_member.drill) == 0
    error_message = "Without the drill, the budget stop has no role on the scratch project."
  }
}

run "the_restart_switches_the_stop_off" {
  module {
    source = "./modules/control"
  }

  variables {
    budget_stop_enabled = false
  }

  assert {
    condition     = google_cloudfunctions2_function.stop["budget-stop"].service_config[0].environment_variables.STOP_ENABLED == "false"
    error_message = "budget_stop_enabled = false reaches the function as STOP_ENABLED=false."
  }
}

run "the_drill_adds_a_copy_for_the_scratch_project_only" {
  module {
    source = "./modules/control"
  }

  variables {
    budget_stop_drill = true
  }

  assert {
    condition = alltrue([
      keys(google_cloudfunctions2_function.stop) == ["budget-stop", "budget-stop-drill"],
      google_cloudfunctions2_function.stop["budget-stop-drill"].service_config[0].environment_variables.STOP_PROJECTS == "aiven-scratch-test",
      google_cloudfunctions2_function.stop["budget-stop-drill"].event_trigger[0].pubsub_topic == google_pubsub_topic.stop["budget-stop-drill"].id,
      google_pubsub_topic.stop["budget-stop-drill"].name == "budget-stop-drill",
      google_billing_budget.stop.all_updates_rule[0].pubsub_topic == google_pubsub_topic.stop["budget-stop"].id,
    ])
    error_message = "The drill copy listens to its own topic and stops the scratch project only; the real budget still publishes to budget-stop."
  }

  assert {
    condition = alltrue([
      length(google_project_iam_member.drill) == 1,
      google_project_iam_member.drill[0].project == "aiven-scratch-test",
      google_project_iam_member.drill[0].role == "roles/billing.projectManager",
    ])
    error_message = "During the drill, the budget stop may unlink the scratch project."
  }
}
