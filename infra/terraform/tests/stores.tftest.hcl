# Task 2.2 checked offline on a mock provider: the stores of the control and gateway projects
# (gateway-design section 5). Each run plans and applies one module on its own.

mock_provider "google" {}

run "the_stores_of_the_control_project" {
  module {
    source = "./modules/control"
  }

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

  assert {
    condition = alltrue([
      google_storage_bucket.policies.name == "aiven-control-test-policies",
      google_storage_bucket.policies.location == "europe-west4",
      google_storage_bucket.policies.uniform_bucket_level_access,
      google_storage_bucket.policies.public_access_prevention == "enforced",
      google_storage_bucket.policies.versioning[0].enabled,
      google_storage_bucket.policies.deletion_policy == "PREVENT",
    ])
    error_message = "The policies bucket: named after the project, in europe-west4, uniform access, never public, versioned, kept."
  }

  assert {
    condition = alltrue([
      google_storage_bucket.snapshots.name == "aiven-control-test-snapshots",
      google_storage_bucket.snapshots.location == "europe-west4",
      google_storage_bucket.snapshots.uniform_bucket_level_access,
      google_storage_bucket.snapshots.public_access_prevention == "enforced",
      google_storage_bucket.snapshots.deletion_policy == "PREVENT",
      google_storage_bucket.snapshots.retention_policy[0].retention_period == "2592000",
      google_storage_bucket.snapshots.retention_policy[0].is_locked == false,
      length(google_storage_bucket.snapshots.lifecycle_rule) == 1,
      one(google_storage_bucket.snapshots.lifecycle_rule[0].condition).age == 30,
      one(google_storage_bucket.snapshots.lifecycle_rule[0].action).type == "Delete",
    ])
    error_message = "The snapshots bucket keeps every object 30 days, unlocked, and then deletes it."
  }

  assert {
    condition = alltrue([
      google_logging_project_bucket_config.audit.bucket_id == "aiven-audit",
      google_logging_project_bucket_config.audit.location == "europe-west4",
      google_logging_project_bucket_config.audit.retention_days == 365,
      google_logging_project_bucket_config.audit.locked == false,
      google_logging_project_bucket_config.audit.deletion_policy == "PREVENT",
    ])
    error_message = "The audit log bucket keeps 365 days, in europe-west4, and is not locked until Matthijs confirms it."
  }

  assert {
    condition = alltrue([
      google_logging_project_sink.audit.destination == "logging.googleapis.com/projects/aiven-control-test/locations/europe-west4/buckets/aiven-audit",
      google_logging_project_sink.audit.filter == "logName=\"projects/aiven-control-test/logs/aiven-audit\"",
      google_logging_project_exclusion.audit.filter == google_logging_project_sink.audit.filter,
      google_logging_project_exclusion.audit.disabled != true,
    ])
    error_message = "Log aiven-audit goes to its own bucket, and is kept out of _Default."
  }

  assert {
    condition = alltrue([
      google_firestore_database.control.name == "control",
      google_firestore_database.control.location_id == "europe-west4",
      google_firestore_database.control.type == "FIRESTORE_NATIVE",
      google_firestore_database.control.delete_protection_state == "DELETE_PROTECTION_ENABLED",
      google_firestore_database.control.deletion_policy == "PREVENT",
    ])
    error_message = "Firestore control: native, in europe-west4, protected from deletion."
  }

  assert {
    condition = toset([for binding in google_storage_bucket_iam_member.store : "${binding.bucket} ${binding.role} ${binding.member}"]) == toset([
      "aiven-control-test-policies roles/storage.objectViewer serviceAccount:gateway@aiven-gateway-test.iam.gserviceaccount.com",
      "aiven-control-test-policies roles/storage.objectViewer serviceAccount:control-ui@aiven-control-test.iam.gserviceaccount.com",
      "aiven-control-test-snapshots roles/storage.objectCreator serviceAccount:gateway@aiven-gateway-test.iam.gserviceaccount.com",
      "aiven-control-test-snapshots roles/storage.legacyBucketReader serviceAccount:control-ui@aiven-control-test.iam.gserviceaccount.com",
    ])
    error_message = "The roles on the buckets are those of gateway-design section 3: the gateway reads policies and only adds snapshots."
  }

  assert {
    condition = alltrue([
      google_logging_log_view_iam_member.audit_reader.bucket == "aiven-audit",
      google_logging_log_view_iam_member.audit_reader.name == "_AllLogs",
      google_logging_log_view_iam_member.audit_reader.role == "roles/logging.viewAccessor",
      google_logging_log_view_iam_member.audit_reader.member == "serviceAccount:control-ui@aiven-control-test.iam.gserviceaccount.com",
    ])
    error_message = "The control UI reads the audit log; nobody else gets a role on it."
  }
}

run "the_working_database_of_the_gateway" {
  module {
    source = "./modules/gateway"
  }

  variables {
    project            = "aiven-gateway-test"
    region             = "europe-west4"
    control_ui_member  = "serviceAccount:control-ui@aiven-control-test.iam.gserviceaccount.com"
    budget_stop_member = "serviceAccount:budget-stop@aiven-control-test.iam.gserviceaccount.com"
  }

  assert {
    condition = alltrue([
      google_firestore_database.gateway.name == "gateway",
      google_firestore_database.gateway.location_id == "europe-west4",
      google_firestore_database.gateway.type == "FIRESTORE_NATIVE",
      google_firestore_database.gateway.delete_protection_state == "DELETE_PROTECTION_ENABLED",
    ])
    error_message = "Firestore gateway: native, in europe-west4, protected from deletion."
  }

  assert {
    condition = keys(google_firestore_field.expire_at) == ["calls", "runs"] && alltrue([
      for ttl in google_firestore_field.expire_at :
      ttl.database == "gateway" && ttl.field == "expire_at" && length(ttl.ttl_config) == 1 && length(ttl.index_config[0].indexes) == 0
    ])
    error_message = "Runs and calls expire by their expire_at, which has no index (ruling R106)."
  }
}
