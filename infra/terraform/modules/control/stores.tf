# The stores of the control project (gateway-design section 5, Task 2.2), all in europe-west4.
# Bucket names are global, like project IDs, so a bucket is named after the project:
# <control-project>-policies and <control-project>-snapshots (ruling R125). Terraform refuses to
# remove any of them (deletion_policy): they hold what cannot be rebuilt from Git.

# Signed policies and catalog, allowed_signers and model prices. Matthijs publishes them; the
# gateway and the control UI read them. Versioned, so an earlier version can be found again.
resource "google_storage_bucket" "policies" {
  project                     = var.project
  name                        = "${var.project}-policies"
  location                    = var.region
  storage_class               = "STANDARD"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  deletion_policy             = "PREVENT"

  versioning {
    enabled = true
  }
}

# What a write changed (drive-wrapper section 6), kept 30 days and then deleted. The retention
# policy keeps every object those 30 days, so nobody can overwrite or delete one early. It is not
# locked: a locked retention policy cannot be undone, and nobody asked for one.
resource "google_storage_bucket" "snapshots" {
  project                     = var.project
  name                        = "${var.project}-snapshots"
  location                    = var.region
  storage_class               = "STANDARD"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  deletion_policy             = "PREVENT"

  retention_policy {
    retention_period = 30 * 24 * 60 * 60
    is_locked        = false
  }

  lifecycle_rule {
    condition {
      age = 30
    }
    action {
      type = "Delete"
    }
  }
}

# The audit log: every entry of log `aiven-audit`, kept 365 days in a log bucket of its own, and
# kept out of _Default. Locking the bucket cannot be undone, so it waits for Matthijs to confirm
# it; until the commit that he confirms, tests/infra refuses a lock anywhere (ruling R105).
resource "google_logging_project_bucket_config" "audit" {
  project         = var.project
  location        = var.region
  bucket_id       = "aiven-audit"
  description     = "The AIVEN audit log: one entry per event, with IDs and hashes only."
  retention_days  = 365
  locked          = false
  deletion_policy = "PREVENT"
}

resource "google_logging_project_sink" "audit" {
  project                = var.project
  name                   = "aiven-audit"
  description            = "Routes log aiven-audit to its own log bucket."
  destination            = "logging.googleapis.com/projects/${var.project}/locations/${var.region}/buckets/${google_logging_project_bucket_config.audit.bucket_id}"
  filter                 = "logName=\"projects/${var.project}/logs/aiven-audit\""
  unique_writer_identity = true
}

# A project exclusion applies to the _Default sink only: the audit entries stay out of _Default,
# and its readers do not see them.
resource "google_logging_project_exclusion" "audit" {
  project     = var.project
  name        = "aiven-audit-only-in-its-bucket"
  description = "The audit log is kept in its own log bucket, and not in _Default."
  filter      = "logName=\"projects/${var.project}/logs/aiven-audit\""
}

# Kill switches, decisions, sign-offs, taint clears and wrapper switches (Firestore `control`).
resource "google_firestore_database" "control" {
  project                 = var.project
  name                    = "control"
  location_id             = var.region
  type                    = "FIRESTORE_NATIVE"
  concurrency_mode        = "PESSIMISTIC"
  delete_protection_state = "DELETE_PROTECTION_ENABLED"
  deletion_policy         = "PREVENT"
}

locals {
  # The roles on the stores (gateway-design section 3; ruling R101).
  bucket_iam = {
    # The gateway and the control UI read the signed policies and the catalog.
    "policies roles/storage.objectViewer gateway" = {
      bucket = google_storage_bucket.policies.name
      role   = "roles/storage.objectViewer"
      member = var.gateway_member
    }
    "policies roles/storage.objectViewer control-ui" = {
      bucket = google_storage_bucket.policies.name
      role   = "roles/storage.objectViewer"
      member = local.members["control-ui"]
    }
    # The gateway can add a snapshot, and can never read, overwrite or delete one.
    "snapshots roles/storage.objectCreator gateway" = {
      bucket = google_storage_bucket.snapshots.name
      role   = "roles/storage.objectCreator"
      member = var.gateway_member
    }
    # The control UI lists the snapshots, without reading them.
    "snapshots roles/storage.legacyBucketReader control-ui" = {
      bucket = google_storage_bucket.snapshots.name
      role   = "roles/storage.legacyBucketReader"
      member = local.members["control-ui"]
    }
  }
}

resource "google_storage_bucket_iam_member" "store" {
  for_each = local.bucket_iam

  bucket = each.value.bucket
  role   = each.value.role
  member = each.value.member
}

# The control UI reads the audit log. Matthijs reads it as the owner of the project.
resource "google_logging_log_view_iam_member" "audit_reader" {
  parent   = "projects/${var.project}"
  location = var.region
  bucket   = google_logging_project_bucket_config.audit.bucket_id
  name     = "_AllLogs"
  role     = "roles/logging.viewAccessor"
  member   = local.members["control-ui"]
}
