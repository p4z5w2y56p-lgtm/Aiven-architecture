# The gateway's working database (gateway-design section 5, Task 2.2). It is working state: if it
# is lost, it is rebuilt empty, so Terraform may let go of it (deletion_policy ABANDON, the
# default), but Google refuses to delete it while delete protection is on.
resource "google_firestore_database" "gateway" {
  project                 = var.project
  name                    = "gateway"
  location_id             = var.region
  type                    = "FIRESTORE_NATIVE"
  concurrency_mode        = "PESSIMISTIC"
  delete_protection_state = "DELETE_PROTECTION_ENABLED"
}

# Runs and calls expire 90 days after they are written: the gateway sets `expire_at` to that time
# (gateway-design section 13, ruling R106). The audit log is the permanent record. The field has no
# index: nothing queries it, and an index on a time that only grows makes a hot spot.
resource "google_firestore_field" "expire_at" {
  for_each = toset(["runs", "calls"])

  project    = var.project
  database   = google_firestore_database.gateway.name
  collection = each.key
  field      = "expire_at"

  ttl_config {}
  index_config {}
}
