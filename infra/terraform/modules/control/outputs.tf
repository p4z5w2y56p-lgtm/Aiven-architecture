output "members" {
  description = "The member of each service account here (serviceAccount:<email>), by name."
  value       = local.members
}

output "project_iam" {
  description = "Every role granted on this project: project, role and member."
  value = [
    for binding in google_project_iam_member.project :
    { project = binding.project, role = binding.role, member = binding.member }
  ]
}

output "stores" {
  description = "The names of the stores: buckets, the audit log bucket and the Firestore database."
  value = {
    policies_bucket  = google_storage_bucket.policies.name
    snapshots_bucket = google_storage_bucket.snapshots.name
    audit_log_bucket = google_logging_project_bucket_config.audit.bucket_id
    firestore        = google_firestore_database.control.name
  }
}
