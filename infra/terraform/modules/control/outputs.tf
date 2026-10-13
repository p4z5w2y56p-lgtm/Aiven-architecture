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
