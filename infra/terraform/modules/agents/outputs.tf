output "members" {
  description = "The member of each agent's service account (serviceAccount:<email>), by name."
  value       = local.members
}

output "apis" {
  description = "The APIs enabled in this project."
  value       = sort([for api in google_project_service.api : api.service])
}

output "project_iam" {
  description = "Every role granted on this project: project, role and member."
  value = [
    for binding in google_project_iam_member.project :
    { project = binding.project, role = binding.role, member = binding.member }
  ]
}
