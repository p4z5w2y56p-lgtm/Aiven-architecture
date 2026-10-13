output "service_accounts" {
  description = "The email of each service account, by name (the Sandbox drive gets the gateway's as Contributor)."
  value = {
    for name, member in merge(module.agents.members, module.gateway.members, module.control.members) :
    name => trimprefix(member, "serviceAccount:")
  }
}

output "apis" {
  description = "The APIs enabled in each project."
  value = {
    agents  = module.agents.apis
    gateway = module.gateway.apis
    control = sort([for api in google_project_service.control : api.service])
  }
}

output "project_iam" {
  description = "Every role granted on a project: project, role and member (gateway-design section 3)."
  value       = concat(module.agents.project_iam, module.gateway.project_iam, module.control.project_iam)
}

output "stores" {
  description = "The names of the stores of the control and gateway projects."
  value       = merge(module.control.stores, { gateway_firestore = module.gateway.firestore })
}
