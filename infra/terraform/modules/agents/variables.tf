variable "project" {
  description = "The project ID of aiven-agents."
  type        = string
}

variable "agents" {
  description = "The agent IDs; the root module checks them."
  type        = list(string)
}

variable "budget_stop_member" {
  description = "The budget stop's service account, as an IAM member."
  type        = string
}
