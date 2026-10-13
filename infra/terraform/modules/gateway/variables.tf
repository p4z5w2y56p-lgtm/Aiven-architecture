variable "project" {
  description = "The project ID of aiven-gateway."
  type        = string
}

variable "control_ui_member" {
  description = "The control UI's service account, as an IAM member."
  type        = string
}

variable "budget_stop_member" {
  description = "The budget stop's service account, as an IAM member."
  type        = string
}
