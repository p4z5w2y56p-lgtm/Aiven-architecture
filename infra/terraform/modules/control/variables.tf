variable "project" {
  description = "The project ID of aiven-control."
  type        = string
}

variable "gateway_member" {
  description = "The gateway's service account, as an IAM member."
  type        = string
}
