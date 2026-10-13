variable "project" {
  description = "The project ID of aiven-control."
  type        = string
}

variable "gateway_member" {
  description = "The gateway's service account, as an IAM member."
  type        = string
}

variable "region" {
  description = "The region of every regional resource; the root module checks it."
  type        = string
}

variable "billing_account" {
  description = "The ID of the billing account of the budgets; the root module checks it."
  type        = string
}

variable "budget_currency" {
  description = "The currency of the billing account: EUR or USD."
  type        = string
}

variable "budget_alert_amount" {
  description = "The amount of budget aiven-alert, in whole units of the currency."
  type        = number
}

variable "budget_stop_amount" {
  description = "The amount of budget aiven-stop, in whole units of the currency."
  type        = number
}

variable "budget_projects" {
  description = "The IDs of the projects whose gross cost the budgets count: agents, gateway and control."
  type        = list(string)
}

variable "stop_projects" {
  description = "The IDs of the projects the budget stop unlinks: agents and gateway."
  type        = list(string)
}

variable "budget_stop_enabled" {
  description = "Whether the budget stop acts (STOP_ENABLED); off only while restarting (runbook budget-stop.md)."
  type        = bool
}

variable "scratch_project" {
  description = "The ID of the scratch project of drill BD-1."
  type        = string
}

variable "budget_stop_drill" {
  description = "Whether the copy of the budget stop for drill BD-1 exists."
  type        = bool
}

variable "python_src" {
  description = "The folder that holds the package aiven: src in the repository."
  type        = string
}

variable "alert_email" {
  description = "The address the alerts go to; the root module checks it."
  type        = string
}

variable "credit_alert_date" {
  description = "The day of the credit reminder, YYYY-MM-DD."
  type        = string
}

variable "credit_expiry_date" {
  description = "The day the promotional credit ends, YYYY-MM-DD."
  type        = string
}
