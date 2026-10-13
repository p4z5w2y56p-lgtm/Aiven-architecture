# The values of a deployment are in terraform.tfvars, and terraform.tfvars.example shows them: IDs
# and addresses only, never a credential (CI refuses anything else, ruling R113).

variable "agents_project" {
  description = "The project ID of aiven-agents: one Cloud Run job and one service account per agent."
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.agents_project))
    error_message = "A project ID has 6 to 30 lowercase letters, digits and hyphens, starts with a letter, and does not end with a hyphen."
  }
}

variable "gateway_project" {
  description = "The project ID of aiven-gateway: the gateway and its working database."
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.gateway_project))
    error_message = "A project ID has 6 to 30 lowercase letters, digits and hyphens, starts with a letter, and does not end with a hyphen."
  }
}

variable "control_project" {
  description = "The project ID of aiven-control: the audit log, the switches, the policies, the snapshots, budgets and alerts."
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.control_project))
    error_message = "A project ID has 6 to 30 lowercase letters, digits and hyphens, starts with a letter, and does not end with a hyphen."
  }

  validation {
    condition     = length(distinct([var.agents_project, var.gateway_project, var.control_project])) == 3
    error_message = "The agents, gateway and control projects are three different projects."
  }
}

variable "region" {
  description = "The region of every regional resource (gateway-design section 2)."
  type        = string
  default     = "europe-west4"

  validation {
    condition     = var.region == "europe-west4"
    error_message = "Every regional resource is in europe-west4 (the Netherlands)."
  }
}

variable "agents" {
  description = "The IDs of the agents (validator-spec 3.3). Each gets the service account agent-<id> in the agents project."
  type        = list(string)
  default     = []

  # The agent ID rule of the validator (constants.py: AGENT_ID_LENGTH, AGENT_ID_PATTERN and
  # RESERVED_AGENT_IDS). tests/infra/test_terraform.py keeps the two in step.
  validation {
    condition = alltrue([
      for agent in var.agents :
      length(agent) >= 3 && length(agent) <= 24 && can(regex("^[a-z][a-z0-9]*(-[a-z0-9]+)*$", agent))
    ])
    error_message = "An agent ID has 3 to 24 characters: lowercase letters and digits, starting with a letter, with single hyphens between them."
  }

  validation {
    condition = length(setintersection(toset(var.agents), toset([
      "admin", "all", "audit", "control", "gateway", "killswitch", "matthijs", "policy", "system", "template",
    ]))) == 0
    error_message = "An agent ID is not one of the reserved IDs of validator-spec 3.3."
  }

  validation {
    condition     = length(distinct(var.agents)) == length(var.agents)
    error_message = "Each agent is listed once."
  }
}
