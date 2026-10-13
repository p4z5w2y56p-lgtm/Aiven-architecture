# Task 2.1 checked offline: the mock provider makes no call to Google (ruling R97). Run it with
# `terraform -chdir=infra/terraform test` after `terraform init -backend=false`.

mock_provider "google" {}

variables {
  agents_project  = "aiven-agents-test"
  gateway_project = "aiven-gateway-test"
  control_project = "aiven-control-test"
  agents          = ["invoice-reminder", "payment-nudge"]
}

run "every_project_has_both_organisation_policies" {
  assert {
    condition = toset([for policy in google_org_policy_policy.baseline : policy.name]) == toset([
      "projects/aiven-agents-test/policies/iam.disableServiceAccountKeyCreation",
      "projects/aiven-agents-test/policies/iam.automaticIamGrantsForDefaultServiceAccounts",
      "projects/aiven-gateway-test/policies/iam.disableServiceAccountKeyCreation",
      "projects/aiven-gateway-test/policies/iam.automaticIamGrantsForDefaultServiceAccounts",
      "projects/aiven-control-test/policies/iam.disableServiceAccountKeyCreation",
      "projects/aiven-control-test/policies/iam.automaticIamGrantsForDefaultServiceAccounts",
    ])
    error_message = "Each project has the two organisation policies of gateway-design section 3, and no others."
  }

  assert {
    condition = alltrue([
      for policy in google_org_policy_policy.baseline :
      policy.spec[0].rules[0].enforce == "TRUE" && policy.deletion_policy == "PREVENT"
    ])
    error_message = "Both policies are enforced, and Terraform refuses to remove them."
  }
}

run "the_service_accounts_of_gateway_design_section_3" {
  assert {
    condition = output.service_accounts == {
      "agent-invoice-reminder" = "agent-invoice-reminder@aiven-agents-test.iam.gserviceaccount.com"
      "agent-payment-nudge"    = "agent-payment-nudge@aiven-agents-test.iam.gserviceaccount.com"
      "gateway"                = "gateway@aiven-gateway-test.iam.gserviceaccount.com"
      "control-ui"             = "control-ui@aiven-control-test.iam.gserviceaccount.com"
      "budget-stop"            = "budget-stop@aiven-control-test.iam.gserviceaccount.com"
      "credit-reminder"        = "credit-reminder@aiven-control-test.iam.gserviceaccount.com"
    }
    error_message = "One account per agent, and the gateway, control UI, budget stop and credit reminder."
  }
}

run "the_roles_on_the_projects_are_exactly_those_of_gateway_design_section_3" {
  # Roles on a bucket, a log bucket or a service come with that resource (ruling R101).
  assert {
    condition = toset([for binding in output.project_iam : "${binding.project} ${binding.role} ${binding.member}"]) == toset([
      "aiven-agents-test roles/aiplatform.user serviceAccount:agent-invoice-reminder@aiven-agents-test.iam.gserviceaccount.com",
      "aiven-agents-test roles/aiplatform.user serviceAccount:agent-payment-nudge@aiven-agents-test.iam.gserviceaccount.com",
      "aiven-agents-test roles/billing.projectManager serviceAccount:budget-stop@aiven-control-test.iam.gserviceaccount.com",
      "aiven-gateway-test roles/billing.projectManager serviceAccount:budget-stop@aiven-control-test.iam.gserviceaccount.com",
      "aiven-gateway-test roles/datastore.user serviceAccount:gateway@aiven-gateway-test.iam.gserviceaccount.com",
      "aiven-gateway-test roles/datastore.viewer serviceAccount:control-ui@aiven-control-test.iam.gserviceaccount.com",
      "aiven-control-test roles/datastore.user serviceAccount:control-ui@aiven-control-test.iam.gserviceaccount.com",
      "aiven-control-test roles/datastore.viewer serviceAccount:gateway@aiven-gateway-test.iam.gserviceaccount.com",
      "aiven-control-test roles/logging.logWriter serviceAccount:gateway@aiven-gateway-test.iam.gserviceaccount.com",
      "aiven-control-test roles/logging.logWriter serviceAccount:control-ui@aiven-control-test.iam.gserviceaccount.com",
      "aiven-control-test roles/logging.logWriter serviceAccount:budget-stop@aiven-control-test.iam.gserviceaccount.com",
      "aiven-control-test roles/logging.logWriter serviceAccount:credit-reminder@aiven-control-test.iam.gserviceaccount.com",
    ])
    error_message = "The roles on the three projects differ from gateway-design section 3."
  }

  assert {
    condition     = length(output.project_iam) == 10 + 2
    error_message = "Ten roles, and one per agent, each granted once (docs/runbooks/m2-apply.md, part 4)."
  }
}

run "the_apis_of_each_project" {
  assert {
    condition = output.apis.agents == tolist([
      "aiplatform.googleapis.com",
      "artifactregistry.googleapis.com",
      "iam.googleapis.com",
      "logging.googleapis.com",
      "run.googleapis.com",
    ])
    error_message = "The agents project has exactly the APIs an agent needs (ruling R103)."
  }

  assert {
    condition = length(setintersection(toset(output.apis.agents), toset([
      "drive.googleapis.com", "sheets.googleapis.com", "gmail.googleapis.com",
    ]))) == 0
    error_message = "Drive, Sheets and Gmail are never enabled in the agents project."
  }

  assert {
    condition = alltrue([
      for api in ["drive.googleapis.com", "sheets.googleapis.com", "firestore.googleapis.com", "run.googleapis.com"] :
      contains(output.apis.gateway, api)
    ])
    error_message = "The gateway project has the APIs of the gateway and the Drive wrapper."
  }

  assert {
    condition     = !contains(concat(output.apis.agents, output.apis.gateway, output.apis.control), "gmail.googleapis.com")
    error_message = "Gmail waits for the email wrapper (M6), which ships switched off."
  }

  assert {
    condition = alltrue([
      for api in ["billingbudgets.googleapis.com", "cloudbilling.googleapis.com", "orgpolicy.googleapis.com", "serviceusage.googleapis.com", "cloudresourcemanager.googleapis.com"] :
      contains(output.apis.control, api)
    ])
    error_message = "The control project, which Terraform bills its calls to, has the APIs Terraform calls."
  }

  assert {
    condition     = [length(output.apis.control), length(output.apis.agents), length(output.apis.gateway)] == [17, 5, 7]
    error_message = "17 APIs in control, 5 in agents and 7 in gateway (docs/runbooks/m2-apply.md, part 4)."
  }
}

run "no_agents_means_no_agent_accounts" {
  variables {
    agents = []
  }

  assert {
    condition     = keys(output.service_accounts) == ["budget-stop", "control-ui", "credit-reminder", "gateway"]
    error_message = "Without agents, only the four platform accounts exist."
  }

  assert {
    condition     = length([for binding in output.project_iam : binding if binding.role == "roles/aiplatform.user"]) == 0
    error_message = "Without agents, nobody has aiplatform.user."
  }
}

# --- the variables

run "an_agent_id_against_the_rule_is_refused" {
  command = plan
  variables {
    agents = ["Invoice_Reminder"]
  }
  expect_failures = [var.agents]
}

run "an_agent_id_of_two_characters_is_refused" {
  command = plan
  variables {
    agents = ["ab"]
  }
  expect_failures = [var.agents]
}

run "an_agent_id_of_25_characters_is_refused" {
  command = plan
  variables {
    agents = ["a234567890123456789012345"]
  }
  expect_failures = [var.agents]
}

run "an_agent_id_with_two_hyphens_in_a_row_is_refused" {
  command = plan
  variables {
    agents = ["invoice--reminder"]
  }
  expect_failures = [var.agents]
}

run "a_reserved_agent_id_is_refused" {
  command = plan
  variables {
    agents = ["gateway"]
  }
  expect_failures = [var.agents]
}

run "an_agent_listed_twice_is_refused" {
  command = plan
  variables {
    agents = ["invoice-reminder", "invoice-reminder"]
  }
  expect_failures = [var.agents]
}

run "an_agent_id_of_24_characters_is_fine" {
  command = plan
  variables {
    agents = ["a23456789012345678901234"]
  }
}

run "another_region_is_refused" {
  command = plan
  variables {
    region = "europe-west1"
  }
  expect_failures = [var.region]
}

run "a_project_id_against_the_rule_is_refused" {
  command = plan
  variables {
    agents_project = "Aiven-Agents"
  }
  expect_failures = [var.agents_project]
}

run "the_same_project_twice_is_refused" {
  command = plan
  variables {
    control_project = "aiven-gateway-test"
  }
  expect_failures = [var.control_project]
}
