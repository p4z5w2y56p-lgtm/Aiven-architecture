# The Terraform values of the deployment: IDs and addresses only, never a credential, a key or a
# token. CI refuses anything else here (aiven-check-config). scripts/m2-oneclick.sh wrote it from
# terraform.tfvars.example and the answers it was given.

agents_project  = "aiven-agents-819c3e"
gateway_project = "aiven-gateway-819c3e"
control_project = "aiven-control-819c3e"
scratch_project = "aiven-scratch-819c3e"
region          = "europe-west4"

# Budgets, gross cost per month (setup step S2): 10 and 25 in EUR, 11 and 27 in USD.
billing_account     = "012A60-DF87B5-BE025D"
budget_currency     = "EUR"
budget_alert_amount = 10
budget_stop_amount  = 25

# Alerts, and the reminder before the promotional credit ends (setup step S3).
alert_email        = "m.vanhoorn@aivenstudios.com"
credit_alert_date  = "2026-12-20"
credit_expiry_date = "2027-01-04"

# The agents, by agent ID (validator-spec 3.3). Each gets the service account agent-<id>.
agents = ["invoice-reminder"]
