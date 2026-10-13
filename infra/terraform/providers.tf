# Terraform runs with Matthijs's own login (gcloud auth application-default login); it holds no
# key. Every resource names its project. Calls are billed to the control project, and need their
# API enabled there: the Budget API refuses a user login that has no such quota project.
provider "google" {
  region                = var.region
  billing_project       = var.control_project
  user_project_override = true
}
