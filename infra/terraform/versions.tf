terraform {
  # Exact versions (ruling R98). CI downloads this Terraform and checks its SHA-256, and
  # .terraform.lock.hcl holds the hashes of the providers for Linux, macOS and Windows.
  required_version = "1.16.4"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "8.4.0"
    }
    # Zips the source of the functions (Task 2.3).
    archive = {
      source  = "hashicorp/archive"
      version = "2.8.1"
    }
  }

  # The state lives in a versioned bucket in the control project, made once by hand before the
  # first init (ruling R100, docs/runbooks/m2-apply.md). Its name is given at init, so no ID is
  # written here.
  backend "gcs" {}
}
