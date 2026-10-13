# The source of the Cloud Run functions of this project (ruling R110). Terraform zips each one from
# the repository: a main.py that imports its entry point, the aiven modules that it imports, and
# requirements.txt, which pins every library with its hashes (uv export of the dependency group
# `functions`). tests/functions/test_packaging.py keeps both lists in step with the code.

locals {
  # The aiven modules that every function imports, its own module aside.
  function_modules = [
    "aiven/__init__.py",
    "aiven/common/__init__.py",
    "aiven/common/audit.py",
    "aiven/functions/__init__.py",
    "aiven/policy/__init__.py",
    "aiven/policy/chars.py",
    "aiven/policy/constants.py",
    "aiven/policy/content.py",
  ]

  # Each function, by name: its module.
  functions = {
    "budget-stop"     = "aiven/functions/budget_stop.py"
    "credit-reminder" = "aiven/functions/credit_reminder.py"
  }
}

# The zips, by the hash of what is in them: a function is built again only when its code changed.
resource "google_storage_bucket" "functions" {
  project                     = var.project
  name                        = "${var.project}-functions"
  location                    = var.region
  storage_class               = "STANDARD"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
}

data "archive_file" "function" {
  for_each = local.functions

  type             = "zip"
  output_path      = "${path.root}/.build/${each.key}.zip"
  output_file_mode = "0644"

  source {
    filename = "main.py"
    content  = "from ${replace(trimsuffix(each.value, ".py"), "/", ".")} import main  # noqa: F401\n"
  }

  source {
    filename = "requirements.txt"
    content  = file("${var.python_src}/aiven/functions/requirements.txt")
  }

  dynamic "source" {
    for_each = toset(concat(local.function_modules, [each.value]))
    content {
      filename = source.value
      content  = file("${var.python_src}/${source.value}")
    }
  }
}

resource "google_storage_bucket_object" "function" {
  for_each = local.functions

  bucket = google_storage_bucket.functions.name
  name   = "${each.key}/${data.archive_file.function[each.key].output_sha256}.zip"
  source = data.archive_file.function[each.key].output_path
}

# Cloud Functions copies the source to a bucket of its own, gcf-v2-sources-<number>-<region>, which
# it makes on the first function, and the build reads it from there. The builder may read buckets of
# that name only (an IAM condition; Google's buckets have uniform access, which conditions need).
resource "google_project_iam_member" "builder_reads_staging" {
  project = var.project
  role    = "roles/storage.objectViewer"
  member  = local.members["function-builder"]

  condition {
    title       = "gcf-v2-sources buckets only"
    description = "The staging buckets of Cloud Functions, which hold the source of the functions."
    expression  = "resource.name.startsWith(\"projects/_/buckets/gcf-v2-sources-\")"
  }
}

# The build reads the source; nobody else needs to.
resource "google_storage_bucket_iam_member" "builder_reads_source" {
  bucket = google_storage_bucket.functions.name
  role   = "roles/storage.objectViewer"
  member = local.members["function-builder"]
}
