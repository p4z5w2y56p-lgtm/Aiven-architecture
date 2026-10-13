#!/usr/bin/env bash
# M2 in one go: everything of docs/runbooks/m2-apply.md, on your Mac.
#
#   bash scripts/m2-oneclick.sh             # the whole of M2: plan, one question, apply, drills, checks
#   bash scripts/m2-oneclick.sh --dry-run   # up to the plan only: nothing changes in Google Cloud
#
# What you do: log in twice in the browser (gcloud, then Terraform's login), type an ID when one is
# missing from config/platform.yaml or infra/terraform/terraform.tfvars, and answer "Apply? (y/n)"
# once. At the end it asks whether the alert emails arrived (Enter skips that).
#
# In order: the tools (Terraform 1.16.4 checked against its SHA-256, gcloud and uv through
# Homebrew), the two logins, the values (checked with aiven-check-config), Organization Policy
# Administrator for you, the bootstrap of the control project (4 APIs and the state bucket),
# terraform init and plan, a short summary against the runbook, the question, the apply. Then: the
# credit reminder run by hand, drills BD-1 and BD-2 on the scratch project only, the gateway as
# Contributor of the Sandbox drive, aiven-deploy-check all, and a report in m2-result.txt (IDs and
# results only) to send back.
#
# Safe to run again: each step checks first and skips what is done. A step that was done and must
# not run twice (the reminder email, the drills) is remembered in .m2-oneclick/state. A real error
# stops it with what happened and what to do; a check that fails (a drill, the deploy check) is
# reported, and the rest still runs.
#
# Credentials: the logins live in a folder of their own that only this run uses, and are revoked
# and deleted when it ends: nothing of them stays on your Mac, and your own gcloud setup is not
# touched. The script never prints, writes or logs a token. The audit log lock stays off (it waits
# for your confirmation, ruling R105).

# --- bash 4 or later. macOS starts this with bash 3.2: then it runs again under Homebrew's bash.
# This part is plain on purpose, so that bash 3.2 can run it.
if [ -z "${BASH_VERSINFO:-}" ] || [ "${BASH_VERSINFO[0]}" -lt 4 ]; then
  if ! command -v brew >/dev/null 2>&1; then
    for candidate in /opt/homebrew/bin/brew /usr/local/bin/brew; do
      if [ -x "$candidate" ]; then
        eval "$("$candidate" shellenv)"
        break
      fi
    done
  fi
  if ! command -v brew >/dev/null 2>&1; then
    echo "This needs Homebrew (https://brew.sh). Install it, then run this script again." >&2
    exit 1
  fi
  newer_bash="$(brew --prefix)/bin/bash"
  if [ ! -x "$newer_bash" ]; then
    echo "Installing a current bash with Homebrew (macOS's own is too old for this script)..."
    brew install bash || exit 1
  fi
  exec "$newer_bash" "$0" "$@"
fi

set -Eeuo pipefail

TF_VERSION="1.16.4"
TF_SHA256_darwin_arm64="42cfdf97ad722f79085fe2279b06d4b8680172de3534b22eeddd9a0fbbe7b8f1"
TF_SHA256_darwin_amd64="2ee4b62064086e4b24b0d6cf2e61718fbaf0556feba990f708a5e32557554b3b"
REGION="europe-west4"
BOOTSTRAP_APIS="serviceusage.googleapis.com cloudresourcemanager.googleapis.com orgpolicy.googleapis.com storage.googleapis.com"
DRILL_TOPIC="budget-stop-drill"

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TFDIR="$REPO/infra/terraform"
WORK="$REPO/.m2-oneclick"
LOG="$WORK/run.log"
STATE="$WORK/state"
RESULT="$REPO/m2-result.txt"

DRY_RUN=0
for argument in "$@"; do
  case "$argument" in
    --dry-run) DRY_RUN=1 ;;
    -h | --help)
      awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"
      exit 0
      ;;
    *)
      echo "Unknown option: $argument (use --dry-run, or nothing)" >&2
      exit 2
      ;;
  esac
done

mkdir -p "$WORK/plugin-cache"
export TF_PLUGIN_CACHE_DIR="$WORK/plugin-cache" TF_IN_AUTOMATION=1
: >"$LOG"
touch "$STATE"
cd "$REPO"

RESULTS=()       # one line per step: PASS, FAIL, MANUAL, NOTE or SKIP, a name and a detail
TF=""            # the terraform to use
ACCOUNT=""       # who logged in
DRIVE_SCOPE="no" # whether Terraform's login (ADC) holds the Drive scope
GCLOUD_HOME=""   # the folder of this run's logins
EMAILS="not asked"
STOP_AMOUNT=""   # budget aiven-stop, a whole amount (variables.tf)
APPLIED="no"     # whether this run applied, or found nothing to apply
SANDBOX_BY_HAND=0
STARTED="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# --- output, the report, and stopping

say() { printf '%s\n' "$*"; }
step() { printf '\n== %s\n' "$*"; }
record() { # record STATUS NAME DETAIL
  RESULTS+=("$1 $2: $3")
  printf '   %s %s: %s\n' "$1" "$2" "$3"
}

state_get() { grep -E "^$1=" "$STATE" 2>/dev/null | tail -n 1 | cut -d= -f2- || true; }
state_set() {
  grep -vE "^$1=" "$STATE" >"$STATE.new" 2>/dev/null || true
  printf '%s=%s\n' "$1" "$2" >>"$STATE.new"
  mv "$STATE.new" "$STATE"
}

# Run a command with its output in the run log only.
logged() {
  printf '\n$ %s\n' "$*" >>"$LOG"
  "$@" >>"$LOG" 2>&1
}
show_log_tail() {
  say "   Its last lines (all of it is in .m2-oneclick/run.log):"
  tail -n 12 "$LOG" | sed 's/^/     | /'
}
# The same, and on failure show its last lines.
quietly() {
  if logged "$@"; then
    return 0
  else
    local status=$?
    show_log_tail
    return "$status"
  fi
}

STOPPED=""
fail() { # fail "what happened" "what to do"
  STOPPED="$1"
  printf '\nSTOPPED: %s\n' "$1" >&2
  printf 'What to do: %s\n' "$2" >&2
  printf 'Then run the script again; it continues where it stopped.\n' >&2
  RESULTS+=("FAIL stopped: $1. What to do: $2")
  exit 3
}

on_error() {
  STOPPED="unexpected error at line $1 ($2)"
  RESULTS+=("FAIL stopped: unexpected error at line $1 ($2)")
  printf '\nSTOPPED: an unexpected error at line %s: %s\n' "$1" "$2" >&2
  printf 'What to do: run the script again. If it stops here again, send m2-result.txt and .m2-oneclick/run.log.\n' >&2
}
trap 'on_error "$LINENO" "$BASH_COMMAND"' ERR

helper() { uv run --frozen --quiet python -m aiven.m2_oneclick "$@"; }

write_result() {
  local text line
  text="M2 one-click result
Written: $(date -u +%Y-%m-%dT%H:%M:%SZ) (run started $STARTED)
Mode: $([[ $DRY_RUN == 1 ]] && echo "dry run (nothing applied)" || echo "full run")
Commit: $(git -C "$REPO" rev-parse --short HEAD 2>/dev/null || echo unknown)
Account: ${ACCOUNT:-not logged in}
Projects: agents ${V_agents_project:-?}, gateway ${V_gateway_project:-?}, control ${V_control_project:-?}, scratch ${V_scratch_project:-?}
Billing account: ${V_billing_account:-?} (${V_budget_currency:-?})
Alert address: ${V_alert_email:-?}
Sandbox drive: ${V_sandbox_drive_id:-not set}
Alert emails received: $EMAILS
"
  if [[ -n $STOPPED ]]; then
    text+="
Stopped: $STOPPED
"
  fi
  text+="
Steps:
"
  for line in "${RESULTS[@]+"${RESULTS[@]}"}"; do
    text+="  $line
"
  done
  if [[ -f "$WORK/plan-summary.txt" ]]; then
    text+="
Plan summary:
$(cat "$WORK/plan-summary.txt")
"
  fi
  if [[ -f "$WORK/deploy-check.txt" ]]; then
    text+="
aiven-deploy-check all:
$(cat "$WORK/deploy-check.txt")
"
  fi
  if ! printf '%s' "$text" | helper result-write "$RESULT" 2>>"$LOG"; then
    printf '%s' "$text" >"$RESULT" # the helper did not run: the text holds IDs and results only
  fi
}

revoke_logins() {
  if [[ -n $GCLOUD_HOME && -d $GCLOUD_HOME && $GCLOUD_HOME == */aiven-m2-gcloud.* ]]; then
    gcloud auth application-default revoke --quiet >/dev/null 2>&1 || true
    gcloud auth revoke --all --quiet >/dev/null 2>&1 || true
    rm -rf "$GCLOUD_HOME"
  fi
}

on_exit() {
  local status=$?
  trap - ERR
  revoke_logins
  write_result || true
  if [[ $status -ne 0 ]]; then
    printf '\nThe report so far is in m2-result.txt. The full log is .m2-oneclick/run.log.\n' >&2
  fi
}
trap on_exit EXIT

# --- 1. the tools

need_brew() {
  if ! command -v brew >/dev/null 2>&1; then
    fail "Homebrew is not installed" "install it from https://brew.sh"
  fi
}

terraform_ok() { [[ "$("$1" version 2>/dev/null | head -n 1)" == "Terraform v$TF_VERSION" ]]; }

install_terraform() {
  local arch zip sha got
  case "$(uname -m)" in
    arm64) arch="darwin_arm64" sha="$TF_SHA256_darwin_arm64" ;;
    x86_64) arch="darwin_amd64" sha="$TF_SHA256_darwin_amd64" ;;
    *) fail "this Mac's processor ($(uname -m)) is not one the runbook lists" "send the line above" ;;
  esac
  zip="terraform_${TF_VERSION}_${arch}.zip"
  mkdir -p "$WORK/download" "$WORK/bin"
  say "   Downloading Terraform $TF_VERSION and checking its SHA-256..."
  if ! quietly curl -fsSLo "$WORK/download/$zip" "https://releases.hashicorp.com/terraform/$TF_VERSION/$zip"; then
    fail "Terraform could not be downloaded" "check the internet connection"
  fi
  got="$(shasum -a 256 "$WORK/download/$zip" | cut -d' ' -f1)"
  if [[ $got != "$sha" ]]; then
    rm -f "$WORK/download/$zip"
    fail "the Terraform download does not have the SHA-256 of the runbook, so it was thrown away" \
      "run again; if it happens again, do not install it by hand, and tell Claude"
  fi
  quietly unzip -o -q "$WORK/download/$zip" terraform -d "$WORK/bin"
  chmod +x "$WORK/bin/terraform"
}

check_tools() {
  step "1. Tools"
  if [[ "$(uname -s)" != "Darwin" ]]; then
    fail "this script is for macOS" "run it on your Mac"
  fi
  if ! command -v gcloud >/dev/null 2>&1; then
    need_brew
    say "   Installing the gcloud CLI with Homebrew..."
    quietly brew install --cask gcloud-cli || quietly brew install --cask google-cloud-sdk ||
      fail "the gcloud CLI could not be installed" "run: brew install --cask gcloud-cli"
  fi
  if ! command -v uv >/dev/null 2>&1; then
    need_brew
    say "   Installing uv with Homebrew..."
    quietly brew install uv || fail "uv could not be installed" "run: brew install uv"
  fi
  hash -r
  if command -v terraform >/dev/null 2>&1 && terraform_ok terraform; then
    TF="$(command -v terraform)"
  elif [[ -x "$WORK/bin/terraform" ]] && terraform_ok "$WORK/bin/terraform"; then
    TF="$WORK/bin/terraform"
  else
    install_terraform
    TF="$WORK/bin/terraform"
    terraform_ok "$TF" || fail "the downloaded Terraform does not run" "send .m2-oneclick/run.log"
  fi
  if ! quietly uv sync --frozen; then
    fail "the Python tools of the repository could not be installed" "check the internet connection"
  fi
  record PASS tools "gcloud, uv, Terraform $TF_VERSION ($TF)"
}

# --- 2. the logins, in a folder of this run's own

login() {
  step "2. Log in (twice, in the browser)"
  GCLOUD_HOME="$(mktemp -d "${TMPDIR:-/tmp}/aiven-m2-gcloud.XXXXXX")"
  export CLOUDSDK_CONFIG="$GCLOUD_HOME"
  export GOOGLE_APPLICATION_CREDENTIALS="$GCLOUD_HOME/application_default_credentials.json"
  say "   First login: gcloud, for the setup commands. Use your @aivenstudios.com account."
  if ! gcloud auth login --quiet; then
    fail "the gcloud login did not finish" "run again, and finish the login in the browser"
  fi
  ACCOUNT="$(gcloud config get-value account 2>/dev/null || true)"
  if [[ $ACCOUNT != *@aivenstudios.com ]]; then
    fail "you logged in as ${ACCOUNT:-nobody}, not with an @aivenstudios.com account" \
      "run again, and pick your AIVEN account in the browser"
  fi
  say "   Second login: Terraform's, with the Drive scope (for the Sandbox drive and its checks)."
  if gcloud auth application-default login --quiet \
    --scopes=https://www.googleapis.com/auth/cloud-platform,https://www.googleapis.com/auth/drive; then
    DRIVE_SCOPE="yes"
  else
    say "   Google did not give the Drive scope. Once more, without it: the Sandbox then takes one step by hand."
    if ! gcloud auth application-default login --quiet \
      --scopes=https://www.googleapis.com/auth/cloud-platform; then
      fail "Terraform's login did not finish" "run again, and finish both logins in the browser"
    fi
  fi
  record PASS login "$ACCOUNT (Drive scope: $DRIVE_SCOPE); revoked when the script ends"
}

# --- 3. the values: IDs and addresses only

V_agents_project="" V_gateway_project="" V_control_project="" V_scratch_project=""
V_billing_account="" V_budget_currency="" V_alert_email="" V_agents="" V_trusted_authors=""
V_sandbox_drive_id="" ORG=""

is_project() { [[ $1 =~ ^[a-z][a-z0-9-]{4,28}[a-z0-9]$ ]]; }
is_billing() { [[ $1 =~ ^[0-9A-F]{6}-[0-9A-F]{6}-[0-9A-F]{6}$ ]]; }
is_currency() { [[ $1 == EUR || $1 == USD ]]; }
is_aiven_address() { [[ $1 =~ ^[a-z0-9._%+-]+@aivenstudios\.com$ ]]; }
is_drive_or_empty() { [[ -z $1 || $1 =~ ^[A-Za-z0-9_-]{10,100}$ ]]; }
is_org() { [[ $1 =~ ^[0-9]{1,20}$ ]]; }
project_exists() { gcloud projects describe "$1" --format='value(projectId)' >/dev/null 2>>"$LOG"; }
is_reachable_project() { is_project "$1" && project_exists "$1"; }

# ask NAME "question" "default" check "what it must be"
ask() {
  local name="$1" question="$2" default="$3" check="$4" shape="$5" answer prompt
  while true; do
    prompt="   $question"
    [[ -n $default ]] && prompt+=" [$default]"
    if ! read -r -p "$prompt: " answer; then
      fail "no answer to \"$question\"" "run the script in a terminal"
    fi
    answer="${answer:-$default}"
    answer="${answer//[[:space:]]/}"
    if "$check" "$answer"; then
      printf -v "$name" '%s' "$answer"
      return 0
    fi
    say "   That is not $shape. Try again."
  done
}

suggest_project() { # the one project of yours whose ID holds the word, if there is exactly one
  local found
  found="$(gcloud projects list --format='value(projectId)' 2>>"$LOG" | grep -- "$1" || true)"
  if [[ -n $found && $(printf '%s\n' "$found" | wc -l) -eq 1 ]]; then
    printf '%s' "$found"
  fi
}

values() {
  step "3. The values (IDs and addresses only)"
  local key value asked=0 role var
  if ! helper values-read >"$WORK/values.txt" 2>"$WORK/values.err"; then
    cat "$WORK/values.err" >&2
    fail "the values files do not pass the check above" \
      "fix the lines it names (or delete the file to be asked again)"
  fi
  while IFS='=' read -r key value; do
    printf -v "V_$key" '%s' "$value"
  done <"$WORK/values.txt"

  for role in agents gateway control scratch; do
    var="V_${role}_project"
    if [[ -z ${!var} ]]; then
      ask "$var" "Project ID of $role" "$(suggest_project "$role")" is_reachable_project \
        "the ID of a project that your account can see"
      asked=1
    fi
  done
  if [[ $(printf '%s\n' "$V_agents_project" "$V_gateway_project" "$V_control_project" "$V_scratch_project" | sort -u | wc -l) -ne 4 ]]; then
    fail "the four project IDs are not four different projects" \
      "fix them in infra/terraform/terraform.tfvars (or delete it to be asked again)"
  fi
  if [[ -z $V_billing_account ]]; then
    local linked
    linked="$(gcloud billing projects describe "$V_control_project" --format='value(billingAccountName)' 2>>"$LOG" || true)"
    ask V_billing_account "Billing account ID" "${linked#billingAccounts/}" is_billing \
      "XXXXXX-XXXXXX-XXXXXX (0 to 9 and A to F)"
    asked=1
  fi
  if [[ -z $V_budget_currency ]]; then
    local currency
    currency="$(gcloud billing accounts describe "$V_billing_account" --format='value(currencyCode)' 2>>"$LOG" || true)"
    ask V_budget_currency "Currency of the billing account (EUR or USD)" "$currency" is_currency "EUR or USD"
    asked=1
  fi
  if [[ -z $V_alert_email ]]; then
    ask V_alert_email "Address for the alerts" "$ACCOUNT" is_aiven_address "an @aivenstudios.com address"
    asked=1
  fi
  if [[ -z $V_sandbox_drive_id ]]; then
    say "   The Sandbox drive ID is the last part of its address in Drive (drive/folders/<ID>)."
    ask V_sandbox_drive_id "Sandbox drive ID (Enter: not yet)" "" is_drive_or_empty \
      "a drive ID (10 to 100 letters, digits, _ and -)"
    asked=1
  fi
  [[ -n $V_trusted_authors ]] || V_trusted_authors="$ACCOUNT"
  [[ -n $V_agents ]] || V_agents="invoice-reminder"

  if [[ $asked == 1 || ! -f config/platform.yaml || ! -f infra/terraform/terraform.tfvars ]]; then
    local pairs=(
      "agents_project=$V_agents_project" "gateway_project=$V_gateway_project"
      "control_project=$V_control_project" "scratch_project=$V_scratch_project"
      "billing_account=$V_billing_account" "budget_currency=$V_budget_currency"
      "alert_email=$V_alert_email" "agents=$V_agents" "trusted_authors=$V_trusted_authors"
    )
    [[ -n $V_sandbox_drive_id ]] && pairs+=("sandbox_drive_id=$V_sandbox_drive_id")
    if ! helper values-write "${pairs[@]}" 2>"$WORK/values.err"; then
      cat "$WORK/values.err" >&2
      fail "the values were not written: the check above refused them" "run again, and give the IDs again"
    fi
    say "   Written: config/platform.yaml and infra/terraform/terraform.tfvars."
  fi
  if ! quietly uv run --frozen --quiet aiven-check-config; then
    fail "aiven-check-config refuses the values files" "fix the lines it names above"
  fi
  STOP_AMOUNT="$(sed -nE 's/^budget_stop_amount *= *([0-9]+).*/\1/p' infra/terraform/terraform.tfvars)"
  if ! [[ $STOP_AMOUNT =~ ^[0-9]+$ ]]; then
    fail "budget_stop_amount in infra/terraform/terraform.tfvars is not a whole amount" "make it 25 (EUR) or 27 (USD)"
  fi

  ORG="$(gcloud projects get-ancestors "$V_control_project" --format='value(id,type)' 2>>"$LOG" | awk '$2 == "organization" {print $1}' || true)"
  if [[ -z $ORG ]]; then
    ask ORG "Organisation ID (gcloud organizations list)" "" is_org "a number"
  fi
  record PASS values "checked with aiven-check-config; organisation $ORG"
}

# --- 4. Organization Policy Administrator, and the bootstrap of the control project

org_policy_admin() {
  step "4. Organization Policy Administrator for $ACCOUNT"
  local has
  has="$(gcloud organizations get-iam-policy "$ORG" --flatten='bindings[].members' \
    --filter="bindings.role=roles/orgpolicy.policyAdmin AND bindings.members=\"user:$ACCOUNT\"" \
    --format='value(bindings.role)' 2>>"$LOG" || true)"
  if [[ -n $has ]]; then
    record PASS org-policy-admin "you have it already"
  elif [[ $DRY_RUN == 1 ]]; then
    record NOTE org-policy-admin "you do not have it yet: a full run grants it"
  elif quietly gcloud organizations add-iam-policy-binding "$ORG" --member="user:$ACCOUNT" \
    --role=roles/orgpolicy.policyAdmin --condition=None --quiet; then
    record PASS org-policy-admin "granted"
  else
    # You may hold it through a group, which this check does not see. If not, the apply stops at
    # the first organisation policy, before anything else is made, and says so.
    record NOTE org-policy-admin "could not grant it; if the apply stops at an organisation policy, grant it as Workspace super admin (console.cloud.google.com > IAM, the organisation) and run again"
  fi
}

STATE_BUCKET_READY=0
bootstrap() {
  step "5. Bootstrap of the control project $V_control_project"
  local control="$V_control_project" enabled missing="" api where
  enabled="$(gcloud services list --enabled --project="$control" --format='value(config.name)' 2>>"$LOG" || true)"
  for api in $BOOTSTRAP_APIS; do
    grep -qx "$api" <<<"$enabled" || missing+=" $api"
  done
  if [[ -z $missing ]]; then
    record PASS bootstrap-apis "the 4 APIs are on"
  elif [[ $DRY_RUN == 1 ]]; then
    record NOTE bootstrap-apis "a full run turns on:$missing"
  else
    # shellcheck disable=SC2086 # one word per API
    quietly gcloud services enable $missing --project="$control" ||
      fail "the APIs could not be turned on in $control" "check that billing is linked to $control"
    record PASS bootstrap-apis "turned on:$missing"
  fi
  where="$(gcloud storage buckets describe "gs://$control-tfstate" --format='value(location,versioning_enabled)' 2>>"$LOG" || true)"
  if [[ -z $where && $DRY_RUN == 1 ]]; then
    record NOTE state-bucket "gs://$control-tfstate does not exist yet: a full run makes it"
    return 0
  fi
  if [[ -z $where ]]; then
    quietly gcloud storage buckets create "gs://$control-tfstate" --project="$control" \
      --location="$REGION" --uniform-bucket-level-access --public-access-prevention ||
      fail "the state bucket gs://$control-tfstate could not be made" \
        "if the log says the name is taken, the bucket belongs to another project: tell Claude"
  fi
  if [[ $DRY_RUN != 1 ]]; then
    quietly gcloud storage buckets update "gs://$control-tfstate" --versioning ||
      fail "versioning could not be turned on for gs://$control-tfstate" "see the log lines above"
  fi
  where="$(gcloud storage buckets describe "gs://$control-tfstate" --format='value(location,versioning_enabled)' 2>>"$LOG" || true)"
  if [[ $where != EUROPE-WEST4*True && $DRY_RUN != 1 ]]; then
    fail "gs://$control-tfstate is not in europe-west4 with versioning on ($where)" \
      "tell Claude: the state bucket must be europe-west4 and versioned"
  fi
  STATE_BUCKET_READY=1
  record PASS state-bucket "gs://$control-tfstate, europe-west4, versioned"
}

# --- 6. terraform init and plan, the summary, and the one question

TFRUN="$TFDIR"
tf() { "$TF" -chdir="$TFRUN" "$@"; }

explain_terraform() { # a plain-English hint for the errors that the runbook names
  local tail
  tail="$(tail -n 60 "$LOG")"
  case "$tail" in
    *orgpolicy.policies.create*) say "   Hint: Organization Policy Administrator is missing (runbook part 2)." ;;
    *billing.budgets* | *billingbudgets*) say "   Hint: budgets need Billing Account Administrator on $V_billing_account." ;;
    *SERVICE_DISABLED* | *"has not been used in project"*) say "   Hint: an API was only just turned on; wait 5 minutes." ;;
    *"Error acquiring the state lock"*) say "   Hint: another Terraform run holds the lock; wait for it to end." ;;
    *"Build failed"* | *"build failed"*) say "   Hint: the function build failed; send m2-result.txt and .m2-oneclick/run.log to Claude (the builder's roles, ruling R134)." ;;
  esac
}

init_terraform() {
  if [[ $DRY_RUN == 1 && $STATE_BUCKET_READY != 1 ]]; then
    # No state bucket yet: plan a copy with a local, empty state. Nothing is written in Google.
    local copy="$WORK/dry-run"
    rm -rf "${copy:?}"
    mkdir -p "$copy/infra/terraform"
    cp "$TFDIR"/*.tf "$TFDIR/.terraform.lock.hcl" "$TFDIR/terraform.tfvars" "$copy/infra/terraform/"
    cp -R "$TFDIR/modules" "$copy/infra/terraform/"
    ln -s "$REPO/src" "$copy/src"
    printf 'terraform {\n  backend "local" {}\n}\n' >"$copy/infra/terraform/backend_override.tf"
    TFRUN="$copy/infra/terraform"
    quietly tf init -input=false -lockfile=readonly ||
      fail "terraform init failed" "check the internet connection (it downloads the providers)"
  else
    quietly tf init -input=false -reconfigure -lockfile=readonly \
      -backend-config="bucket=$V_control_project-tfstate" -backend-config="prefix=aiven" ||
      fail "terraform init failed" "check the internet connection and the state bucket"
  fi
}

# plan NAME [terraform options]: 0 no changes, 2 changes; stops on an error
plan() {
  local name="$1" status=0
  shift
  local options=(-input=false -lock-timeout=120s "-out=$WORK/$name.tfplan" -detailed-exitcode)
  [[ $DRY_RUN == 1 ]] && options+=(-lock=false)
  logged tf plan "${options[@]}" "$@" || status=$?
  if [[ $status -ne 0 && $status -ne 2 ]]; then
    show_log_tail
    explain_terraform
    fail "terraform plan failed" "read the lines above; the whole output is in .m2-oneclick/run.log"
  fi
  tf show -json "$WORK/$name.tfplan" >"$WORK/$name.json" 2>>"$LOG" ||
    fail "the plan could not be read back (terraform show)" "send .m2-oneclick/run.log to Claude"
  return "$status"
}

apply() { # apply NAME
  if ! tf apply -input=false "$WORK/$1.tfplan" 2>&1 | tee -a "$LOG"; then
    explain_terraform
    fail "terraform apply stopped with an error" \
      "read the lines above; what was made stays, and the next run continues from there"
  fi
}

plan_and_ask() {
  step "6. Terraform: init, plan, and your one question"
  init_terraform
  local status=0 summary=0
  plan m2 || status=$?
  helper plan-summary "$WORK/m2.json" --mode main >"$WORK/plan-summary.txt" || summary=$?
  sed 's/^/   /' "$WORK/plan-summary.txt"
  if [[ $summary -eq 3 ]]; then
    fail "the plan holds something the runbook forbids (see NOT TO BE APPLIED)" "tell Claude; do not apply it by hand"
  elif [[ $summary -ne 0 ]]; then
    fail "the plan could not be summarised" "send .m2-oneclick/run.log to Claude"
  fi
  if [[ $DRY_RUN == 1 ]]; then
    record PASS plan "dry run: planned, nothing applied"
    return 0
  fi
  if [[ $status -eq 0 ]]; then
    APPLIED="nothing to change"
    record PASS apply "nothing to change: the projects match the code"
    return 0
  fi
  local answer=""
  read -r -p $'\n   Apply? (y/n) ' answer || true
  if [[ $answer != y && $answer != Y && $answer != yes ]]; then
    record SKIP apply "you answered no: nothing applied (the bootstrap aside)"
    report
    exit 0
  fi
  apply m2
  APPLIED="yes"
  record PASS apply "applied"
}

# --- 7. after the apply: the reminder, the drills, the Sandbox, the deploy check

now() { date -u +%Y-%m-%dT%H:%M:%SZ; }

audit_entries() { # audit_entries FILTER SINCE: the timestamps of matching audit entries
  gcloud logging read "logName=\"projects/$V_control_project/logs/aiven-audit\" AND $1 AND timestamp>=\"$2\"" \
    --project="$V_control_project" --bucket=aiven-audit --location="$REGION" --view=_AllLogs \
    --format='value(timestamp)' 2>>"$LOG" || true
}

drill_log() { # drill_log OUTCOME SINCE: the timestamps of the drill function's lines with it
  gcloud logging read "resource.type=\"cloud_run_revision\" AND resource.labels.service_name=\"budget-stop-drill\" AND jsonPayload.outcome=\"$1\" AND timestamp>=\"$2\"" \
    --project="$V_control_project" --format='value(timestamp)' 2>>"$LOG" || true
}

billing_on() { [[ "$(gcloud billing projects describe "$1" --format='value(billingEnabled)' 2>>"$LOG" || true)" == True ]]; }
billing_off() { ! billing_on "$1"; }
has_audit() { [[ -n "$(audit_entries "$1" "$2")" ]]; }      # has_audit FILTER SINCE
has_drill_log() { [[ -n "$(drill_log "$1" "$2")" ]]; }     # has_drill_log OUTCOME SINCE

# wait_until SECONDS INTERVAL command...: 0 when the command succeeds in time
wait_until() {
  local limit="$1" every="$2" start
  shift 2
  start="$(date +%s)"
  while true; do
    if "$@"; then return 0; fi
    if (($(date +%s) - start >= limit)); then return 1; fi
    sleep "$every"
  done
}

reminder() {
  step "7. The credit reminder, run by hand (the alert path)"
  if [[ "$(state_get reminder)" == PASS* ]]; then
    record PASS credit-reminder "done before ($(state_get reminder | cut -d' ' -f2-)); not run again, so no second email"
    return 0
  fi
  local since
  since="$(now)"
  if ! quietly gcloud scheduler jobs run credit-reminder --location="$REGION" --project="$V_control_project"; then
    record FAIL credit-reminder "Cloud Scheduler could not start the job"
    return 0
  fi
  say "   Waiting for its audit entry (up to 5 minutes)..."
  if wait_until 300 15 has_audit 'jsonPayload.reason="CREDIT_EXPIRY"' "$since"; then
    record PASS credit-reminder "audit entry written; the email should arrive at $V_alert_email"
    state_set reminder "PASS $(now)"
  else
    record FAIL credit-reminder "no audit entry within 5 minutes (gcloud functions logs read credit-reminder --region=$REGION --project=$V_control_project)"
  fi
}

publish() { # publish AMOUNT: a budget notification on the drill's topic, and only that one
  local message
  message="{\"budgetDisplayName\":\"aiven-stop\",\"costAmount\":$1,\"budgetAmount\":$STOP_AMOUNT,\"currencyCode\":\"$V_budget_currency\"}"
  quietly gcloud pubsub topics publish "$DRILL_TOPIC" --project="$V_control_project" --message="$message"
}

relink_scratch() {
  billing_on "$V_scratch_project" && return 0
  quietly gcloud billing projects link "$V_scratch_project" --billing-account="$V_billing_account" &&
    wait_until 120 10 billing_on "$V_scratch_project"
}

real_projects_on() { billing_on "$V_agents_project" && billing_on "$V_gateway_project"; }

drill_switch() { # drill_switch on|off: plan, check that it holds the drill only, apply
  local status=0 summary=0 value
  [[ $1 == on ]] && value=true || value=false
  plan "drill-$1" "-var=budget_stop_drill=$value" || status=$?
  helper plan-summary "$WORK/drill-$1.json" --mode "drill-$1" --scratch "$V_scratch_project" >"$WORK/drill-$1.txt" || summary=$?
  sed 's/^/   /' "$WORK/drill-$1.txt"
  if [[ $summary -ne 0 ]]; then
    fail "the plan to switch the drill $1 holds more than the drill, so it was not applied" \
      "tell Claude, and send m2-result.txt"
  fi
  [[ $status -eq 2 ]] && apply "drill-$1"
  return 0
}

DRILL_FAILED=""
drill_check() { # drill_check NAME DETAIL command...: record PASS or FAIL; a FAIL ends the drill
  local name="$1" detail="$2"
  shift 2
  if [[ -n $DRILL_FAILED ]]; then return 1; fi
  if "$@"; then
    record PASS "$name" "$detail"
  else
    record FAIL "$name" "not so: $detail"
    DRILL_FAILED="$name"
    return 1
  fi
}

drills() {
  step "8. Drills BD-1 and BD-2, on the scratch project $V_scratch_project only"
  if [[ "$(state_get drills)" == PASS* ]]; then
    record PASS drills "passed before ($(state_get drills | cut -d' ' -f2-)); not run again"
    return 0
  fi
  local over="$STOP_AMOUNT.01" under="$((STOP_AMOUNT - 1)).99" since start seconds
  if ! real_projects_on; then
    fail "billing is off on the agents or gateway project before the drill" \
      "link billing again (runbook budget-stop.md, Restart, step 4)"
  fi
  if ! relink_scratch; then
    record FAIL drills "billing could not be linked to the scratch project $V_scratch_project (you need Billing Account User on $V_billing_account); drills not run"
    return 0
  fi
  say "   Switching on the drill's copy of the budget stop (it stops $V_scratch_project only)..."
  drill_switch on

  # BD-1: a notification at the stop amount unlinks the scratch project within 5 minutes.
  since="$(now)"
  start="$(date +%s)"
  publish "$over"
  say "   BD-1: published $over $V_budget_currency; waiting for the unlink (up to 5 minutes)..."
  if wait_until 300 10 billing_off "$V_scratch_project"; then
    seconds="$(($(date +%s) - start))"
    record PASS bd1-unlink "billing of $V_scratch_project unlinked ${seconds}s after publishing"
  else
    record FAIL bd1-unlink "billing of $V_scratch_project still on 5 minutes after publishing"
    DRILL_FAILED="bd1-unlink"
  fi
  drill_check bd1-audit "a budget_stop audit entry" \
    wait_until 180 15 has_audit 'jsonPayload.event="budget_stop"' "$since" || true
  drill_check bd1-real-projects "billing of the agents and gateway projects still on" real_projects_on || true

  # BD-2, with billing on the scratch project linked again.
  if [[ -z $DRILL_FAILED ]]; then
    drill_check bd2-relink "billing of $V_scratch_project linked again" relink_scratch || true
  fi
  if [[ -z $DRILL_FAILED ]]; then
    since="$(now)"
    publish "$under"
    drill_check bd2-below "at $under the function logs below" wait_until 240 15 has_drill_log below "$since" || true
    drill_check bd2-below-billing "billing stays on" billing_on "$V_scratch_project" || true
  fi
  if [[ -z $DRILL_FAILED ]]; then
    quietly gcloud run services update budget-stop-drill --region="$REGION" --project="$V_control_project" \
      --update-env-vars=STOP_ENABLED=false --quiet || DRILL_FAILED="bd2-switch-off"
    since="$(now)"
    [[ -z $DRILL_FAILED ]] && publish "$over"
    drill_check bd2-disabled "switched off, the function logs disabled" wait_until 240 15 has_drill_log disabled "$since" || true
    drill_check bd2-disabled-billing "billing stays on" billing_on "$V_scratch_project" || true
    quietly gcloud run services update budget-stop-drill --region="$REGION" --project="$V_control_project" \
      --update-env-vars=STOP_ENABLED=true --quiet || DRILL_FAILED="${DRILL_FAILED:-bd2-switch-on}"
  fi
  if [[ -z $DRILL_FAILED ]]; then
    since="$(now)"
    publish "$over"
    drill_check bd2-first "the first notification unlinks again" \
      wait_until 300 10 billing_off "$V_scratch_project" || true
    if [[ -z $DRILL_FAILED ]]; then
      publish "$over"
      drill_check bd2-second "the second logs already_stopped" wait_until 240 15 has_drill_log already_stopped "$since" || true
      sleep 60 # the audit log takes a moment
      drill_check bd2-one-entry "one budget_stop audit entry for the two" \
        test "$(audit_entries 'jsonPayload.event="budget_stop"' "$since" | grep -c . || true)" -eq 1 || true
    fi
  fi

  say "   Putting it back: billing on $V_scratch_project, and the drill's copy removed..."
  if ! relink_scratch; then
    record FAIL scratch-billing "not linked again; run: gcloud billing projects link $V_scratch_project --billing-account=$V_billing_account"
  fi
  drill_switch off
  if [[ -z $DRILL_FAILED ]]; then
    state_set drills "PASS $(now)"
    record PASS drills "BD-1 and BD-2 passed; scratch linked again, drill copy removed"
  else
    record FAIL drills "stopped at $DRILL_FAILED; scratch linked again, drill copy removed"
  fi
}

sandbox() {
  step "9. The gateway as Contributor of the Sandbox drive"
  local member="gateway@$V_gateway_project.iam.gserviceaccount.com" line status=0
  local by_hand="In Google Drive, open Shared drives > AIVEN Architecture Sandbox > Manage members, add $member as Contributor, untick Notify people, and Share."
  SANDBOX_BY_HAND=1
  if [[ -z $V_sandbox_drive_id ]]; then
    record MANUAL sandbox-member "no sandbox_drive_id yet (setup step S5): make the drive, then run again and give its ID"
  elif [[ $DRIVE_SCOPE != yes ]]; then
    record MANUAL sandbox-member "$by_hand"
  else
    line="$(helper drive-member --drive "$V_sandbox_drive_id" --member "$member" --quota-project "$V_gateway_project" 2>>"$LOG")" || status=$?
    if [[ $status -eq 0 || $status -eq 1 || $status -eq 3 ]] && [[ -n $line ]]; then
      record "${line%% *}" sandbox-member "${line#*: }"
      [[ $status -eq 0 ]] && SANDBOX_BY_HAND=0
    else
      record FAIL sandbox-member "the Drive call could not run (see .m2-oneclick/run.log). $by_hand"
    fi
  fi
}

deploy_check() {
  step "10. aiven-deploy-check all"
  local status=0 failed noted passed
  uv run --frozen --quiet aiven-deploy-check all >"$WORK/deploy-check.txt" 2>&1 || status=$?
  sed 's/^/   /' "$WORK/deploy-check.txt"
  passed="$(grep -c '^PASS' "$WORK/deploy-check.txt" || true)"
  failed="$(grep -c '^FAIL' "$WORK/deploy-check.txt" || true)"
  noted="$(grep -c '^NOTE' "$WORK/deploy-check.txt" || true)"
  if [[ $status -eq 0 ]]; then
    record PASS deploy-check "$passed PASS, $noted NOTE (expected in M2: gateway service, audit lock, maybe the Firestore TTL)"
  elif [[ $status -eq 1 ]]; then
    local why="the FAIL lines are in m2-result.txt"
    [[ $SANDBOX_BY_HAND == 1 ]] && why+="; drive sandbox members passes once the gateway is added by hand"
    record FAIL deploy-check "$failed FAIL, $passed PASS, $noted NOTE ($why)"
  else
    record FAIL deploy-check "it could not run (exit $status)"
  fi
}

ask_emails() {
  local answer=""
  printf '\n'
  read -r -p "   Did the alert emails arrive at $V_alert_email (the credit reminder, and the drill's budget stop)? (y/n, Enter skips) " answer || true
  case "$answer" in
    y | Y | yes) EMAILS="yes" ;;
    n | N | no) EMAILS="no" ;;
    *) EMAILS="not answered" ;;
  esac
}

FAILED=0
report() {
  local line
  step "Report"
  FAILED=0
  for line in "${RESULTS[@]+"${RESULTS[@]}"}"; do
    say "   $line"
    [[ $line == FAIL* ]] && FAILED=$((FAILED + 1))
  done
  say ""
  if [[ $DRY_RUN == 1 ]]; then
    say "   Dry run: nothing was applied, and nothing changed in Google Cloud."
  elif [[ $APPLIED == no ]]; then
    say "   Not applied: nothing changed in the projects (the bootstrap aside)."
  elif [[ $FAILED -eq 0 ]]; then
    say "   M2 is applied and checked."
  else
    say "   M2 is applied; $FAILED step(s) failed (above)."
  fi
  say "   Send m2-result.txt to Claude. Commit config/platform.yaml and infra/terraform/terraform.tfvars"
  say "   (IDs and addresses only). The audit log lock stays off until you confirm it."
}

main() {
  say "AIVEN M2 one-click$([[ $DRY_RUN == 1 ]] && echo " (dry run: up to the plan)")"
  check_tools
  login
  values
  org_policy_admin
  bootstrap
  plan_and_ask
  if [[ $DRY_RUN == 0 ]]; then
    reminder
    drills
    sandbox
    deploy_check
    ask_emails
  fi
  report
  [[ $FAILED -eq 0 ]] || exit 1
}

# Run, unless a test sources this file to call its steps against the mock.
if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
  main
fi
