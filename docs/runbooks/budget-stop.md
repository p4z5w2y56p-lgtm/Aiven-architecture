# Runbook: budget hard stop and restart

## Budgets

| Budget | Amount (gross, before credits) | Does |
|---|---|---|
| `aiven-alert` | €10/month | Emails at 50 %, 90 % and 100 % |
| `aiven-stop` | €25/month | At 100 %, triggers the `budget-stop` function through Pub/Sub |

Both budgets cover the agents, gateway and control projects, and both are set to exclude all credits (`EXCLUDE_ALL_CREDITS`). While the promotional credit lasts (until 2027-01-04), it pays for usage, so net cost stays near zero. A budget that subtracted credits would never fire. If the billing account's currency is USD, use about $11 and $27.

## What happens at the stop

- **Trigger.** This month's gross cost reaches €25. Google's cost notifications arrive hours after the spending, so the real total can be higher.
- **Automatic action.** The `budget-stop` function unlinks billing from `aiven-agents` and `aiven-gateway`, writes a `budget_stop` audit entry and emails an alert.
- **Result.**
  - All agents and the gateway stop.
  - Google may delete some resources in those two projects.
  - The control project keeps running, so the audit log, snapshots, kill switch and control UI stay available.

## Restart

1. **Find the cause.** Open Billing, then Reports, grouped by project and service for this month, with credits excluded. Then look at the audit log around the time the cost jumped: `run_end` entries carry each run's cost estimate.
2. **Keep everything stopped.** Turn on the global kill switch in the control UI. It stays on until step 7.
3. **Stop the trigger from firing again.** While this month's gross cost is still at or above €25, the next notification will unlink billing again. Pick one of these, and write down which, because step 8 undoes it:
   - raise `aiven-stop` above this month's cost (Billing, then Budgets & alerts), or
   - switch the stop off: `budget_stop_enabled = false` in `infra/terraform/terraform.tfvars`,
     then `terraform apply`. The function then gets `STOP_ENABLED=false`.
4. **Relink billing.** You need Billing Account User on the billing account and Project Billing Manager on both projects.

   ```sh
   gcloud billing projects link <gateway-project> --billing-account=<BILLING_ACCOUNT_ID>
   gcloud billing projects link <agents-project> --billing-account=<BILLING_ACCOUNT_ID>
   ```

5. **Check what survived.** Run `gcloud run services describe gateway --region=europe-west4 --project=<gateway-project>`, then check the agents' Cloud Run jobs and the `gateway` Firestore database. Redeploy anything missing from Git. Pending R2 confirms may be gone; they would have expired anyway.
6. **Smoke test.** With a test agent in shadow mode, call `GET /v1/me`, start a run and make one R0 call. Then turn on that test agent's kill switch and check that its next call is refused.
7. **Reopen.** Turn the global kill switch off. In the control UI, choose Record event, then Budget restart, and note the cause, the fix and any budget change.
8. **Next month,** set `aiven-stop` back to €25, or `budget_stop_enabled` back to `true` (and apply), whichever you changed in step 3.

## Drill (test BD-1)

Don't drill on the real projects, because Google may delete resources. The drill uses a copy of the
function, `budget-stop-drill`, which listens to its own topic and stops the scratch project only.
The real budget stop stays on throughout.

1. Check that the scratch project is linked to the billing account (setup S1):
   `gcloud billing projects describe <scratch-project> --format="value(billingEnabled)"` prints
   `True`.
2. Set `budget_stop_drill = true` in `infra/terraform/terraform.tfvars`, then `terraform apply`.
   Terraform adds the topic and function `budget-stop-drill`, and lets `budget-stop` unlink the
   scratch project.
3. Publish a notification at the amount, and note the time:

   ```sh
   gcloud pubsub topics publish budget-stop-drill --project=<control-project> \
     --message='{"budgetDisplayName":"aiven-stop","costAmount":25.01,"budgetAmount":25,"currencyCode":"EUR"}'
   ```

   Use your currency, and its stop amount, if it is not EUR.
4. Pass when:
   - billing on the scratch project is unlinked within 5 minutes (the check of step 1 prints
     `False`);
   - the `budget_stop` audit entry is written:
     `gcloud logging read 'jsonPayload.event="budget_stop"' --project=<control-project> --bucket=aiven-audit --location=europe-west4 --view=_AllLogs --limit=1`;
   - the alert email arrives;
   - the real projects are untouched (their billing is still on).
5. **BD-2**, with billing on the scratch project linked again
   (`gcloud billing projects link <scratch-project> --billing-account=<BILLING_ACCOUNT_ID>`):
   - Publish `"costAmount":24.99`: the function logs `below`, and billing stays on.
   - Switch the copy off, `gcloud run services update budget-stop-drill --region=europe-west4 --project=<control-project> --update-env-vars=STOP_ENABLED=false`,
     and publish `"costAmount":25.01`: it logs `disabled`, and billing stays on. Switch it on
     again with `STOP_ENABLED=true`.
   - Publish `"costAmount":25.01` twice: the first unlinks billing and writes one audit entry; the
     second logs `already_stopped` and writes none.
   - The function's log lines: `gcloud functions logs read budget-stop-drill --region=europe-west4 --project=<control-project>`.
6. Link billing on the scratch project again, set `budget_stop_drill = false`, and
   `terraform apply`: the copy, its topic and its role on the scratch project are gone.

## Credit

- The account is paid since 2026-10-06. The remaining promotional credit (€252.56 then) expires on 2027-01-04, and an alert on 2026-12-20 is the reminder.
- After that, all usage is billed. The budgets already count gross cost, so when they fire doesn't change.
