# Runbook: budget hard stop and restart

## Budgets

| Budget | Amount (gross, before credits) | Does |
|---|---|---|
| `aiven-alert` | €10/month | Emails at 50 %, 90 % and 100 % |
| `aiven-stop` | €25/month | At 100 %, triggers the `budget-stop` function through Pub/Sub |

Both budgets cover the agents, gateway and control projects, and both are set to exclude all credits (`EXCLUDE_ALL_CREDITS`). On the free trial the credit pays for usage, so net cost stays near zero. A budget that subtracted credits would never fire. If the billing account's currency is USD, use about $11 and $27.

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
   - set the function's `STOP_ENABLED` variable to `false`.
4. **Relink billing.** You need Billing Account User on the billing account and Project Billing Manager on both projects.

   ```sh
   gcloud billing projects link <gateway-project> --billing-account=<BILLING_ACCOUNT_ID>
   gcloud billing projects link <agents-project> --billing-account=<BILLING_ACCOUNT_ID>
   ```

5. **Check what survived.** Run `gcloud run services describe gateway --region=europe-west4 --project=<gateway-project>`, then check the agents' Cloud Run jobs and the `gateway` Firestore database. Redeploy anything missing from Git. Pending R2 confirms may be gone; they would have expired anyway.
6. **Smoke test.** With a test agent in shadow mode, call `GET /v1/me`, start a run and make one R0 call. Then turn on that test agent's kill switch and check that its next call is refused.
7. **Reopen.** Turn the global kill switch off. In the control UI, choose Record event, then Budget restart, and note the cause, the fix and any budget change.
8. **Next month,** set `aiven-stop` back to €25, or `STOP_ENABLED` back to `true`, whichever you changed in step 3.

## Drill (test BD-1)

Don't drill on the real projects, because Google may delete resources. Instead:

1. Create a scratch project linked to the same billing account. On the trial, first check that the account can hold a fourth project.
2. Deploy a copy of the function with a project list that holds only the scratch project, and give it its own topic.
3. Publish a test message to that topic. Use the real notification's fields, with `budgetDisplayName` `aiven-stop`, and set `costAmount` greater than or equal to `budgetAmount`.
4. Pass when:
   - billing on the scratch project is unlinked within 5 minutes;
   - the `budget_stop` audit entry is written;
   - the alert email arrives;
   - the real projects are untouched.
5. Relink billing on the scratch project. Then run BD-2: a message just below the amount, a duplicate, and one sent with `STOP_ENABLED=false`.

## Free trial

- **Trial end.** The trial ends after 90 days or once the $300 is used. Upgrade to a paid account before that. Without the upgrade, Google stops every project, including control, and deletes them after a 30-day grace period. The audit log would be lost with them.
- **Billing errors.** If relinking fails with a billing error, check whether the trial has ended.
