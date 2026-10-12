# Runbook: budget hard stop and restart

## What happens

- **Trigger.** This month's actual cost reaches the `aiven-monthly` budget of €10. Google's cost notifications arrive hours after the spending, so the real total can end up above €10.
- **Automatic action.** The `budget-stop` function unlinks billing from `aiven-agents` and `aiven-gateway`, writes a `budget_stop` audit entry and emails an alert.
- **Result.**
  - All agents and the gateway stop.
  - Google may delete some resources in those two projects.
  - The control project keeps running, so the audit log, snapshots, kill switch and control UI stay available.

## Restart

1. **Find the cause.** Open Billing, then Reports, grouped by project and service for this month. Then check the audit log around the time the cost jumped (`jsonPayload.event="run_start"`, per agent).
2. **Keep everything stopped.** Turn on the global kill switch in the control UI. It stays on until step 7.
3. **Stop the trigger from firing again.** While this month's cost is still at or above the budget, the next notification will unlink billing again. Pick one of these, and write down which, because step 8 undoes it:
   - raise the budget above this month's cost (Billing, then Budgets & alerts, then `aiven-monthly`), or
   - set the function's `STOP_ENABLED` variable to `false`.
4. **Relink billing.** You need Billing Account User on the billing account and Project Billing Manager on both projects.

   ```sh
   gcloud billing projects link <gateway-project> --billing-account=<BILLING_ACCOUNT_ID>
   gcloud billing projects link <agents-project> --billing-account=<BILLING_ACCOUNT_ID>
   ```

5. **Check what survived.** Run `gcloud run services describe gateway --region=europe-west4 --project=<gateway-project>`, then check the agents' Cloud Run jobs and the `gateway` Firestore database. Redeploy anything missing from Git. Pending R2 confirms may be gone; they would have expired anyway.
6. **Smoke test.** With a test agent in shadow mode, call `GET /v1/me`, start a run and make one R0 call. Then turn on that test agent's kill switch and check that its next call is refused.
7. **Reopen.** Turn the global kill switch off. In the control UI, choose Record event, then Budget restart, and note the cause, the fix and any budget change.
8. **Next month,** set the budget back to €10 or `STOP_ENABLED` back to `true`, whichever you changed in step 3.

## Drill (step 3)

Don't drill on the real projects, because Google may delete resources. Instead:

1. Deploy a copy of the function whose project list holds only a scratch project.
2. Publish a test message to its topic with `costAmount` greater than or equal to `budgetAmount`.
3. Check that billing on the scratch project is unlinked and that the audit entry is written.
4. Relink billing on the scratch project.
