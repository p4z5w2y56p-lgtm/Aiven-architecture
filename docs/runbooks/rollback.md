# Runbook: manual rollback of agent writes

Use this when an agent changed Sandbox files it shouldn't have, and for the step 3 rollback test.

What you need:

- the control UI;
- read access to the snapshot bucket `aiven-control-snapshots`;
- Manager rights on the AIVEN Architecture Sandbox drive.

Snapshots are kept for 30 days. After that, only Google's version history is left (step 7).

## 1. Stop the agent

In the control UI, turn on the agent's kill switch and note the time. Leave it on until step 6.

## 2. List what changed

Open Logs Explorer in `aiven-control`, scope it to log bucket `aiven-audit`, and run:

```
logName="projects/<control-project>/logs/aiven-audit"
jsonPayload.agent="invoice-reminder"
jsonPayload.run_id="r_01JA..."
jsonPayload.event="call"
jsonPayload.outcome="executed"
jsonPayload.class=("R1" OR "R2")
```

To cover everything since a point in time instead of one run, drop the `run_id` line and add `timestamp>="2026-10-12T08:00:00Z"`.

Sort newest first. Each entry gives the action, the call ID and the snapshot path. The system can't undo R2 actions such as a sent email, so list those for manual follow-up.

## 3. Undo each call, newest first

Going newest first means changes stacked on the same file unwind in the right order.

| Action | Undo |
|---|---|
| `drive.update` | Download `before.bin` and check that its MD5 matches `before.json`. In Drive, right-click the file, choose File information, then Manage versions, then Upload new version, and pick `before.bin`. If the name changed, rename the file back to the `name` in `before.json`. |
| `sheets.write` | Open `before-cells.json` and type each listed value back into the same sheet and cell; an empty value means clear the cell. For large ranges, use the Sheet's version history instead (File, then Version history) and restore the version from just before the call. That also undoes any other edits made after it. |
| `drive.create` | Move the file named in `after.json` to the trash. You are Manager, so you can; agents can't. |

If a call has `before.json` but no `after.json`, the write may or may not have happened. Compare the file with `before.json`; if they differ, undo it as above.

## 4. Check the result

- Every restored file has the MD5 recorded in `before.json`.
- Every restored range equals `before-cells.json`.
- To check a whole run, list the scope folder (non-trashed items only) and compare it with that run's `manifest.json`. IDs, names, parents and MD5s must all match. Modified times will differ, and that's expected.

## 5. Record it

In the control UI, choose Record event, then Rollback. Enter the run, the calls restored and any manual follow-ups. This writes a `control` entry to the audit log.

## 6. Turn the agent back on

Keep the agent stopped until its policy or prompt is fixed and, if needed, re-signed. Then turn its kill switch off.

## 7. After 30 days

The snapshots are gone by then.

- Google Docs and Sheets still have version history (File, then Version history).
- Other files keep older versions for about 30 days, unless a version is marked "Keep forever".
- The audit log still shows what changed for a full year, but it doesn't hold the old content.
