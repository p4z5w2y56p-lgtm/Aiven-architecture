# Drive wrapper (wrap 1)

Status: draft for review (Phase 1, step 2). Nothing here is built yet.
Classes come from the catalog in `docs/validator-spec.md` §5, which stays authoritative. The gateway flow around these actions is described in `docs/gateway-design.md`.

## 1. Setup (once, as Workspace admin)

1. **Create the Shared Drive.** Name it **AIVEN Architecture Sandbox**, with Matthijs as Manager. It is a drive of its own, not a folder inside a bigger drive. To give a non-member access to a single folder, the bigger drive's non-member access would have to be on, and that removes Google's block on sharing files out.
2. **Set the drive's sharing.**
   - In the drive's settings, turn **on** access for people outside AIVEN. The gateway account is the only outsider.
   - Turn **off** access for non-members.
   - Check that the Admin console (Drive and Docs → Sharing settings) lets shared drives have outside members. The setting labels may differ; check them before step 3.
3. **Add the gateway.** Add `gateway@<gateway-project>.iam.gserviceaccount.com` as **Contributor**. Nobody else joins besides Matthijs.
4. **Create the working folders**, for example `Invoices`, `Reports` and `Rollback test`, and note their IDs for the policies.
5. **Configure the gateway.** Set the drive ID as `SANDBOX_DRIVE_ID`, and Matthijs's AIVEN account as the only entry in `TRUSTED_AUTHORS`.

After this, Google itself enforces the following, even if the gateway has a bug:

- The gateway account can't trash, delete or move anything, because Contributors can't.
- Nobody can share Sandbox files with non-members, and only a Manager can add members.
- The gateway account sees nothing outside this drive unless someone shares a file with it directly. The `driveId` check refuses those files anyway.
- Files belong to the drive, so the service account's missing storage quota doesn't matter.

## 2. Rules for every Drive action

- **Arguments.** Each action has a JSON Schema, and unknown fields are refused (`BAD_ARGS`). Agents never pass raw Drive query strings or raw API fields.
- **Target check.** `files.get(fileId, supportsAllDrives=true)` must show:
  - `driveId == SANDBOX_DRIVE_ID`;
  - `trashed == false`;
  - a parent chain (at most 20 levels) that reaches the policy's `scope.drive_folder_id`.

  Otherwise the call is refused with `OUT_OF_SCOPE`, which is also the answer for missing files, so existence isn't revealed.
- **Listing.** The gateway builds the query itself: `'<folder>' in parents and trashed = false`, plus an escaped `name contains '<text>'` when asked. It sends `corpora=drive`, `driveId=SANDBOX_DRIVE_ID`, `includeItemsFromAllDrives=true` and `supportsAllDrives=true`.
- **Writes** send only `name`, `appProperties` and content. They never send `trashed`, `parents`, `addParents`, `removeParents`, permission fields, `writersCanShare`, `copyRequiresWriterPermission`, `contentRestrictions` or `inheritedPermissionsDisabled`. A request that names any of these is refused, not silently trimmed.
- **Labels.** Every write sets `appProperties` `aiven_agent`, `aiven_run` and `aiven_taint` (`1` when the run is tainted). App properties are visible only to the gateway's own app, so neither agents nor people can fake them.
- **Effective class.** Before a write, the gateway calls `permissions.list` on the file. Any permission beyond the drive's members, or any `anyone` or `domain` link, makes the write R2. The drive settings should make this impossible; the check stays as a backstop.
- **Content scan.** The new content, and the old content about to be snapshotted, are both scanned with the patterns in validator-spec §3.8. A match refuses the call (`CONTENT_BLOCKED`) with no write and no snapshot. That way bank details, ID numbers and credentials never get copied into the snapshot store.
- **Sizes.**
  - Reads: up to 5 MB.
  - Writes: up to 1 MB.
  - Sheets: up to 1,000 cells written and 10,000 cells read per call.
- **Timeouts and retries.** Each Drive call has a 30 s timeout. Reads are retried once on 429 or 5xx, with backoff. Writes are never retried blindly: the gateway re-reads the target first.

## 3. Actions

| Action | Class | Arguments | Google API | Snapshot | Records |
|---|---|---|---|---|---|
| `drive.list` | R0 | `folder_id` (default: the scope folder), `name_contains`, `page_token`, `page_size` ≤ 100 | `files.list`, as in §2 | | 0 |
| `drive.read` | R0 | `file_id` | Google Docs: `files.export` as `text/plain`. Text, Markdown, CSV, JSON: `files.get` with `alt=media`. Other types are refused (`BAD_ARGS`). | | 0 |
| `sheets.read` | R0 | `file_id`, `range` (A1) | `spreadsheets.values.get` | | 0 |
| `drive.create` | R1 | `parent_id`, `name`, `type` (`text`, `markdown`, `csv`, `json`, `google_doc` from text, `google_sheet` from CSV), `content` | `files.create` (multipart, with conversion for Google types) | `before.json` (parent, name, content hash), `after.json` (new file ID) | 1 |
| `drive.update` | R1, or R2 if shared | `file_id`, plus `name` and/or `content` | `files.update` (metadata and/or media) | `before.json` (name, type, MD5, revision, size, modified time), `before.bin` (exact bytes), `after.json` | 1 |
| `sheets.write` | R1, or R2 if shared | `file_id`, `range` (one rectangle inside the existing grid), `values` (strings, numbers, booleans) | `spreadsheets.batchUpdate` with `updateCells` on `userEnteredValue` | `before-cells.json`: the exact previous `userEnteredValue` of every cell in the range | Rows touched |
| `drive.move`, `drive.share`, `drive.delete` | R3 | | Never called | | |

What v1 leaves out, and why:

- **`drive.update` content changes** apply only to non-Google files (text, Markdown, CSV, JSON). Content changes to Google Docs or Slides can't be restored exactly through the API, so agents create a new Doc instead. Any file can be renamed.
- **`sheets.write` writes literal values only.** A value starting with `=` is stored as text, never as a formula. Formulas such as `IMPORTXML` or `IMAGE` can send sheet data to the internet.
- **No inserts or copies.** v1 has no row, column or sheet inserts, no copies, and no exports to other formats.

## 4. Snapshots

Every R1 write, and every R2 write after its confirm, follows these steps:

1. Re-read the target's metadata.
2. Content-scan the old and the new content.
3. Write `before.json`, plus `before.bin` or `before-cells.json`, to `gs://aiven-control-snapshots/<agent>/<run_id>/<call_id>/`. Check it: for binary files the uploaded bytes' MD5 must equal Drive's `md5Checksum`, and for Sheets the cell JSON must round-trip unchanged.
4. If the target's `modifiedTime` changed since step 1, stop with `STALE_TARGET`.
5. Write to Drive.
6. Write `after.json` (the new revision and MD5, or the new file ID).

If any step before 5 fails, nothing is written to Drive (`SNAPSHOT_FAILED`). If step 6 fails, the audit entry still holds the call and the snapshot path, and the rollback runbook handles the rest.

At the start of each run, the gateway also writes `manifest.json` for the agent's scope folder. It lists every non-trashed item with its ID, name, type, parent, MD5 (binary files) and modified time, up to 500 items; beyond that it is marked partial. Rollback checks compare against this manifest.

The gateway has create-only access and the bucket has 30-day retention. Objects can't be overwritten, so every snapshot written is kept for 30 days.

## 5. Taint: where untrusted content comes from

A Drive read taints the run when the file it reads, or any file a listing returns, is untrusted. A file is untrusted when any of these holds:

1. It carries `aiven_taint=1` (written during a tainted run), unless Matthijs cleared that exact version in the control UI.
2. It isn't a Google Doc, Sheet or Slides file, and its current version wasn't written by the gateway. In other words, it was uploaded.
3. Its last modifier is neither a trusted author (`TRUSTED_AUTHORS`, which is Matthijs) nor the gateway account.

Gmail reads (wrap 2) and anything from the web always taint.

Why: the plan's taint rule names web, email and uploaded content. Step 1's conservative default counted every read. Combined with `strict`, that would put almost every R1 write behind a confirm, which breaks the Phase 1 done test ("normal work is blocked only at R2 confirms"). Under these rules, a run that only reads Matthijs's own Docs and Sheets stays clean.

Known gap: text Matthijs pastes into a Google Doc counts as trusted. Put outside material into the Sandbox as uploaded files, not as pasted text.

## 6. Refusal reasons from this wrapper

| Reason | When |
|---|---|
| `OUT_OF_SCOPE` | The target is outside the Sandbox drive or the policy's folder, is trashed, or doesn't exist |
| `BAD_ARGS` | Unknown or forbidden fields, an unsupported file type, a range outside the grid, or a size over the limit |
| `CONTENT_BLOCKED` | The old or new content matches a bank-detail, ID-number or credential pattern |
| `SNAPSHOT_FAILED` | The snapshot couldn't be written or checked, so the write was not made |
| `STALE_TARGET` | The file changed between the snapshot (or the R2 preview) and the write |

## 7. Tests

See `docs/test-plan.md`: D-1 to D-8, RB-1 and RB-2, and the forced-delete attacks AT-DEL-1 to AT-DEL-7. AT-DEL-7 proves the Google-side backstop.
