# Maintainer Operations

## Sources of truth

- GitHub `master`, issues, pull requests, reviews, and CI are authoritative for current
  coordination.
- `AGENTS.md` defines repository workflow, identity, safety, and validation rules.
- `wiki/issues.org` is the generated Org-mode issue mirror and run ledger.
- `wiki/` is the canonical source for GitHub Wiki pages.
- `research/` contains dated research notes, not approved implementation work.

## Steward run order

1. Record the UTC and operator-timezone run window.
2. Read new maintainer comments and complete target threads; reply only when required.
3. Synchronize GitHub issue state into `wiki/issues.org`.
4. Inspect new `master` commits and update documentation for behavior changes.
5. Reconcile repository wiki sources and the GitHub Wiki.
6. Improve idempotent helpers under `dev_scripts/`.
7. Validate, commit on a fresh branch, and open or update one draft PR.
8. Only then research new possibilities and store cited notes under `research/`.
9. Finalize the Org run entry only after remote writes are confirmed.

Never commit to `master`, reuse another agent's branch, merge, enable auto-merge, or
advance a successful-run cursor before the run is actually complete.

## Helper commands

```bash
python dev_scripts/sync_issues_org.py \
  --repo lost-rob0t/zero-forge --output wiki/issues.org --dry-run

python dev_scripts/update_run_ledger.py \
  --file wiki/issues.org --run-id steward-YYYYMMDDTHHMMSSZ \
  --started-at START --ended-at END --window-start START --window-end END \
  --master-sha SHA --outcome completed --dry-run

python dev_scripts/changed_docs.py \
  --repo-path . --from-ref LAST_DOCUMENTED_SHA --to-ref master

bash dev_scripts/sync_github_wiki.sh \
  --repo lost-rob0t/zero-forge --wiki-dir wiki --mode dry-run
```

Each helper has `--self-check`. GitHub mutations still require authenticated `gh` or Git
credentials; helpers never print credentials.

## Validation gate

Run the focused checks for changed helpers, followed by:

```bash
pytest tests/ -q
ruff check .
mypy zero_forge
```

The current head is mergeable only after GitHub `lint`, `type-check`, `test (3.12)`, and
`test (3.13)` all pass. A new push invalidates previous results.
