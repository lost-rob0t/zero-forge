# Maintainer Operations

The hourly steward reads GitHub before it writes, mirrors issue state to Org, updates docs
from new `master` commits, reconciles wiki pages, maintains synchronization helpers, and
only then performs research.

All steward repository work uses the single long-lived branch named exactly `docs`.
Each run refreshes `master` and `docs`, brings current `master` into `docs` without
force-pushing, and updates one draft pull request from `docs` to `master`. Conflicts stop
the run for coordination. Tests or the documentation-only inspection gate must pass
before commit. No automation merges or enables auto-merge.

See [`docs/maintenance.md`](../docs/maintenance.md) for commands and the complete run order.
