# Maintainer Operations

The hourly steward reads GitHub before it writes, mirrors issue state to Org, updates docs
from new `master` commits, reconciles wiki pages, maintains synchronization helpers, and
only then performs research.

Every repository change uses a fresh branch and draft PR. Tests must pass before commit.
No automation merges or enables auto-merge.

See [`docs/maintenance.md`](../docs/maintenance.md) for commands and the complete run order.
