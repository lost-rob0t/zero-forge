#!/usr/bin/env bash
set -euo pipefail

self_check=false
repository=""
wiki_dir="wiki"
mode="dry-run"

while (($#)); do
  case "$1" in
    --repo) repository="${2:-}"; shift 2 ;;
    --wiki-dir) wiki_dir="${2:-}"; shift 2 ;;
    --mode) mode="${2:-}"; shift 2 ;;
    --self-check) self_check=true; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

if $self_check; then
  [[ "owner/repo" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]
  exit 0
fi

[[ "$repository" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || {
  echo "--repo must use owner/name syntax" >&2
  exit 2
}
[[ "$mode" == "dry-run" || "$mode" == "push" || "$mode" == "pull" ]] || {
  echo "--mode must be dry-run, push, or pull" >&2
  exit 2
}
[[ -d "$wiki_dir" ]] || { echo "wiki directory not found: $wiki_dir" >&2; exit 2; }

if [[ "$mode" == "dry-run" ]]; then
  find "$wiki_dir" -maxdepth 1 -type f \( -name '*.md' -o -name '*.org' \) -print | sort
  exit 0
fi

workspace="$(mktemp -d)"
trap 'rm -rf "$workspace"' EXIT
git clone --quiet "https://github.com/${repository}.wiki.git" "$workspace/wiki"

if [[ "$mode" == "pull" ]]; then
  find "$workspace/wiki" -maxdepth 1 -type f -name '*.md' -exec cp -- {} "$wiki_dir/" \;
  exit 0
fi

find "$wiki_dir" -maxdepth 1 -type f -name '*.md' -exec cp -- {} "$workspace/wiki/" \;
git -C "$workspace/wiki" add -- '*.md'
if git -C "$workspace/wiki" diff --cached --quiet; then
  exit 0
fi
git -C "$workspace/wiki" commit --quiet -m "Sync repository wiki sources"
git -C "$workspace/wiki" push --quiet
