#!/usr/bin/env bash
# flag_gen.sh — generate a randomized flag and place it at a known location.
#
# Usage: ./flag_gen.sh [output_dir] [filename]
# Default: /tmp/zeroforge-target/flag.txt
#
# The flag is randomized using /dev/urandom so it cannot be guessed.
# The script outputs the flag value and file path as JSON.

set -euo pipefail

OUTPUT_DIR="${1:-/tmp/zeroforge-target}"
FILENAME="${2:-flag.txt}"
FLAG_PATH="${OUTPUT_DIR}/${FILENAME}"

# Generate 32 bytes of random hex for the flag
RANDOM_HEX="$(head -c 32 /dev/urandom | xxd -p | tr -d '\n')"
FLAG="FLAG{${RANDOM_HEX}}"

mkdir -p "${OUTPUT_DIR}"
printf '%s' "${FLAG}" > "${FLAG_PATH}"
chmod 600 "${FLAG_PATH}"

# Output JSON for programmatic consumption
cat <<EOF
{"flag": "${FLAG}", "flag_path": "${FLAG_PATH}"}
EOF
