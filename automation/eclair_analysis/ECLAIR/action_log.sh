#!/bin/sh

set -eu

usage() {
    echo "Usage: $0 SECTION_ID SECTION_NAME FILE EXIT_CODE" >&2
    exit 2
}

[ $# -eq 4 ] || usage

# Load settings and helpers
. "$(dirname "$0")/action.helpers"

log_file "$@"
