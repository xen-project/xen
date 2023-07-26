#!/bin/sh

set -eu

usage() {
    echo "Usage: $0 ANALYSIS_OUTPUT_DIR" >&2
    exit 2
}

[ $# -eq 1 ] || usage

analysisOutputDir=$1

cleanAddedTxt="${analysisOutputDir}/clean_added.log"

# Load settings and helpers
. "$(dirname "$0")/action.helpers"
. "$(dirname "$0")/action.settings"

unexpectedReports=$("${ECLAIR_BIN_DIR}eclair_report" \
    "-db='${analysisOutputDir}/PROJECT.ecd'" \
    "-sel_unfixed=unfixed" \
    "-sel_tag_glob=clean_added,clean,added" \
    "-print='',reports_count()")

if [ "${unexpectedReports}" -gt 0 ]; then
    cat <<EOF >"${cleanAddedTxt}"
Failure: ${unexpectedReports} unexpected reports found.
Unexpected reports are tagged 'clean:added'.
EOF
    exit 1
else
    cat <<EOF >"${cleanAddedTxt}"
Success: No unexpected reports.
EOF
fi
