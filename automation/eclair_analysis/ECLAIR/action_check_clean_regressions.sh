#!/bin/sh

set -eu

usage() {
    echo "Usage: $0 ANALYSIS_OUTPUT_DIR" >&2
    exit 2
}

[ $# -eq 1 ] || usage

analysisOutputDir=$1

# Load settings and helpers
. "$(dirname "$0")/action.helpers"
. "$(dirname "$0")/action.settings"

cleanRegressionsTxt=${analysisOutputDir}/clean_regressions.txt

cleanRegressionCount=$("${ECLAIR_BIN_DIR}eclair_report" \
    "-db='${analysisOutputDir}/PROJECT.ecd'" \
    "-sel_unfixed=unfixed" \
    "-sel_tag_glob=violation_only,kind,violation" \
    "-sel_tag_glob=clean_added,clean,added" \
    "-report_counts_txt=service,'${cleanRegressionsTxt}'" \
    "-print='',reports_count()")

if [ "${cleanRegressionCount}" -gt 0 ]; then
    {
        echo "Failure: ${cleanRegressionCount} regressions found for clean guidelines"
        sed -n '/^Number of.*$/,/^$/{ /^Number of.*$/! { /^$/! p } }' ${cleanRegressionsTxt}
    } > ${cleanRegressionsLog}
    rm ${cleanRegressionsTxt}
    exit 1
else
    echo "Success: No regressions for clean guidelines" > ${cleanRegressionsLog}
    rm ${cleanRegressionsTxt}
fi
