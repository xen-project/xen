#!/bin/sh

set -eu

usage() {
    echo "Usage: $0 SARIF_FILE" >&2
    exit 2
}

[ $# -eq 1 ] || usage

HERE=$( (
    cd "$(dirname "$0")"
    echo "${PWD}"
))

. "${HERE}/action.helpers"

sarifFile=$1
sarifPayload=${HERE}/sarif.gz.b64
uploadLog=${HERE}/upload_sarif.log

gzip -c "${sarifFile}" | base64 -w0 >"${sarifPayload}"

ex=0
gh api --method POST -H "Accept: application/vnd.github+json" \
    "/repos/${GITHUB_REPOSITORY}/code-scanning/sarifs" \
    -f "commit_sha=${GITHUB_SHA}" -f "ref=${GITHUB_REF}" \
    -F "sarif=@${sarifPayload}" \
    --silent >"${uploadLog}" 2>&1 || ex=$?
maybe_log_file_exit ADD_COMMENT "Uploading SARIF" "${uploadLog}" "${ex}"
