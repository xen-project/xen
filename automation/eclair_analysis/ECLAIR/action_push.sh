#!/bin/sh

set -eu

usage() {
    echo "Usage: $0 WTOKEN ANALYSIS_OUTPUT_DIR" >&2
    exit 2
}

[ $# -eq 2 ] || usage

wtoken=$1
analysisOutputDir=$2

# Load settings and helpers
. "$(dirname "$0")/action.helpers"
. "$(dirname "$0")/action.settings"

case "${event}" in
push)
    curl -sS "${eclairReportUrlPrefix}/ext/update_push" \
        -F "wtoken=${wtoken}" \
        -F "artifactsDir=${artifactsDir}" \
        -F "subDir=${subDir}" \
        -F "jobId=${jobId}" \
        -F "jobHeadline=${jobHeadline}" \
        -F "commitId=${headCommitId}" \
        -F "badgeLabel=${badgeLabel}" \
        -F "keepOldAnalyses=${keepOldAnalyses}" \
        -F "db=@${analysisOutputDir}/PROJECT.ecd" \
        >"${updateLog}"
    ;;
auto_pull_request)
    curl -sS "${eclairReportUrlPrefix}/ext/update_pull_request" \
        -F "wtoken=${wtoken}" \
        -F "artifactsDir=${artifactsDir}" \
        -F "subDir=${subDir}" \
        -F "jobId=${jobId}" \
        -F "jobHeadline=${jobHeadline}" \
        -F "baseCommitId=${baseCommitId}" \
        -F "keepOldAnalyses=${keepOldAnalyses}" \
        -F "db=@${analysisOutputDir}/PROJECT.ecd" \
        >"${updateLog}"
    ;;
*)
    echo "Unexpected event ${event}" >&2
    exit 1
    ;;
esac

ex=0
grep -Fq "unfixedReports: " "${updateLog}" || ex=$?
maybe_log_file_exit PUBLISH_RESULT "Publishing results" "${updateLog}" "${ex}"

summary

if is_enabled "${ENABLE_ECLAIR_BOT:-}"; then
    case ${ci} in
    github)
        ex=0
        gh api \
            --method POST \
            "/repos/${repository}/commits/${headCommitId}/comments" \
            -F "body=@${summaryTxt}" \
            --silent >"${commentLog}" 2>&1 || ex=$?
        maybe_log_file_exit ADD_COMMENT "Adding comment" "${commentLog}" "${ex}"
        ;;
    gitlab)
        curl -sS --request POST \
            "${gitlabApiUrl}/projects/${CI_PROJECT_ID}/repository/commits/${CI_COMMIT_SHA}/comments" \
            -H "PRIVATE-TOKEN: ${gitlabBotToken}" \
            -F "note=<${summaryTxt}" >"${commentLog}"
        ex=0
        grep -Fq "Unfixed reports: " "${commentLog}" || ex=$?
        maybe_log_file_exit ADD_COMMENT "Adding comment" "${commentLog}" "${ex}"
        ;;
    jenkins)
        ex=0
        curl \
            --user "${jenkinsBotUsername}:${jenkinsBotToken}" \
            --data-urlencode "description=$(cat "${summaryTxt}")" \
            --data-urlencode "Submit=Submit" \
            "${jenkinsApiUrl}job/${project}/${jobId}/submitDescription" \
            >"${commentLog}" 2>&1 || ex=$?
        curl \
            --user "${jenkinsBotUsername}:${jenkinsBotToken}" \
            --data-urlencode "description=$(cat "${summaryTxt}")" \
            --data-urlencode "Submit=Submit" \
            "${jenkinsApiUrl}job/${project}/submitDescription" \
            >"${commentLog}" 2>&1 || ex=$?
        maybe_log_file_exit ADD_COMMENT "Adding comment" "${commentLog}" "${ex}"
        ;;
    *) ;;
    esac
fi
