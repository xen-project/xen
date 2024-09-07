#!/bin/bash
# Stop immediately if any executed command has exit status different from 0.
set -e
set -o pipefail

script_name="$(basename "$0")"

fatal() {
  echo "${script_name}: $*" >&2
  exit 1
}

usage() {
  fatal "Usage: ${script_name} <ARM64|X86_64> <accepted|monitored>"
}

if [[ $# -ne 2 ]]; then
  usage
fi

# Absolute path of the ECLAIR bin directory.
export ECLAIR_BIN_DIR=/opt/bugseng/eclair/bin/

# Directory where this script resides: usually in a directory named "ECLAIR".
SCRIPT_DIR="$(
  cd "$(dirname "$0")"
  echo "${PWD}"
)"
# Directory where to put all ECLAIR output and temporary files.
if [[ -z "${ECLAIR_OUTPUT_DIR:-}" ]]; then
  ECLAIR_OUTPUT_DIR="${PWD}/ECLAIR/out"
fi

export ECLAIR_DIAGNOSTICS_OUTPUT="${ECLAIR_OUTPUT_DIR}/ANALYSIS.log"
# Set the variable for the build log file.
ECLAIR_BUILD_LOG=${ECLAIR_OUTPUT_DIR}/BUILD.log
# Set the variable for the report log file.
ECLAIR_REPORT_LOG=${ECLAIR_OUTPUT_DIR}/REPORT.log

if [[ "$1" = "X86_64" ]]; then
  export CROSS_COMPILE=
  export XEN_TARGET_ARCH=x86_64
elif [[ "$1" = "ARM64" ]]; then
  export CROSS_COMPILE=aarch64-linux-gnu-
  export XEN_TARGET_ARCH=arm64
else
  fatal "Unknown configuration: $1"
fi

VARIANT="${XEN_TARGET_ARCH}"

# Used in analysis.ecl
case "$2" in
accepted|monitored)
  export SET="$2"
  ;;
*)
  fatal "Unknown configuration: $2"
  ;;
esac

export CC_ALIASES="${CROSS_COMPILE}gcc-12"
export CXX_ALIASES="${CROSS_COMPILE}g++-12"
export LD_ALIASES="${CROSS_COMPILE}ld"
export AR_ALIASES="${CROSS_COMPILE}ar"
export AS_ALIASES="${CROSS_COMPILE}as"
export FILEMANIP_ALIASES="cp mv ${CROSS_COMPILE}objcopy"

# ECLAIR binary data directory and workspace.
export ECLAIR_DATA_DIR="${ECLAIR_OUTPUT_DIR}/.data"
# ECLAIR workspace.
export ECLAIR_WORKSPACE="${ECLAIR_DATA_DIR}/eclair_workspace"

# Identifies the particular build of the project.
export ECLAIR_PROJECT_NAME="XEN_${VARIANT}-${SET}"

# Erase and recreate the output directory and the data directory.
rm -rf "${ECLAIR_OUTPUT_DIR:?}/*"
mkdir -p "${ECLAIR_DATA_DIR}"

# Perform the build (from scratch) in an ECLAIR environment.
"${ECLAIR_BIN_DIR}eclair_env" \
    "-config_file='${SCRIPT_DIR}/analysis.ecl'" \
    "${EXTRA_ECLAIR_ENV_OPTIONS}" \
  -- "${SCRIPT_DIR}/../build.sh" "$1" | tee "${ECLAIR_BUILD_LOG}"


# Create the project database.
PROJECT_ECD="${ECLAIR_OUTPUT_DIR}/PROJECT.ecd"
find "${ECLAIR_DATA_DIR}" -maxdepth 1 -name "FRAME.*.ecb" |
  sort | xargs cat |
  "${ECLAIR_BIN_DIR}eclair_report" \
    "-create_db='${PROJECT_ECD}'" \
    -load=/dev/stdin > "${ECLAIR_REPORT_LOG}" 2>&1

# Create the Jenkins reports file.
"${ECLAIR_BIN_DIR}eclair_report" \
  "-db='${PROJECT_ECD}'" \
  "-eval_file='${SCRIPT_DIR}/report.ecl'" \
  >> "${ECLAIR_REPORT_LOG}" 2>&1

"${SCRIPT_DIR}/print_analyzed_files.sh" "${PROJECT_ECD}" "${ECLAIR_OUTPUT_DIR}"
