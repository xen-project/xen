#!/bin/bash

# Generates the .ecl files

set -eu

script_dir="$(
  cd "$(dirname "$0")"
  echo "${PWD}"
)"

exclude_list="${ECLAIR_PROJECT_ROOT}/docs/misra/exclude-list.json"

# Generate the exclude list file
"${script_dir}/adopted.sh" "${exclude_list}"
