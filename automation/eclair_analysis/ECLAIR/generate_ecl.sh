#!/bin/bash

# Generates the .ecl files

set -eu

script_dir="$(
  cd "$(dirname "$0")"
  echo "${PWD}"
)"

exclude_list="${ECLAIR_PROJECT_ROOT}/docs/misra/exclude-list.json"
accepted_rst="${ECLAIR_PROJECT_ROOT}/docs/misra/rules.rst"

# Generate the exclude list file
"${script_dir}/adopted.sh" "${exclude_list}"

# Generate accepted guidelines
"${script_dir}/accepted_guidelines.sh" "${accepted_rst}"

# Generate the list of linker-defined symbols (must be run after a Xen build)
"${script_dir}/generate-linker-symbols.sh"
