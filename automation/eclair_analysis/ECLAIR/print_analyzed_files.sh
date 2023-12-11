#!/bin/bash
# Stop immediately if any executed command has exit status different from 0.
set -eu

script_name="$(basename "$0")"
script_dir="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

fatal() {
  echo "${script_name}: $*" >&2
  exit 1
}

usage() {
  fatal "Usage: ${script_name} DATABASE OUT_DIR"
}

extrapolate_regex() {
  lookbehind=$1
  file=$2
  grep -Po "(?<=${lookbehind}\"\\^).*(?=\\$\")" "${file}" | sed 's/\\\\/\\/'
}

if [ $# -lt 2 ]; then
  usage
fi

DB=$1
OUT_DIR=$2

files_txt="${OUT_DIR}/files.txt"
files_c_txt="${OUT_DIR}/files_c.txt"
files_h_txt="${OUT_DIR}/files_h.txt"
exclusions_txt="${OUT_DIR}/exclusions.txt"


if [[ ! -d "${OUT_DIR}" ]]; then
  mkdir -p "${OUT_DIR}"
else
  rm -f "${files_txt}"
  rm -f "${files_c_txt}"
  rm -f "${files_h_txt}"
  rm -f "${exclusions_txt}"
fi

# Generating txt report with files
"${ECLAIR_BIN_DIR}eclair_report" -db="${DB}" -files_txt="${files_txt}"

{
  # Extracting out of scope and adopted code
  adopted_ecl="${script_dir}/adopted.ecl"
  extrapolate_regex adopted,             "${adopted_ecl}"
  out_of_scope_ecl="${script_dir}/out_of_scope.ecl"
  extrapolate_regex adopted,             "${out_of_scope_ecl}"
  extrapolate_regex out_of_scope_tools,  "${out_of_scope_ecl}"
  extrapolate_regex out_of_scope,        "${out_of_scope_ecl}"
  extrapolate_regex hypercall_ABI,       "${out_of_scope_ecl}"
  extrapolate_regex "hide, "             "${out_of_scope_ecl}"
} >"${exclusions_txt}"
sort -o "${exclusions_txt}" -u "${exclusions_txt}"

# Removing exclusions from files_txt
grep -E -v "(object: |/dev/pipe)" "${files_txt}" > "${files_txt}.tmp"
grep -vf "${exclusions_txt}" "${files_txt}.tmp" > "${files_txt}"
rm "${files_txt}.tmp"
# Creating files with only headers
grep -Ev "(xen.*\.(h\w+|[^h]\w*) |.*ecl)" "${files_txt}" > "${files_h_txt}"
# Creating files with only c files
grep -Ev "(xen.*\.(c\w+|[^c]\w*) |.*ecl)" "${files_txt}" > "${files_c_txt}"
