#!/bin/bash

# Generates the adopted.ecl file

set -eu

script_name="$(basename "$0")"
script_dir="$(
  cd "$(dirname "$0")"
  echo "${PWD}"
)"

fatal() {
  echo "${script_name}: $*" >&2
  exit 1
}

usage() {
  fatal "Usage: ${script_name}"
}

exclude_list=$1
outfile=${script_dir}/adopted.ecl

(
  echo "-doc_begin=\"Adopted files.\"" >"${outfile}"
  sed -n -E -e 's|^\s+"rel_path":\s+"([^"]*).*$|-file_tag+={adopted,"^xen/\1$"}|p' "${exclude_list}" |
    sed -E -e 's|\.([ch])|\\\\.\1|g' -e 's|\*|.*|g' >>"${outfile}"
  printf "%s\n" "-doc_end" >>"${outfile}"
)
