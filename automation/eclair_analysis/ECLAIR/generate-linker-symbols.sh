#!/bin/bash

set -e

script_name="$(basename "$0")"
script_dir="$(
  cd "$(dirname "$0")"
  echo "${PWD}"
)"

fatal() {
  echo "${script_name}: $*" >&2
  exit 1
}

arch=""
if [ "${XEN_TARGET_ARCH}" == "x86_64" ]; then
  arch=x86
elif [ "${XEN_TARGET_ARCH}" == "arm64" ]; then
  arch=arm
else
  fatal "Unknown configuration: $1"
fi

outfile=${script_dir}/linker_symbols.ecl

(
  echo -n "-decl_selector+={linker_symbols, \"^(" >"${outfile}"
  "${script_dir}/../linker-symbols.sh" "${arch}" | sort -u | tr '\n' '|' | sed '$ s/|//' >>"${outfile}"
  echo -n ")$\"}" >>"${outfile}"
)
