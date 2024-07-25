#!/bin/sh

# Stop immediately if any executed command has exit status different from 0.
set -e

# Extract linker symbol names (except those starting with ".") from assignments.

script_name=$(basename "$0")
script_dir="$(
  cd "$(dirname "$0")"
  echo "${PWD}"
)"
src_dir="${script_dir}/../.."

fatal() {
  echo "${script_name}: $*" >&2
  exit 1
}

usage() {
  fatal "Usage: ${script_name} <arch>"
}

if [ $# -ne 1 ]; then
  usage
fi

filepath="${src_dir}/xen/arch/${1}/xen.lds"

if [ ! -f "$filepath" ]; then
  fatal "Could not find ${1} linker script. Must be run after the build."
fi

sed -n "s/^\s*\([a-zA-Z_][a-zA-Z_0-9.\-]*\)\s*=.*;.*$/\1/p" "$filepath"
