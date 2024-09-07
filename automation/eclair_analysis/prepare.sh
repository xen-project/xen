#!/bin/bash
# Stop immediately if any executed command has exit status different from 0.
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

usage() {
  fatal "Usage: ${script_name}"
}

if [ $# -ne 1 ]; then
  usage
  exit 1
fi

export XEN_TARGET_ARCH

if [ "$1" = "X86_64" ]; then
  CONFIG_FILE="${script_dir}/xen_x86_config"
  XEN_TARGET_ARCH=x86_64
elif [ "$1" = "ARM64" ]; then
  CONFIG_FILE="${script_dir}/xen_arm_config"
  XEN_TARGET_ARCH=arm64
else
  fatal "Unknown configuration: $1"
fi

(
    ./configure
    cp "${CONFIG_FILE}" xen/.config
    make clean
    find . -type f -name "*.safparse" -print -delete
    "${script_dir}/build.sh" "$1"
    # Generate additional configuration files
    "${script_dir}/ECLAIR/generate_ecl.sh"
    make clean
    cd xen
    make -f "${script_dir}/Makefile.prepare" prepare
    # Translate the /* SAF-n-safe */ comments into ECLAIR CBTs
    scripts/xen-analysis.py --run-eclair --no-build --no-clean
    # Translate function-properties.json into ECLAIR properties
    python3 "${script_dir}/propertyparser.py"
)
