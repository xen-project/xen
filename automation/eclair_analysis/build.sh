#!/bin/bash
# Stop immediately if any executed command has exit status different from 0.
set -e

script_name="$(basename "$0")"

fatal() {
  echo "${script_name}: $*" >&2
  exit 1
}

usage() {
  fatal "Usage: ${script_name} <ARM64|X86_64>"
}

if [ $# -ne 1 ]; then
  usage
fi

if [ "$1" = "X86_64" ]; then
  export CROSS_COMPILE=
  export XEN_TARGET_ARCH=x86_64
elif [ "$1" = "ARM64" ]; then
  export CROSS_COMPILE=aarch64-linux-gnu-
  export XEN_TARGET_ARCH=arm64
else
  fatal "Unknown configuration: $1"
fi

if [[ -f /proc/cpuinfo ]]; then
  PROCESSORS=$(grep -c ^processor /proc/cpuinfo)
else
  PROCESSORS=6
fi

# Variables driving the build
CC=${CROSS_COMPILE}gcc-12
CXX=${CROSS_COMPILE}g++-12

runtime_failures_docs() {
  doc="C-runtime-failures.rst"
  builddir="automation/eclair_analysis"
  
  cd "${builddir}"
  printf "/*\n\n" >"${doc}.c"
  sed -e 's|\*/|*//*|g' "../../docs/misra/${doc}" >>"${doc}.c"
  
  # At least a dummy decl is needed to comply with the C standard.
  printf "\n\n*/\ntypedef int dummy_typedef;\n" >>"${doc}.c"
  
  # The C language standard applicable to Xen is C99 (with extensions),
  # therefore even this dummy file needs to be compiled with -std=c99.
  # Cannot redirect to /dev/null because it would be excluded from the analysis
  "${CC}" -std=c99 -c "${doc}.c" -o "${doc}.o"
  cd -
}

(
  runtime_failures_docs

  make "-j${PROCESSORS}" "-l${PROCESSORS}.0"    \
       "CROSS_COMPILE=${CROSS_COMPILE}"         \
       "CC=${CC}"                               \
       "CXX=${CXX}"                             \
       "XEN_TARGET_ARCH=${XEN_TARGET_ARCH}"     \
       -C xen
)
