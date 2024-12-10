#!/bin/bash
# Stop immediately if any executed command has exit status different from 0.
set -eu

script_dir="$(
  cd "$(dirname "$0")"
  echo "${PWD}"
)"

accepted_rst=$1

grep -Eo "\`(Dir|Rule) [0-9]+\.[0-9]+" ${accepted_rst} \
     | sed -e 's/`Rule /MC3A2.R/' -e  's/`Dir /MC3A2.D/' -e 's/.*/-enable=&/' > ${script_dir}/accepted.ecl

echo "-enable=B.UNEVALEFF" >> ${script_dir}/accepted.ecl
