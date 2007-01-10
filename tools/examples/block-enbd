#!/bin/bash

# Usage: block-enbd [bind server ctl_port |unbind node]
#
# The node argument to unbind is the name of the device node we are to
# unbind.
#
# This assumes you're running a correctly configured server at the other end!

dir=$(dirname "$0")
. "$dir/block-common.sh"

case "$command" in
  add)
    for dev in /dev/nd*; do
      if nbd-client $2:$3 $dev; then
        write_dev $dev
        exit 0
      fi
    done
    exit 1
    ;;
  remove)
    nbd-client -d $2
    exit 0
    ;;
esac
