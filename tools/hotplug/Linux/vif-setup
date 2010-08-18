#!/bin/bash

if test "$script"
then
    exec $script $*
else
    exec /etc/xen/scripts/vif-bridge $*
fi

