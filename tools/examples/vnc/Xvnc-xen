#!/bin/bash
#============================================================================
# This script should be installed in /usr/X11R6/bin/Xvnc-xen.
#============================================================================
#
# Start Xvnc and use vncconnect to connect back to a vncviewer listening in
# domain 0. The host and port to connect to are given by
#
#    VNC_VIEWER=<host>:<port>
#
# in the kernel command line (/proc/cmdline). 
#
# The '--vnc' option to 'xm create' will start a vncviewer and
# pass its address in VNC_VIEWER for this script to find.
#
# Usage:
#        Xvnc-xen [args]
#
# Any arguments are passed to Xvnc.
#
#============================================================================

# Prefix for messages.
M="[$(basename $0)]"

# Usage: vnc_addr
# Print <host>:<port> for the vncviewer given in
# the kernel command line.
vnc_addr () {
    sed -n -e "s/.*VNC_VIEWER=\([^ ]*\).*/\1/p" /proc/cmdline
}

# Usage: vnc_connect
# If a vncviewer address was given on the kernel command line,
# run vncconnect for it.
vnc_connect () {
    local addr=$(vnc_addr)

    if [ -n "${addr}" ] ; then
        echo "$M Connecting to ${addr}."
        vncconnect ${addr}
    else
        echo "$M No VNC_VIEWER in kernel command line."
        echo "$M Create the domain with 'xm create --vnc <display>'."
        return 1
    fi
}

# Start the vnc server.
Xvnc "$@" >/dev/null 2>&1 &

# Connect back to the viewer in domain-0.
vnc_connect
