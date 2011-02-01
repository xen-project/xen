#!/bin/bash
#============================================================================
# Default Xen network start/stop script.
# Xend calls a network script when it starts.
# The script name to use is defined in ${XEN_CONFIG_DIR}/xend-config.sxp
# in the network-script field.
#
# Usage:
#
# network-route (start|stop|status) {VAR=VAL}*
#
# Vars:
#
# netdev     The gateway interface (default eth0).
# antispoof  Whether to use iptables to prevent spoofing (default yes).
#
#============================================================================

dir=$(dirname "$0")
. "$dir/hotplugpath.sh"
. "$dir/xen-script-common.sh"

evalVariables "$@"

netdev=${netdev:-eth0}

echo 1 >/proc/sys/net/ipv4/ip_forward
echo 1 >/proc/sys/net/ipv4/conf/${netdev}/proxy_arp
