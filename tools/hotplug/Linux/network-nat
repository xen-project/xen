#!/bin/bash
#============================================================================
# Default Xen network start/stop script when using NAT.
# Xend calls a network script when it starts.
# The script name to use is defined in ${XEN_CONFIG_DIR}/xend-config.sxp
# in the network-script field.
#
# Usage:
#
# network-nat (start|stop|status) {VAR=VAL}*
#
# Vars:
#
# netdev     The gateway interface (default eth0).
# antispoof  Whether to use iptables to prevent spoofing (default no).
# dhcp       Whether to alter the local DHCP configuration (default no).
#
#============================================================================

dir=$(dirname "$0")
. "$dir/hotplugpath.sh"
. "$dir/xen-script-common.sh"
. "$dir/xen-network-common.sh"

findCommand "$@"
evalVariables "$@"

netdev=${netdev:-eth0}
# antispoofing not yet implemented
antispoof=${antispoof:-no}

# turn on dhcp feature by default if dhcpd is installed
if [ -f /etc/dhcpd.conf ]
then
	dhcp=${dhcp:-yes}
else
	dhcp=${dhcp:-no}
fi


if [ "$dhcp" != 'no' ]
then
  dhcpd_conf_file=$(find_dhcpd_conf_file)
  dhcpd_init_file=$(find_dhcpd_init_file)
  if [ -z "$dhcpd_conf_file" ] || [ -z "$dhcpd_init_file" ]
  then
    echo 'Failed to find dhcpd configuration or init file.' >&2
    exit 1
  fi
fi

domain_name=`cat /etc/resolv.conf | grep -v "#" | grep -E 'search|domain' -i | tail -n 1 | awk '{ print $2 }'`
nameserver=`cat /etc/resolv.conf | grep -v "#" | grep "nameserver" -i -m 1 | awk '{ print $2 }'`

function dhcp_start()
{
  if ! grep -q "subnet 10.0.0.0" "$dhcpd_conf_file"
  then
    echo >>"$dhcpd_conf_file" "subnet 10.0.0.0 netmask 255.255.0.0 {\
 option domain-name \"$domain_name\";\
 option domain-name-servers $nameserver; }"
  fi

  "$dhcpd_init_file" restart
}


function dhcp_stop()
{
  local tmpfile=$(mktemp)
  grep -v "subnet 10.0.0.0" "$dhcpd_conf_file" >"$tmpfile"
  if diff "$tmpfile" "$dhcpd_conf_file" >&/dev/null
  then
    rm "$tmpfile"
  else
    mv "$tmpfile" "$dhcpd_conf_file"
  fi

  "$dhcpd_init_file" restart
}


op_start() {
	echo 1 >/proc/sys/net/ipv4/ip_forward
	iptables -t nat -A POSTROUTING -o ${netdev} -j MASQUERADE
        [ "$dhcp" != 'no' ] && dhcp_start
}


op_stop() {
        [ "$dhcp" != 'no' ] && dhcp_stop
	iptables -t nat -D POSTROUTING -o ${netdev} -j MASQUERADE
}


show_status() {
    echo '============================================================'
    ifconfig
    echo ' '
    ip route list
    echo ' '
    route -n
    echo '============================================================'

}

case "$command" in
    start)
        op_start
        ;;
    
    stop)
        op_stop
        ;;

    status)
        show_status
       ;;

    *)
       echo "Unknown command: $command" >&2
       echo 'Valid commands are: start, stop, status' >&2
       exit 1
esac
