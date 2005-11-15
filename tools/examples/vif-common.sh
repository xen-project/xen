#
# Copyright (c) 2005 XenSource Ltd.
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of version 2.1 of the GNU Lesser General Public
# License as published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#


dir=$(dirname "$0")
. "$dir/xen-hotplug-common.sh"
. "$dir/xen-network-common.sh"

findCommand "$@"

if [ "$command" != "online" ]  &&
   [ "$command" != "offline" ] &&
   [ "$command" != "add" ]     &&
   [ "$command" != "remove" ]
then
  log err "Invalid command: $command"
  exit 1
fi

case "$command" in
    add | remove)
        exit 0
        ;;
esac


# Parameters may be read from the environment, the command line arguments, and
# the store, with overriding in that order.  The environment is given by the
# driver, the command line is given by the Xend global configuration, and
# store details are given by the per-domain or per-device configuration.

evalVariables "$@"

ip=${ip:-}
ip=$(xenstore_read_default "$XENBUS_PATH/ip" "$ip")

# Check presence of compulsory args.
XENBUS_PATH="${XENBUS_PATH:?}"
vif="${vif:?}"


function frob_iptable()
{
  if [ "$command" == "online" ]
  then
    local c="-A"
  else
    local c="-D"
  fi

  iptables "$c" FORWARD -m physdev --physdev-in "$vif" "$@" -j ACCEPT ||
    fatal "iptables $c FORWARD -m physdev --physdev-in $vif $@ -j ACCEPT failed"
}


##
# Add or remove the appropriate entries in the iptables.  With antispoofing
# turned on, we have to explicitly allow packets to the interface, regardless
# of the ip setting.  If ip is set, then we additionally restrict the packets
# to those coming from the specified networks, though we allow DHCP requests
# as well.
#
function handle_iptable()
{
  # Check for a working iptables installation.  Checking for the iptables
  # binary is not sufficient, because the user may not have the appropriate
  # modules installed.  If iptables is not working, then there's no need to do
  # anything with it, so we can just return.
  if ! iptables -L >&/dev/null
  then
    return
  fi

  if [ "$ip" != "" ]
  then
      local addr
      for addr in "$ip"
      do
        frob_iptable -s "$addr"
      done

      # Always allow the domain to talk to a DHCP server.
      frob_iptable -p udp --sport 68 --dport 67
  else
      # No IP addresses have been specified, so allow anything.
      frob_iptable
  fi
}
