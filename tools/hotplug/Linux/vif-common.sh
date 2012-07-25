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


# Parameters may be read from the environment, the command line arguments, and
# the store, with overriding in that order.  The environment is given by the
# driver, the command line is given by the Xend global configuration, and
# store details are given by the per-domain or per-device configuration.

evalVariables "$@"

# Older versions of Xen do not pass in the type as an argument,
# so the default value is vif.
: ${type_if:=vif}

case "$type_if" in
    vif)
        dev=$vif
        ;;
    tap)
        dev=$INTERFACE
        ;;
    *)
        log err "unknown interface type $type_if"
        exit 1
        ;;
esac

case "$command" in
    online | offline)
        test "$type_if" != vif && exit 0
        ;;
    add | remove)
        test "$type_if" != tap && exit 0
        ;;
esac

rename_vif() {
    local dev=$1
    local vifname=$2

    # if a custom vifname was chosen and a link with that desired name
    # already exists, then stop, before messing up whatever is using
    # that interface (e.g. another running domU) because it's likely a
    # configuration error
    if ip link show "$vifname" >&/dev/null
    then
        fatal "Cannot rename interface $dev. An interface with name $vifname already exists."
    fi
    do_or_die ip link set "$dev" name "$vifname"
}

if [ "$type_if" = vif ]; then
    # Check presence of compulsory args.
    XENBUS_PATH="${XENBUS_PATH:?}"
    dev="${dev:?}"

    vifname=$(xenstore_read_default "$XENBUS_PATH/vifname" "")
    if [ "$vifname" ]
    then
        if [ "$command" == "online" ]
        then
            rename_vif "$dev" "$vifname"
        fi
        dev="$vifname"
    fi
elif [ "$type_if" = tap ]; then
    # Check presence of compulsory args.
    : ${INTERFACE:?}

    # Get xenbus_path from device name.
    # The name is built like that: "vif${domid}.${devid}-emu".
    dev_=${dev#vif}
    dev_=${dev_%-emu}
    domid=${dev_%.*}
    devid=${dev_#*.}

    XENBUS_PATH="/local/domain/0/backend/vif/$domid/$devid"
    vifname=$(xenstore_read_default "$XENBUS_PATH/vifname" "")
    if [ "$vifname" ]
    then
        vifname="${vifname}-emu"
        if [ "$command" == "add" ]
        then
            rename_vif "$dev" "$vifname"
        fi
        dev="$vifname"
    fi
fi

ip=${ip:-}
ip=$(xenstore_read_default "$XENBUS_PATH/ip" "$ip")

frob_iptable()
{
  if [ "$command" == "online" ]
  then
    local c="-I"
  else
    local c="-D"
  fi

  iptables "$c" FORWARD -m physdev --physdev-is-bridged --physdev-in "$dev" \
    "$@" -j ACCEPT 2>/dev/null &&
  iptables "$c" FORWARD -m physdev --physdev-is-bridged --physdev-out "$dev" \
    -j ACCEPT 2>/dev/null

  if [ "$command" == "online" -a $? -ne 0 ]
  then
    log err "iptables setup failed. This may affect guest networking."
  fi
}


##
# Add or remove the appropriate entries in the iptables.  With antispoofing
# turned on, we have to explicitly allow packets to the interface, regardless
# of the ip setting.  If ip is set, then we additionally restrict the packets
# to those coming from the specified networks, though we allow DHCP requests
# as well.
#
handle_iptable()
{
  # Check for a working iptables installation.  Checking for the iptables
  # binary is not sufficient, because the user may not have the appropriate
  # modules installed.  If iptables is not working, then there's no need to do
  # anything with it, so we can just return.
  if ! iptables -L -n >&/dev/null
  then
    return
  fi

  claim_lock "iptables"

  if [ "$ip" != "" ]
  then
      local addr
      for addr in $ip
      do
        frob_iptable -s "$addr"
      done

      # Always allow the domain to talk to a DHCP server.
      frob_iptable -p udp --sport 68 --dport 67
  else
      # No IP addresses have been specified, so allow anything.
      frob_iptable
  fi

  release_lock "iptables"
}


##
# ip_of interface
#
# Print the IP address currently in use at the given interface, or nothing if
# the interface is not up.
#
ip_of()
{
  ip -4 -o addr show primary dev "$1" | awk '$3 == "inet" {split($4,i,"/"); print i[1]; exit}'
}


##
# dom0_ip
#
# Print the IP address of the interface in dom0 through which we are routing.
# This is the IP address on the interface specified as "netdev" as a parameter
# to these scripts, or eth0 by default.  This function will call fatal if no
# such interface could be found.
#
dom0_ip()
{
  local nd=${netdev:-eth0}
  local result=$(ip_of "$nd")
  if [ -z "$result" ]
  then
      fatal
"$netdev is not up.  Bring it up or specify another interface with " \
"netdev=<if> as a parameter to $0."
  fi
  echo "$result"
}
