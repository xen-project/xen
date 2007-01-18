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


# On SuSE it is necessary to run a command before transfering addresses and
# routes from the physical interface to the virtual.  This command creates a
# variable $HWD_CONFIG_0 that specifies the appropriate configuration for
# ifup.

# Gentoo doesn't have ifup/ifdown, so we define appropriate alternatives.

# Other platforms just use ifup / ifdown directly.

##
# preiftransfer
#
# @param $1 The current name for the physical device, which is also the name
#           that the virtual device will take once the physical device has
#           been renamed.

if [ -e /etc/SuSE-release ]
then
  preiftransfer()
  {
    eval `/sbin/getcfg -d /etc/sysconfig/network/ -f ifcfg- -- $1`
  }
  ifup()
  {
    /sbin/ifup ${HWD_CONFIG_0} $1
  }
elif ! which ifup >/dev/null 2>/dev/null
then
  preiftransfer()
  {
    true
  }
  ifup()
  {
    false
  }
  ifdown()
  {
    false
  }
else
  preiftransfer()
  {
    true
  }
fi


first_file()
{
  t="$1"
  shift
  for file in $@
  do
    if [ "$t" "$file" ]
    then
      echo "$file"
      return
    fi
  done
}

find_dhcpd_conf_file()
{
  first_file -f /etc/dhcp3/dhcpd.conf /etc/dhcpd.conf
}


find_dhcpd_init_file()
{
  first_file -x /etc/init.d/{dhcp3-server,dhcp,dhcpd}
}

# configure interfaces which act as pure bridge ports:
#  - make quiet: no arp, no multicast (ipv6 autoconf)
#  - set mac address to fe:ff:ff:ff:ff:ff
setup_bridge_port() {
    local dev="$1"

    # take interface down ...
    ip link set ${dev} down

    # ... and configure it
    ip link set ${dev} arp off
    ip link set ${dev} multicast off
    ip link set ${dev} addr fe:ff:ff:ff:ff:ff
    ip addr flush ${dev}
}

# Usage: create_bridge bridge
create_bridge () {
    local bridge=$1

    # Don't create the bridge if it already exists.
    if [ ! -e "/sys/class/net/${bridge}/bridge" ]; then
	brctl addbr ${bridge}
	brctl stp ${bridge} off
	brctl setfd ${bridge} 0
        ip link set ${bridge} arp off
        ip link set ${bridge} multicast off
    fi

    # A small MTU disables IPv6 (and therefore IPv6 addrconf).
    mtu=$(ip link show ${bridge} | sed -n 's/.* mtu \([0-9]\+\).*/\1/p')
    ip link set ${bridge} mtu 68
    ip link set ${bridge} up
    ip link set ${bridge} mtu ${mtu:-1500}
}

# Usage: add_to_bridge bridge dev
add_to_bridge () {
    local bridge=$1
    local dev=$2

    # Don't add $dev to $bridge if it's already on a bridge.
    if [ -e "/sys/class/net/${bridge}/brif/${dev}" ]; then
	ip link set ${dev} up || true
	return
    fi
    brctl addif ${bridge} ${dev}
    ip link set ${dev} up
}

