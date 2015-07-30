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
# License along with this library; If not, see <http://www.gnu.org/licenses/>.
#


# Gentoo doesn't have ifup/ifdown, so we define appropriate alternatives.

# Other platforms just use ifup / ifdown directly.

##
# preiftransfer
#
# @param $1 The current name for the physical device, which is also the name
#           that the virtual device will take once the physical device has
#           been renamed.

if ! which ifup >/dev/null 2>/dev/null
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

find_dhcpd_arg_file()
{
  first_file -f /etc/sysconfig/dhcpd /etc/defaults/dhcp /etc/default/dhcp3-server
}

# configure interfaces which act as pure bridge ports:
_setup_bridge_port() {
    local dev="$1"
    local virtual="$2"

    # take interface down ...
    ip link set dev ${dev} down

    if [ $virtual -ne 0 ] ; then
        # Initialise a dummy MAC address. We choose the numerically
        # largest non-broadcast address to prevent the address getting
        # stolen by an Ethernet bridge for STP purposes.
        # (FE:FF:FF:FF:FF:FF)
        ip link set dev ${dev} address fe:ff:ff:ff:ff:ff || true
    fi

    # ... and configure it
    ip address flush dev ${dev}
}

setup_physical_bridge_port() {
    _setup_bridge_port $1 0
}
setup_virtual_bridge_port() {
    _setup_bridge_port $1 1
}

# Usage: create_bridge bridge
create_bridge () {
    local bridge=$1

    # Don't create the bridge if it already exists.
    if [ ! -e "/sys/class/net/${bridge}/bridge" ]; then
	brctl addbr ${bridge}
	brctl stp ${bridge} off
	brctl setfd ${bridge} 0
    fi
}

# Usage: add_to_bridge bridge dev
add_to_bridge () {
    local bridge=$1
    local dev=$2

    # Don't add $dev to $bridge if it's already on a bridge.
    if [ -e "/sys/class/net/${bridge}/brif/${dev}" ]; then
	ip link set dev ${dev} up || true
	return
    fi
    brctl addif ${bridge} ${dev}
    ip link set dev ${dev} up
}

# Usage: set_mtu bridge dev
set_mtu () {
    local bridge=$1
    local dev=$2
    mtu="`ip link show dev ${bridge}| awk '/mtu/ { print $5 }'`"
    if [ -n "$mtu" ] && [ "$mtu" -gt 0 ]
    then
            ip link set dev ${dev} mtu $mtu || :
    fi
}
