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
  first_file -f /etc/dhcp/dhcpd.conf /etc/dhcp3/dhcpd.conf /etc/dhcpd.conf
}


find_dhcpd_init_file()
{
  first_file -x /etc/init.d/{isc-dhcp-server,dhcp-server,dhcp3-server,dhcp,dhcpd}
}

find_dhcpd_arg_file()
{
  first_file -f /etc/sysconfig/dhcpd /etc/defaults/dhcp /etc/default/dhcp-server /etc/default/dhcp3-server
}

# configure interfaces which act as pure bridge ports:
setup_bridge_port() {
    local dev="$1"

    # take interface down ...
    ip link set dev ${dev} down

    # Initialise a dummy MAC address. We choose the numerically
    # largest non-broadcast address to prevent the address getting
    # stolen by an Ethernet bridge for STP purposes.
    # (FE:FF:FF:FF:FF:FF)
    ip link set dev ${dev} address fe:ff:ff:ff:ff:ff || true

    # ... and configure it
    ip address flush dev ${dev}
}

# Usage: create_bridge bridge
create_bridge () {
    local bridge=$1

    # Don't create the bridge if it already exists.
    if [ ! -e "/sys/class/net/${bridge}/bridge" ]; then
        if which brctl >&/dev/null; then
            brctl addbr ${bridge}
            brctl stp ${bridge} off
            brctl setfd ${bridge} 0
        else
            ip link add name ${bridge} type bridge stp_state 0 forward_delay 0
        fi
    fi
}

_vif_vlan_add() {
    # References vlans and pvid variables from the calling function
    local -i vid=$1
    local flag=${2:-}

    if (( vid < 1 || vid > 4094 )) ;then
        fatal "vlan id $vid not between 1 and 4094"
    fi
    if [[ -n "${vlans[$vid]}" ]] ;then
        fatal "vlan id $vid specified more than once"
    fi
    case $flag in
     p) if (( pvid != 0 )) ;then
            fatal "more than one pvid specified ($vid and $pvid)"
        fi
        pvid=$vid
        vlans[$vid]=p ;;
     u) vlans[$vid]=u ;;
     *) vlans[$vid]=t ;;
    esac
}

_vif_vlan_parse_term() {
    local vid incr last term=${1:-}

    if [[ $term =~ ^([0-9]+)([pu])?$ ]] ;then
        _vif_vlan_add ${BASH_REMATCH[1]} ${BASH_REMATCH[2]}
    elif [[ $term =~ ^([0-9]+)-([0-9]+)(u)?$ ]] ;then
        vid=${BASH_REMATCH[1]}
        last=${BASH_REMATCH[2]}
        if (( last >= vid )) ;then
            for (( ; vid<=last; vid++ )) ;do
                _vif_vlan_add $vid ${BASH_REMATCH[3]}
            done
        else
            fatal "invalid vlan id range: $term"
        fi
    elif [[ $term =~ ^([0-9]+)\+([0-9]+)x([0-9]+)(u)?$ ]] ;then
        vid=${BASH_REMATCH[1]}
        incr=${BASH_REMATCH[2]}
        for (( j=${BASH_REMATCH[3]}; j>0; --j, vid+=incr ))
        do
            _vif_vlan_add $vid ${BASH_REMATCH[4]}
        done
    else
        fatal "invalid vlan specification: $term"
    fi
}

_vif_vlan_validate_pvid() {
    # References vlans and pvid variables from the calling function
    if (( pvid == 0 )) ;then
        if (( ${#vlans[@]} == 1 )) ;then
            vlans[${!vlans[*]}]=p
        else
            fatal "pvid required when using multiple vlan ids"
        fi
    fi
}

_vif_vlan_setup() {
    # References vlans and dev variable from the calling function
    local -i vid
    local -a args

    # Remove the default vlan id automatically added to the vif
    bridge vlan del dev $dev vid 1

    # Add the required vlans
    for vid in ${!vlans[@]} ;do
        case ${vlans[$vid]} in
             p) args=(pvid untagged) ;;
             u) args=(untagged) ;;
             t) args=() ;;
        esac
        bridge vlan add dev $dev vid $vid ${args[@]}
    done
}

_vif_vlan_membership() {
    # The vlans, pvid and dev variables are used by sub-functions
    local -A vlans=()
    local -a terms=()
    local -i i pvid=0
    local dev=$1 term

    # Split the vlan specification string into its terms, removing the newline
    # that readarray adds to the last element
    readarray -d / -t terms <<<$2
    terms[-1]=${terms[-1]%%[[:space:]]}

    for term in ${terms[@]} ;do
        _vif_vlan_parse_term $term
    done

    _vif_vlan_validate_pvid
    _vif_vlan_setup
    return 0
}

# Usage: add_to_bridge bridge dev
add_to_bridge () {
    local bridge=$1
    local dev=$2
    local vlan=$(xenstore_read_default "$XENBUS_PATH/vlan" "")

    # Don't add $dev to $bridge if it's already on the bridge.
    if [ ! -e "/sys/class/net/${bridge}/brif/${dev}" ]; then
        log debug "adding $dev to bridge $bridge"
        if which brctl >&/dev/null; then
            brctl addif ${bridge} ${dev}
        else
            ip link set ${dev} master ${bridge}
        fi
        if [ -n "${vlan}" ] ;then
            log debug "configuring vlans for ${dev} on ${bridge}"
            if which bridge >&/dev/null; then
                _vif_vlan_membership "${dev}" "${vlan}"
            else
                fatal "vlan configuration failed: bridge command not found"
            fi
        fi
    else
        log debug "$dev already on bridge $bridge"
    fi

    ip link set dev ${dev} up
}

remove_from_bridge () {
    local bridge=$1
    local dev=$2

    do_without_error ip link set dev ${dev} down

    # Don't remove $dev from $bridge if it's not on the bridge.
    if [ -e "/sys/class/net/${bridge}/brif/${dev}" ]; then
        log debug "removing $dev from bridge $bridge"
        if which brctl >&/dev/null; then
            do_without_error brctl delif ${bridge} ${dev}
        else
            do_without_error ip link set ${dev} nomaster
        fi
    else
        log debug "$dev not on bridge $bridge"
    fi
}

# Usage: set_mtu bridge dev
set_mtu () {
    local bridge=$1
    local dev=$2
    local type_if=$3

    XENBUS_PATH="${XENBUS_PATH:?}"

    local mtu=$(xenstore_read_default "$XENBUS_PATH/mtu" "")
    if [ -z "$mtu" ]
    then
        mtu="$(ip link show dev ${bridge}| awk '/mtu/ { print $5 }')"
        if [ -n "$mtu" ]
        then
            log debug "$bridge MTU is $mtu"
        fi
    fi
    if [ -n "$mtu" ] && [ "$mtu" -ge 68 ]
    then
        log debug "setting $dev MTU to $mtu"
        ip link set dev ${dev} mtu ${mtu} || :

        if [ ${type_if} = vif ]
        then
            local FRONTEND_PATH="$(xenstore_read "$XENBUS_PATH/frontend")"

            xenstore_write "$FRONTEND_PATH/mtu" ${mtu}
        fi
    fi
}
