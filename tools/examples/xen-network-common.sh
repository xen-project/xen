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
elif ! which ifup >&/dev/null
then
  if [ -e /etc/conf.d/net ]
  then
    preiftransfer()
    {
      true
    }
    ifup()
    {
      /etc/init.d/net.$1 start
    }
    ifdown()
    {
      /etc/init.d/net.$1 stop
    }
  else
    logger -p "daemon.crit" -- \
      "You don't have ifup and don't seem to be running Gentoo either!"
    exit 1
  fi
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
  first_file -x /etc/init.d/dhcp3-server /etc/init.d/dhcp
}
