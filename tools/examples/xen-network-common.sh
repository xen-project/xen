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


# Gentoo doesn't have ifup/ifdown: define appropriate alternatives
if ! which ifup >&/dev/null
then
  if [ -e /etc/conf.d/net ]
  then
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
fi
