#============================================================================
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
#============================================================================
# Copyright (C) 2004, 2005 Mike Wray <mike.wray@hp.com>
# Copyright (C) 2005 XenSource Ltd
#============================================================================

from xen.web.SrvDir import SrvDir

class SrvRoot(SrvDir):
    """The root of the xend server.
    """

    """Server sub-components. Each entry is (name, class), where
    'name' is the entry name and  'class' is the name of its class.
    """
    #todo Get this list from the XendOptions config.
    subdirs = [
        ('node',    'SrvNode'       ),
        ('domain',  'SrvDomainDir'  ),
        ('vnet',    'SrvVnetDir'    ),
        ]

    def __init__(self):
        SrvDir.__init__(self)
        for (name, klass) in self.subdirs:
            self.add(name, klass)
        for (name, klass) in self.subdirs:
            self.get(name)
        
    def __repr__(self):
        return "<SrvRoot %x %s>" %(id(self), self.table.keys())
