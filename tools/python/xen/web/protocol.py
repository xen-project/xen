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
# Copyright (C) 2005 Mike Wray <mike.wray@hp.com>
# Copyright (C) 2005 XenSource Ltd.
#============================================================================

class Protocol:

    def __init__(self):
        self.transport = None

    def setTransport(self, transport):
        self.transport = transport

    def dataReceived(self, data):
        raise NotImplementedError()

    def write(self, data):
        if self.transport:
            return self.transport.write(data)
        else:
            return 0

    def read(self):
        if self.transport:
            return self.transport.read()
        else:
            return None
