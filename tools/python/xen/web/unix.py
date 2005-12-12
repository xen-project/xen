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


import socket
import os
import os.path

import connection


class UnixListener(connection.SocketListener):
    def __init__(self, path, protocol_class):
        self.path = path
        connection.SocketListener.__init__(self, protocol_class)


    def createSocket(self):
        pathdir = os.path.dirname(self.path)
        if not os.path.exists(pathdir):
            os.makedirs(pathdir)
        else:
            try:
                os.unlink(self.path)
            except SystemExit:
                raise
            except Exception, ex:
                pass
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(self.path)
        return sock


    def acceptConnection(self, sock, _):
        connection.SocketServerConnection(sock, self.protocol_class)
