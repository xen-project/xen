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
# Copyright (C) 2005-2006 XenSource Ltd.
#============================================================================


import os
import os.path
import socket
import stat

import connection


def bind(path):
    """Create a Unix socket, and bind it to the given path.  The socket is
created such that only the current user may access it."""

    parent = os.path.dirname(path)
    if os.path.exists(parent):
        os.chown(parent, os.geteuid(), os.getegid())
        os.chmod(parent, stat.S_IRWXU)
        if os.path.exists(path):
            os.unlink(path)
    else:
        os.makedirs(parent, stat.S_IRWXU)

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.bind(path)
    return sock


class UnixListener(connection.SocketListener):
    def __init__(self, path, protocol_class):
        self.path = path
        connection.SocketListener.__init__(self, protocol_class)


    def createSocket(self):
        return bind(self.path)


    def acceptConnection(self, sock, _):
        connection.SocketServerConnection(sock, self.protocol_class)
