#============================================================================
# This library is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation; either version 2.1 of the License, or
# (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this library; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#============================================================================
# Copyright (C) 2005 Mike Wray <mike.wray@hp.com>
# Copyright (C) 2005 XenSource Ltd.
#============================================================================

import sys
import os
import threading
import socket
import fcntl

from errno import EAGAIN, EINTR, EWOULDBLOCK

try:
    from OpenSSL import SSL
except ImportError:
    pass

from xen.xend.XendLogging import log

"""General classes to support server and client sockets, without
specifying what kind of socket they are. There are subclasses
for TCP and unix-domain sockets (see tcp.py and unix.py).
"""

BUFFER_SIZE = 16384
BACKLOG = 5


class SocketServerConnection:
    """An accepted connection to a server.
    """

    def __init__(self, sock, protocol_class):
        self.sock = sock
        self.protocol = protocol_class()
        self.protocol.setTransport(self)
        threading.Thread(target=self.main).start()


    def main(self):
        try:
            while True:
                try:
                    data = self.sock.recv(BUFFER_SIZE)
                    if data == '':
                        break
                    if self.protocol.dataReceived(data):
                        break
                except socket.error, ex:
                    if ex.args[0] not in (EWOULDBLOCK, EAGAIN, EINTR):
                        break
        finally:
            try:
                self.sock.close()
            except:
                pass


    def close(self):
        self.sock.close()


    def write(self, data):
        self.sock.send(data)


class SocketListener:
    """A server socket, running listen in a thread.
    Accepts connections and runs a thread for each one.
    """

    def __init__(self, protocol_class):
        self.protocol_class = protocol_class
        self.sock = self.createSocket()
        threading.Thread(target=self.main).start()


    def close(self):
        try:
            self.sock.close()
        except:
            pass


    def createSocket(self):
        raise NotImplementedError()


    def acceptConnection(self, sock, protocol, addr):
        raise NotImplementedError()


    def main(self):
        try:
            fcntl.fcntl(self.sock.fileno(), fcntl.F_SETFD, fcntl.FD_CLOEXEC)
            self.sock.listen(BACKLOG)

            while True:
                try:
                    (sock, addr) = self.sock.accept()
                    self.acceptConnection(sock, addr)
                except socket.error, ex:
                    if ex.args[0] not in (EWOULDBLOCK, EAGAIN, EINTR):
                        break
        finally:
            self.close()


class SSLSocketServerConnection(SocketServerConnection):
    """An SSL aware accepted connection to a server.

    As pyOpenSSL SSL.Connection fileno() method just retrieve the file
    descriptor number for the underlying socket, direct read/write to the file
    descriptor will result no data encrypted.
    
    recv2fd() and fd2send() are simple wrappers for functions who need direct
    read/write to a file descriptor rather than a socket like object.
    
    To use recv2fd(), you can create a pipe and start a thread to transfer all
    received data to one end of the pipe, then read from the other end:
    
    p2cread, p2cwrite = os.pipe()
    threading.Thread(target=connection.SSLSocketServerConnection.recv2fd,
                     args=(sock, p2cwrite)).start()
    os.read(p2cread, 1024)
    
    To use fd2send():
    
    p2cread, p2cwrite = os.pipe()
    threading.Thread(target=connection.SSLSocketServerConnection.fd2send,
                     args=(sock, p2cread)).start()
    os.write(p2cwrite, "data")
    """

    def __init__(self, sock, protocol_class):
        SocketServerConnection.__init__(self, sock, protocol_class)


    def main(self):
        try:
            while True:
                try:
                    data = self.sock.recv(BUFFER_SIZE)
                    if data == "":
                        break
                    if self.protocol.dataReceived(data):
                        break
                except socket.error, ex:
                    if ex.args[0] not in (EWOULDBLOCK, EAGAIN, EINTR):
                        break
                except (SSL.WantReadError, SSL.WantWriteError, \
                        SSL.WantX509LookupError):
                    # The operation did not complete; the same I/O method
                    # should be called again.
                    continue
                except SSL.ZeroReturnError:
                    # The SSL Connection has been closed.
                    break
                except SSL.SysCallError, (retval, desc):
                    if ((retval == -1 and desc == "Unexpected EOF")
                        or retval > 0):
                        # The SSL Connection is lost.
                        break
                    log.debug("SSL SysCallError:%d:%s" % (retval, desc))
                    break
                except SSL.Error, e:
                    # other SSL errors
                    log.debug("SSL Error:%s" % e)
                    break
        finally:
            try:
                self.sock.close()
            except:
                pass


    def recv2fd(sock, fd):
        try:
            while True:
                try:
                    data = sock.recv(BUFFER_SIZE)
                    if data == "":
                        break
                    count = 0
                    while count < len(data):
                        try:
                            nbytes = os.write(fd, data[count:])
                            count += nbytes
                        except os.error, ex:
                            if ex.args[0] not in (EWOULDBLOCK, EAGAIN, EINTR):
                                raise
                except socket.error, ex:
                    if ex.args[0] not in (EWOULDBLOCK, EAGAIN, EINTR):
                        break
                except (SSL.WantReadError, SSL.WantWriteError, \
                        SSL.WantX509LookupError):
                    # The operation did not complete; the same I/O method
                    # should be called again.
                    continue
                except SSL.ZeroReturnError:
                    # The SSL Connection has been closed.
                    break
                except SSL.SysCallError, (retval, desc):
                    if ((retval == -1 and desc == "Unexpected EOF")
                        or retval > 0):
                        # The SSL Connection is lost.
                        break
                    log.debug("SSL SysCallError:%d:%s" % (retval, desc))
                    break
                except SSL.Error, e:
                    # other SSL errors
                    log.debug("SSL Error:%s" % e)
                    break
        finally:
            try:
                sock.close()
                os.close(fd)
            except:
                pass

    recv2fd = staticmethod(recv2fd)


    def fd2send(sock, fd):
        try:
            while True:
                try:
                    data = os.read(fd, BUFFER_SIZE)
                    if data == "":
                        break
                    count = 0
                    while count < len(data):
                        try:
                            nbytes = sock.send(data[count:])
                            count += nbytes
                        except socket.error, ex:
                            if ex.args[0] not in (EWOULDBLOCK, EAGAIN, EINTR):
                                raise
                        except (SSL.WantReadError, SSL.WantWriteError, \
                                SSL.WantX509LookupError):
                            # The operation did not complete; the same I/O method
                            # should be called again.
                            continue
                        except SSL.ZeroReturnError:
                            # The SSL Connection has been closed.
                            raise
                        except SSL.SysCallError, (retval, desc):
                            if not (retval == -1 and data == ""):
                                # errors when writing empty strings are expected
                                # and can be ignored
                                log.debug("SSL SysCallError:%d:%s" % (retval, desc))
                                raise
                        except SSL.Error, e:
                            # other SSL errors
                            log.debug("SSL Error:%s" % e)
                            raise
                except os.error, ex:
                    if ex.args[0] not in (EWOULDBLOCK, EAGAIN, EINTR):
                        break
        finally:
            try:
                sock.close()
                os.close(fd)
            except:
                pass

    fd2send = staticmethod(fd2send)


def hostAllowed(addrport, hosts_allowed):
    if hosts_allowed is None:
        return True
    else:
        fqdn = socket.getfqdn(addrport[0])
        for h in hosts_allowed:
            if h.match(fqdn) or h.match(addrport[0]):
                return True
        log.warn("Rejected connection from %s (%s).", addrport[0], fqdn)
        return False


class SocketDgramListener:
    """A connectionless server socket, running listen in a thread.
    """

    def __init__(self, protocol_class):
        self.protocol = protocol_class()
        self.sock = self.createSocket()
        threading.Thread(target=self.main).start()


    def close(self):
        try:
            self.sock.close()
        except:
            pass


    def createSocket(self):
        raise NotImplementedError()


    def main(self):
        try:
            fcntl.fcntl(self.sock.fileno(), fcntl.F_SETFD, fcntl.FD_CLOEXEC)

            while True:
                try:
                    data = self.sock.recv(BUFFER_SIZE)
                    self.protocol.dataReceived(data)
                except socket.error, ex:
                    if ex.args[0] not in (EWOULDBLOCK, EAGAIN, EINTR):
                        break
        finally:
            try:
                self.close()
            except:
                pass
