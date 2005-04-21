import sys
import socket
import types

from connection import *
from protocol import *

class TCPServerConnection(SocketServerConnection):
    pass

class TCPListener(SocketListener):

    def __init__(self, port, factory, backlog=None, interface=''):
        SocketListener.__init__(self, factory, backlog=backlog)
        self.port = port
        self.interface = interface
        
    def createSocket(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        addr = (self.interface, self.port)
        sock.bind(addr)
        return sock

    def acceptConnection(self, sock, protocol, addr):
        return TCPServerConnection(sock, protocol, addr, self)

class TCPClientConnection(SocketClientConnection):

    def __init__(self, host, port, bindAddress, connector):
        SocketClientConnection.__init__(self, connector)
        self.addr = (host, port)
        self.bindAddress = bindAddress

    def createSocket(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if self.bindAddress is not None:
            sock.bind(self.bindAddress)
        return sock
    
class TCPConnector(SocketConnector):

    def __init__(self, host, port, factory, timeout=None, bindAddress=None):
        SocketConnector.__init__(self, factory)
        self.host = host
        self.port = self.servicePort(port)
        self.bindAddress = bindAddress
        self.timeout = timeout

    def servicePort(self, port):
        if isinstance(port, types.StringTypes):
            try:
                port = socket.getservbyname(port, 'tcp')
            except socket.error, ex:
                raise IOError("unknown service: " + ex)
        return port

    def getDestination(self):
        return (self.host, self.port)

    def connectTransport(self):
        self.transport = TCPClientConnection(
            self.host, self.port, self.bindAddress, self)
        self.transport.connect(self.timeout)

def listenTCP(port, factory, interface='', backlog=None):
    l = TCPListener(port, factory, interface=interface, backlog=backlog)
    l.startListening()
    return l

def connectTCP(host, port, factory, timeout=None, bindAddress=None):
    c = TCPConnector(host, port, factory, timeout=timeout, bindAddress=bindAddress)
    c.connect()
    return c

def main(argv):
    host = 'localhost'
    port = 8005
    if argv[1] == "client":
        c = connectTCP(host, port, TestClientFactory())
        print 'client:', c
    else:
        s = listenTCP(port, TestServerFactory())
        print 'server:', s
        
if __name__ == "__main__":
    main(sys.argv)

        

