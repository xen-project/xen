
#############################################################
## xend/console.py -- Console-management functions for Xend
## Copyright (c) 2004, K A Fraser (University of Cambridge)
#############################################################

import errno, re, os, select, signal, socket, struct, sys


##
## interface:
##  Each control interface owns an instance of this class, which manages
##  the current state of the console interface. Normally a console interface
##  will be one of two state:
##   LISTENING: listening for a connection on TCP port 'self.port'
##   CONNECTED: sending/receiving console data on TCP port 'self.port'
##
##  A dictionary of all active interfaces, indexed by TCP socket descriptor,
##  is accessible as 'interface.interface_list'.
##
##  NB. When a class instance is to be destroyed you *must* call the 'close'
##  method. Otherwise a stale reference will eb left in the interface list.
##
class interface:

    # The various states that a console interface may be in.
    CLOSED    = 0 # No console activity
    LISTENING = 1 # Listening on port 'self.port'. Socket object 'self.sock'.
    CONNECTED = 2 # Active connection on 'self.port'. Socket obj 'self.sock'.


    # Dictionary of all active (non-closed) console interfaces.
    interface_list = {}


    # NB. 'key' is an opaque value that has no meaning in this class.
    def __init__(self, port, key):
        self.status = interface.CLOSED
        self.port   = port
        self.key    = key


    # Is this interface closed (inactive)?
    def closed(self):
        return self.status == interface.CLOSED


    # Is this interface listening?
    def listening(self):
        return self.status == interface.LISTENING


    # Is this interface active and connected?
    def connected(self):
        return self.status == interface.CONNECTED


    # Close the interface, if it is not closed already.
    def close(self):
        if not self.closed():
            del interface.interface_list[self.sock.fileno()]
            self.sock.close()
            del self.sock
            self.status = interface.CLOSED


    # Move the interface into the 'listening' state. Opens a new listening
    # socket and updates 'interface_list'.
    def listen(self):
        # Close old socket (if any), and create a fresh one.
        self.close()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)

        try:
            # Turn the new socket into a non-blocking listener.
            self.sock.setblocking(False)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                                 struct.pack('ii', 0, 0))
            self.sock.bind(('', self.port))
            self.sock.listen(1)

            # Announce the new status of thsi interface.
            self.status = interface.LISTENING
            interface.interface_list[self.sock.fileno()] = self

        except:
            # In case of trouble ensure we get rid of dangling socket reference
            self.sock.close()
            del self.sock
            raise


    # Move a listening interface into the 'connected' state.
    def connect(self):
        # Pick up a new connection, if one is available.
        try:
            (sock, addr) = self.sock.accept()
        except:
            return 0
        sock.setblocking(False)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                        struct.pack('ii', 0, 0))

        # Close the listening socket.
        self.sock.close()

        # Publish the new socket and the new interface state.
        self.sock = sock
        self.status = interface.CONNECTED
        interface.interface_list[self.sock.fileno()] = self
        return 1


