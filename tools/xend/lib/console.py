
#############################################################
## xend/console.py -- Console-management functions for Xend
## Copyright (c) 2004, K A Fraser (University of Cambridge)
#############################################################

import errno, re, os, select, signal, socket, struct, sys
import xend.blkif, xend.main, xend.manager, xend.utils, Xc

##
## interface:
##  Each control interface owns an instance of this class, which manages
##  the current state of the console interface. Normally a console interface
##  will be one of two state:
##   LISTENING: listening for a connection on TCP port 'self.port'
##   CONNECTED: sending/receiving console data on TCP port 'self.port'
##
##  A dictionary of all active interfaces, indexed by TCP socket descriptor,
##  is accessible as 'interface.list_by_fd'.
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
    list_by_fd = {}


    # Dictionary of all console interfaces, closed and open.
    list = {}


    # NB. 'key' is an opaque value that has no meaning in this class.
    def __init__(self, port, key):
        self.status = interface.CLOSED
        self.port   = port
        self.key    = key
        self.rbuf   = xend.utils.buffer()
        self.wbuf   = xend.utils.buffer()
        interface.list[key] = self


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
            del interface.list_by_fd[self.sock.fileno()]
            self.sock.close()
            del self.sock
            self.status = interface.CLOSED


    # Move the interface into the 'listening' state. Opens a new listening
    # socket and updates 'list_by_fd'.
    def listen(self):
        # Close old socket (if any), and create a fresh one.
        self.close()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)

        try:
            # Turn the new socket into a non-blocking listener.
            self.sock.setblocking(False)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind(('', self.port))
            self.sock.listen(1)

            # Announce the new status of thsi interface.
            self.status = interface.LISTENING
            interface.list_by_fd[self.sock.fileno()] = self

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
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # Close the listening socket.
        self.sock.close()

        # Publish the new socket and the new interface state.
        self.sock = sock
        self.status = interface.CONNECTED
        interface.list_by_fd[self.sock.fileno()] = self
        return 1


    # Completely sestroy a console interface.
    def destroy(self):
        self.close()
        del interface.list[self.key]


    # Do work triggered by resource availability on a console-interface socket.
    def socket_work(self):
        # If the interface is listening, check for pending connections.
        if self.listening():
            self.connect()

        # All done if the interface is not connected.
        if not self.connected():
            return

        # Send as much pending data as possible via the socket.
        while not self.rbuf.empty():
            try:
                bytes = self.sock.send(self.rbuf.peek())
                if bytes > 0:
                    self.rbuf.discard(bytes)
            except socket.error, error:
                pass

        # Read as much data as is available. Don't worry about
        # overflowing our buffer: it's more important to read the
        # incoming data stream and detect errors or closure of the
        # remote end in a timely manner.
        try:
            while 1:
                data = self.sock.recv(2048)
                # Return of zero means the remote end has disconnected.
                # We therefore return the console interface to listening.
                if not data:
                    self.listen()
                    break
                self.wbuf.write(data)
        except socket.error, error:
            # Assume that most errors mean that the connection is dead.
            # In such cases we return the interface to 'listening' state.
            if error[0] != errno.EAGAIN:
                print "Better return to listening"
                self.listen()
                print "New status: " + str(self.status)


    # The parameter @port is the control-interface event channel. This method
    # returns True if messages were written to the control interface.
    def ctrlif_transmit_work(self, port):
        work_done = False
        while not self.wbuf.empty() and port.space_to_write_request():
            msg = xend.utils.message(0, 0, 0)
            msg.append_payload(self.wbuf.read(msg.MAX_PAYLOAD))
            port.write_request(msg)
            work_done = True
        return work_done


    def ctrlif_rx_req(self, port, msg):
        self.rbuf.write(msg.get_payload())
        port.write_response(msg)
