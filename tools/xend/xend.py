#!/usr/bin/env python


###########################################################
## xend.py -- Xen controller daemon
## Copyright (c) 2004, K A Fraser (University of Cambridge)
###########################################################


import errno, re, os, pwd, select, signal, socket, struct, sys, tempfile, time
import xend_utils, Xc



# The following parameters could be placed in a configuration file.
PID  = '/var/run/xend.pid'
LOG  = '/var/log/xend.log'
USER = 'root'
CONTROL_DIR  = '/var/run/xend'
UNIX_SOCK    = 'management_sock' # relative to CONTROL_DIR



##
## console_interface:
##  Each control interface owns an instance of this class, which manages
##  the current state of the console interface. Normally a console interface
##  will be one of two state:
##   LISTENING: listening for a connection on TCP port 'self.port'
##   CONNECTED: sending/receiving console data on TCP port 'self.port'
##
##  A dictionary of all active interfaces, indexed by TCP socket descriptor,
##  is accessible as 'console_interface.interface_list'.
##
##  NB. When a class instance is to be destroyed you *must* call the 'close'
##  method. Otherwise a stale reference will eb left in the interface list.
##
class console_interface:

    # The various states that a console interface may be in.
    CLOSED    = 0 # No console activity
    LISTENING = 1 # Listening on port 'self.port'. Socket object 'self.sock'.
    CONNECTED = 2 # Active connection on 'self.port'. Socket obj 'self.sock'.


    # Dictionary of all active (non-closed) console interfaces.
    interface_list = {}


    # NB. 'key' is an opaque value that has no meaning in this class.
    def __init__(self, port, key):
        self.status = console_interface.CLOSED
        self.port   = port
        self.key    = key


    # Is this interface closed (inactive)?
    def closed(self):
        return self.status == console_interface.CLOSED


    # Is this interface listening?
    def listening(self):
        return self.status == console_interface.LISTENING


    # Is this interface active and connected?
    def connected(self):
        return self.status == console_interface.CONNECTED


    # Close the interface, if it is not closed already.
    def close(self):
        if not self.closed():
            del console_interface.interface_list[self.sock.fileno()]
            self.sock.close()
            del self.sock
            self.status = console_interface.CLOSED


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
            self.status = console_interface.LISTENING
            console_interface.interface_list[self.sock.fileno()] = self

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
        self.status = console_interface.CONNECTED
        console_interface.interface_list[self.sock.fileno()] = self
        return 1



##
## new_control_interface:
##  Create a new control interface with the specified domain 'dom'.
##  The console port may also be specified; otehrwise a suitable port is
##  automatically allocated.
##
def new_control_interface(dom, console_port=-1):
    # Allocate an event channel. Clear pending notifications.
    port = xend_utils.port(dom)
    notifier.clear(port.local_port, notifier.NORMAL)
    notifier.clear(port.local_port, notifier.DISCONNECT)
    
    # If necessary, compute a suitable TCP port for console I/O.
    if console_port < 0:
        console_port = 9600 + port.local_port

    # Create a listenign console interface.
    con_if = console_interface(console_port, port.local_port)
    con_if.listen()

    # Add control state to the master list.
    control_list[port.local_port] = \
      (port, xend_utils.buffer(), xend_utils.buffer(), con_if)

    # Construct the successful response to be returned to the requester.
    response = { 'success': True }
    response['local_port']   = port.local_port
    response['remote_port']  = port.remote_port
    response['console_port'] = console_port
    return response


        
def daemon_loop():
    global control_list, notifier

    xc = Xc.new()
    control_list = {}

    # Ignore writes to disconnected sockets. We clean up differently.
    signal.signal(signal.SIGPIPE, signal.SIG_IGN)

    # Construct the management interface. This is a UNIX domain socket via
    # which we receive 'request' datagrams. Each request is a string that
    # can be eval'ed as a Python statement. Responses can be remotely eval'ed
    # by the requester to create a Python dictionary of result values.
    management_interface = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM, 0)
    if os.path.exists(CONTROL_DIR+'/'+UNIX_SOCK):
        os.unlink(CONTROL_DIR+'/'+UNIX_SOCK)
    management_interface.setblocking(False)
    management_interface.bind(CONTROL_DIR+'/'+UNIX_SOCK)

    notifier = xend_utils.notifier()

    ##
    ## MAIN LOOP
    ## 
    while 1:

        # Construct a poll set. We wait on:
        #  1. Requests on the management interface.
        #  2. Incoming event-channel notifications.
        # Furthermore, for each active control interface:
        #  3. Incoming console data.
        #  4. Space for outgoing console data (if there is data to send).
        waitset = select.poll()
        waitset.register(management_interface, select.POLLIN)
        waitset.register(notifier, select.POLLIN)
        for idx, (port, rbuf, wbuf, con_if) in control_list.items():
            if not con_if.closed():
                pflags = select.POLLIN
                if not rbuf.empty() and con_if.connected():
                    pflags = select.POLLIN | select.POLLOUT
                waitset.register(con_if.sock.fileno(), pflags)

        # Wait for something to do...
        fdset = waitset.poll()
        
        # Look for messages on the management interface.
        # These should consist of executable Python statements that call
        # well-known management functions (e.g., new_control_interface(dom=9)).
        try:
            data, addr = management_interface.recvfrom(2048)
        except socket.error, error:
            if error[0] != errno.EAGAIN:
                raise
        else:
            if addr:
                # Evaluate the request in an exception-trapping sandbox.
                try:
                    print "Mgmt_req[%s]: %s" % (addr, data)
                    response = str(eval(data))

                except:
                    # Catch all exceptions and turn into an error response:
                    #  status:          False
                    #  error_type:      'exception'
                    #  exception_type:  name of exception type.
                    #  exception value: textual exception value.
                    exc_type, exc_val = sys.exc_info()[:2]
                    response = { 'success': False }
                    response['error_type'] = 'exception'
                    response['exception_type'] = str(exc_type)
                    response['exception_value'] = str(exc_val)
                    response = str(response)

                # Try to send a response to the requester.
                try:
                    print "Mgmt_rsp[%s]: %s" % (addr, response)
                    management_interface.sendto(response, addr)
                except socket.error, error:
                    pass
                
        # Do work for every console interface that hit in the poll set.
        for (fd, events) in fdset:
            if not console_interface.interface_list.has_key(fd):
                continue
            con_if = console_interface.interface_list[fd]

            # If the interface is listening, check for pending connections.
            if con_if.listening():
                con_if.connect()

            # All done if the interface is not connected.
            if not con_if.connected():
                continue
            (port, rbuf, wbuf, con_if) = control_list[con_if.key]

            # Send as much pending data as possible via the socket.
            while not rbuf.empty():
                try:
                    bytes = con_if.sock.send(rbuf.peek())
                    if bytes > 0:
                        rbuf.discard(bytes)
                except socket.error, error:
                    pass

            # Read as much data as is available. Don't worry about
            # overflowing our buffer: it's more important to read the
            # incoming data stream and detect errors or closure of the
            # remote end in a timely manner.
            try:
                while 1:
                    data = con_if.sock.recv(2048)
                    # Return of zero means the remote end has disconnected.
                    # We therefore return the console interface to listening.
                    if not data:
                        con_if.listen()
                        break
                    wbuf.write(data)
            except socket.error, error:
                # Assume that most errors mean that the connection is dead.
                # In such cases we return the interface to 'listening' state.
                if error[0] != errno.EAGAIN:
                    print "Better return to listening"
                    con_if.listen()
                    print "New status: " + str(con_if.status)

            # We may now have pending data to send via the relevant
            # inter-domain control interface. If so then we send all we can
            # and notify the remote end.
            work_done = False
            while not wbuf.empty() and port.space_to_write_request():
                msg = xend_utils.message(0, 0, 0)
                msg.append_payload(wbuf.read(msg.MAX_PAYLOAD))
                port.write_request(msg)
                work_done = True
            if work_done:
                port.notify()

        # Process control-interface notifications from other guest OSes.
        while 1:            
            # Grab a notification, if there is one.
            notification = notifier.read()
            if not notification:
                break
            (idx, type) = notification

            # If we pick up a disconnect notification then we do any necessary
            # cleanup, even if the event channel doesn't belong to us.
            # This is intended to prevent the event-channel port space from
            # getting clogged with stale connections.
            if type == notifier.DISCONNECT:
                ret = xc.evtchn_status(idx)
                if ret['status'] != 'connected':
                    notifier.clear(idx, notifier.NORMAL)
                    notifier.clear(idx, notifier.DISCONNECT)
                    if control_list.has_key(idx):
                        (port, rbuf, wbuf, con_if) =  control_list[idx]
                        con_if.close()
                        del control_list[idx], port, rbuf, wbuf, con_if
                    elif ret['status'] == 'disconnected':
                        # There's noone to do the closure for us...
                        xc.evtchn_close(idx)

            # A standard notification: probably means there are messages to
            # read or that there is space to write messages.
            elif type == notifier.NORMAL and control_list.has_key(idx):
                (port, rbuf, wbuf, con_if) = control_list[idx]
                work_done = False

                # We clear the notification before doing any work, to avoid
                # races.
                notifier.clear(idx, notifier.NORMAL)

                # Read incoming requests. Currently assume that request
                # message always containb console data.
                while port.request_to_read():
                    msg = port.read_request()
                    rbuf.write(msg.get_payload())
                    port.write_response(msg)
                    work_done = True

                # Incoming responses are currently thrown on the floor.
                while port.response_to_read():
                    msg = port.read_response()
                    work_done = True

                # Send as much pending console data as there is room for.
                while not wbuf.empty() and port.space_to_write_request():
                    msg = xend_utils.message(0, 0, 0)
                    msg.append_payload(wbuf.read(msg.MAX_PAYLOAD))
                    port.write_request(msg)
                    work_done = True

                # Finally, notify the remote end of any work that we did.
                if work_done:
                    port.notify()



def cleanup_daemon(kill=False):
    # No cleanup to do if the PID file is empty.
    if not os.path.isfile(PID) or not os.path.getsize(PID):
        return 0
    # Read the PID of the previous invocation and search active process list.
    pid = open(PID, 'r').read()
    lines = os.popen('ps ' + pid + ' 2>/dev/null').readlines()
    for line in lines:
        if re.search('^ *' + pid + '.+xend', line):
            if not kill:
                print "Daemon is already running (PID %d)" % int(pid)
                return 1
            # Old daemon is still active: terminate it.
            os.kill(int(pid), 1)
    # Delete the, now stale, PID file.
    os.remove(PID)
    return 0



def start_daemon():
    if cleanup_daemon(kill=False):
        return 1

    if not os.path.exists(CONTROL_DIR):
        os.mkdir(CONTROL_DIR)

    # Open log file. Truncate it if non-empty, and request line buffering.
    if os.path.isfile(LOG):
        os.rename(LOG, LOG+'.old')
    logfile = open(LOG, 'w+', 1)

    # Detach from TTY.
    os.setsid()

    # Set the UID.
    try:
        os.setuid(pwd.getpwnam(USER)[2])
    except KeyError, error:
        print "Error: no such user '%s'" % USER
        return 1

    # Ensure that zombie children are automatically reaped.
    xend_utils.autoreap()

    # Fork -- parent writes the PID file and exits.
    pid = os.fork()
    if pid:
        pidfile = open(PID, 'w')
        pidfile.write(str(pid))
        pidfile.close()
        return 0

    # Close down standard file handles
    try:
        os.close(0) # stdin
        os.close(1) # stdout
        os.close(2) # stderr
    except:
        pass

    # Redirect output to log file, then enter the main loop.
    sys.stdout = sys.stderr = logfile
    daemon_loop()
    return 0



def stop_daemon():
    return cleanup_daemon(kill=True)



def main():
    xend_utils.autoreap()
    if not sys.argv[1:]:
        print 'usage: %s {start|stop|restart}' % sys.argv[0]
    elif os.fork():
        pid, status = os.wait()
        return status >> 8
    elif sys.argv[1] == 'start':
        return start_daemon()
    elif sys.argv[1] == 'stop':
        return stop_daemon()
    elif sys.argv[1] == 'restart':
        return stop_daemon() or start_daemon()
    else:
        print 'not an option:', sys.argv[1]
    return 1



if __name__ == '__main__':
    sys.exit(main())
