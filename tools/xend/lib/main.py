
###########################################################
## xend.py -- Xen controller daemon
## Copyright (c) 2004, K A Fraser (University of Cambridge)
###########################################################

import errno, re, os, pwd, select, signal, socket, struct, sys, time
import xend.blkif, xend.netif, xend.console, xend.manager, xend.utils, Xc


# The following parameters could be placed in a configuration file.
PID  = '/var/run/xend.pid'
LOG  = '/var/log/xend.log'
USER = 'root'
CONTROL_DIR  = '/var/run/xend'
UNIX_SOCK    = 'management_sock' # relative to CONTROL_DIR


CMSG_CONSOLE  = 0
CMSG_BLKIF_BE = 1
CMSG_BLKIF_FE = 2
CMSG_NETIF_BE = 3
CMSG_NETIF_FE = 4


def port_from_dom(dom):
    global port_list
    for idx, port in port_list.items():
        if port.remote_dom == dom:
            return port
    return None


def send_management_response(response, addr):
    try:
        response = str(response)
        print "Mgmt_rsp[%s]: %s" % (addr, response)
        management_interface.sendto(response, addr)
    except socket.error, error:
        pass


def daemon_loop():
    # Could we do this more nicely? The xend.manager functions need access
    # to this global state to do their work.
    global port_list, notifier, management_interface, mgmt_req_addr, dom0_port

    # Lists of all interfaces, indexed by local event-channel port.
    port_list = {}
    
    xc = Xc.new()

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

    # Interface via which we receive event notifications from other guest
    # OSes. This interface also allows us to clear/acknowledge outstanding
    # notifications.
    notifier = xend.utils.notifier()

    # The DOM0 control interface is not set up via the management interface.
    # Note that console messages don't come our way (actually, only driver
    # back-ends should use the DOM0 control interface).
    dom0_port = xend.utils.port(0)
    notifier.bind(dom0_port.local_port)
    port_list[dom0_port.local_port] = dom0_port

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
        for idx, con_if in xend.console.interface.list_by_fd.items():
            if not con_if.closed():
                pflags = select.POLLIN
                if not con_if.rbuf.empty() and con_if.connected():
                    pflags = select.POLLIN | select.POLLOUT
                waitset.register(con_if.sock.fileno(), pflags)

        # Wait for something to do...
        fdset = waitset.poll()
        
        # Look for messages on the management interface.
        # These should consist of executable Python statements that call
        # well-known management functions (e.g., new_control_interface(dom=9)).
        try:
            data, mgmt_req_addr = management_interface.recvfrom(2048)
        except socket.error, error:
            if error[0] != errno.EAGAIN:
                raise
        else:
            if mgmt_req_addr:
                # Evaluate the request in an exception-trapping sandbox.
                try:
                    print "Mgmt_req[%s]: %s" % (mgmt_req_addr, data)
                    response = eval('xend.manager.'+data)

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
                if response:
                    send_management_response(response, mgmt_req_addr)
                
        # Do work for every console interface that hit in the poll set.
        for (fd, events) in fdset:
            if xend.console.interface.list_by_fd.has_key(fd):
                con_if = xend.console.interface.list_by_fd[fd]
                con_if.socket_work()
                # We may now have pending data to send via the control
                # interface. If so then send all we can and notify the remote.
                port = port_list[con_if.key]
                if con_if.ctrlif_transmit_work(port):
                    port.notify()
                    
        # Process control-interface notifications from other guest OSes.
        while 1:            
            # Grab a notification, if there is one.
            notification = notifier.read()
            if not notification:
                break
            (idx, type) = notification

            if not port_list.has_key(idx):
                continue

            port = port_list[idx]
            work_done = False

            con_if = False
            if xend.console.interface.list.has_key(idx):
                con_if = xend.console.interface.list[idx]

            blk_if = False
            if xend.blkif.interface.list.has_key(idx):
                blk_if = xend.blkif.interface.list[idx]

            net_if = False
            if xend.netif.interface.list.has_key(idx):
                net_if = xend.netif.interface.list[idx]

            # If we pick up a disconnect notification then we do any necessary
            # cleanup.
            if type == notifier.EXCEPTION:
                ret = xc.evtchn_status(idx)
                if ret['status'] == 'unbound':
                    notifier.unbind(idx)
                    del port_list[idx], port
                    if con_if:
                        con_if.destroy()
                        del con_if
                    if blk_if:
                        blk_if.destroy()
                        del blk_if
                    if net_if:
                        net_if.destroy()
                        del net_if
                    continue

            # Process incoming requests.
            while port.request_to_read():
                msg = port.read_request()
                work_done = True
                type = (msg.get_header())['type']
                if type == CMSG_CONSOLE and con_if:
                    con_if.ctrlif_rx_req(port, msg)
                elif type == CMSG_BLKIF_FE and blk_if:
                    blk_if.ctrlif_rx_req(port, msg)
                elif type == CMSG_BLKIF_BE and port == dom0_port:
                    xend.blkif.backend_rx_req(port, msg)
                elif type == CMSG_NETIF_FE and net_if:
                    net_if.ctrlif_rx_req(port, msg)
                elif type == CMSG_NETIF_BE:
                    xend.netif.backend_rx_req(port, msg)
                else:
                    port.write_response(msg)

            # Process incoming responses.
            while port.response_to_read():
                msg = port.read_response()
                work_done = True
                type = (msg.get_header())['type']
                if type == CMSG_BLKIF_BE and port == dom0_port:
                    xend.blkif.backend_rx_rsp(port, msg)
                elif type == CMSG_NETIF_BE:
                    xend.netif.backend_rx_rsp(port, msg)

            # Send console data.
            if con_if and con_if.ctrlif_transmit_work(port):
                work_done = True

            # Send blkif messages.
            if blk_if and blk_if.ctrlif_transmit_work(port):
                work_done = True

            # Send netif messages.
            if net_if and net_if.ctrlif_transmit_work(port):
                work_done = True

            # Back-end block-device work.
            if port == dom0_port and xend.blkif.backend_do_work(port):
                work_done = True
                
            # Back-end network-device work.
            if port == xend.netif.be_port and xend.netif.backend_do_work(port):
                work_done = True
                
            # Finally, notify the remote end of any work that we did.
            if work_done:
                port.notify()

            # Unmask notifications for this port.
            notifier.unmask(idx)



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
    xend.utils.autoreap()

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
