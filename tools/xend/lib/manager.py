
#############################################################
## xend/manager.py -- Management-interface functions for Xend
## Copyright (c) 2004, K A Fraser (University of Cambridge)
#############################################################

import xend.console, xend.main, xend.utils


##
## new_control_interface:
##  Create a new control interface with the specified domain 'dom'.
##  The console port may also be specified; otehrwise a suitable port is
##  automatically allocated.
##
def new_control_interface(dom, console_port=-1):
    # Allocate an event channel. Clear pending notifications.
    port = xend.utils.port(dom)
    xend.main.notifier.clear(port.local_port, xend.main.notifier.NORMAL)
    xend.main.notifier.clear(port.local_port, xend.main.notifier.DISCONNECT)
    
    # If necessary, compute a suitable TCP port for console I/O.
    if console_port < 0:
        console_port = 9600 + port.local_port

    # Create a listenign console interface.
    con_if = xend.console.interface(console_port, port.local_port)
    con_if.listen()

    # Add control state to the master list.
    xend.main.control_list[port.local_port] = \
      (port, xend.utils.buffer(), xend.utils.buffer(), con_if)

    # Construct the successful response to be returned to the requester.
    response = { 'success': True }
    response['local_port']   = port.local_port
    response['remote_port']  = port.remote_port
    response['console_port'] = console_port
    return response
