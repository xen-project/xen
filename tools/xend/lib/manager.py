
#############################################################
## xend/manager.py -- Management-interface functions for Xend
## Copyright (c) 2004, K A Fraser (University of Cambridge)
#############################################################

import xend.blkif, xend.console, xend.main, xend.utils


##
## new_control_interface:
##  Create a new control interface with the specified domain @dom.
##  The console port may also be specified; otherwise a suitable port is
##  automatically allocated.
##
def new_control_interface(dom, console_port=-1):
    # Allocate an event channel and binbd to it.
    port = xend.utils.port(dom)
    xend.main.notifier.bind(port.local_port)
    
    # If necessary, compute a suitable TCP port for console I/O.
    if console_port < 0:
        console_port = 9600 + port.local_port

    # Create a listening console interface.
    con_if = xend.console.interface(console_port, port.local_port)
    con_if.listen()

    # Update the master port list.
    xend.main.port_list[port.local_port] = port

    # Construct the successful response to be returned to the requester.
    response = { 'success': True }
    response['local_port']   = port.local_port
    response['remote_port']  = port.remote_port
    response['console_port'] = console_port
    return response


##
## new_block_interface:
##  Create a new block interface for the specified domain @dom.
##
def new_block_interface(dom, handle=-1):
    # By default we create an interface with handle zero.
    if handle < 0:
        handle = 0

    # We only support one interface per domain, which must have handle zero.
    if handle != 0:
        response = { 'success': False }
        response['error_type'] = 'Bad handle %d (only handle 0 ' + \
                                 'is supported)' % handle
        return response

    # Find local event-channel port associated with the specified domain.
    port = xend.main.port_from_dom(dom)
    if not port:
        response = { 'success': False }
        response['error_type'] = 'Unknown domain %d' % dom
        return response

    # The interface must not already exist.
    if xend.blkif.interface.list.has_key(port.local_port):
        response = { 'success': False }
        response['error_type'] = 'Interface (dom=%d,handle=%d) already ' + \
                                 'exists' % (dom, handle)
        return response

    # Create the new interface. Initially no virtual devices are attached.
    xend.blkif.interface(dom, port.local_port)

    # Response is deferred until back-end driver sends acknowledgement.
    return None


##
## new_block_device:
##  Attach a new virtual block device to the specified block interface
##  (@dom, @handle). The new device is identified by @vdev, and maps to
##  the real block extent (@pdev, @start_sect, @nr_sect). If @readonly then
##  write requests to @vdev will be rejected.
##
def new_block_device(dom, handle, vdev, pdev, start_sect, nr_sect, readonly):
    # We only support one interface per domain, which must have handle zero.
    if handle != 0:
        response = { 'success': False }
        response['error_type'] = 'Bad handle %d (only handle 0 ' + \
                                 'is supported)' % handle
        return response

    # Find local event-channel port associated with the specified domain.
    port = xend.main.port_from_dom(dom)
    if not port:
        response = { 'success': False }
        response['error_type'] = 'Unknown domain %d' % dom
        return response
        
    # The interface must exist.
    if not xend.blkif.interface.list.has_key(port.local_port):
        response = { 'success': False }
        response['error_type'] = 'Interface (dom=%d,handle=%d) does not ' + \
                                 'exists' % (dom, handle)
        return response

    # The virtual device must not yet exist.
    blkif = xend.blkif.interface.list[port.local_port]
    if not blkif.attach_device(vdev, pdev, start_sect, nr_sect, readonly):
        response = { 'success': False }
        response['error_type'] = 'Vdevice (dom=%d,handle=%d,vdevice=%d) ' + \
                                 'already exists' % (dom, handle, vdev)
        return response

    # Response is deferred until back-end driver sends acknowledgement.
    return None
