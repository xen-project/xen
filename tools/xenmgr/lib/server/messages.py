import struct

import xend.utils

DEBUG = 0

""" All message formats.
Added to incrementally for the various message types.
See below.
"""
msg_formats = {}

#============================================================================
# Console message types.
#============================================================================

CMSG_CONSOLE  = 0

console_formats = { 'console_data': (CMSG_CONSOLE, 0) }

msg_formats.update(console_formats)

#============================================================================
# Block interface message types.
#============================================================================

CMSG_BLKIF_BE = 1
CMSG_BLKIF_FE = 2

CMSG_BLKIF_FE_INTERFACE_STATUS_CHANGED =  0
CMSG_BLKIF_FE_DRIVER_STATUS_CHANGED    = 32
CMSG_BLKIF_FE_INTERFACE_CONNECT        = 33
CMSG_BLKIF_FE_INTERFACE_DISCONNECT     = 34

CMSG_BLKIF_BE_CREATE      = 0
CMSG_BLKIF_BE_DESTROY     = 1
CMSG_BLKIF_BE_CONNECT     = 2
CMSG_BLKIF_BE_DISCONNECT  = 3
CMSG_BLKIF_BE_VBD_CREATE  = 4
CMSG_BLKIF_BE_VBD_DESTROY = 5
CMSG_BLKIF_BE_VBD_GROW    = 6
CMSG_BLKIF_BE_VBD_SHRINK  = 7
CMSG_BLKIF_BE_DRIVER_STATUS_CHANGED    = 32

BLKIF_DRIVER_STATUS_DOWN  = 0
BLKIF_DRIVER_STATUS_UP    = 1

BLKIF_INTERFACE_STATUS_DESTROYED    = 0 #/* Interface doesn't exist.    */
BLKIF_INTERFACE_STATUS_DISCONNECTED = 1 #/* Exists but is disconnected. */
BLKIF_INTERFACE_STATUS_CONNECTED    = 2 #/* Exists and is connected.    */

BLKIF_BE_STATUS_OKAY                = 0
BLKIF_BE_STATUS_ERROR               = 1
BLKIF_BE_STATUS_INTERFACE_EXISTS    = 2
BLKIF_BE_STATUS_INTERFACE_NOT_FOUND = 3
BLKIF_BE_STATUS_INTERFACE_CONNECTED = 4
BLKIF_BE_STATUS_VBD_EXISTS          = 5
BLKIF_BE_STATUS_VBD_NOT_FOUND       = 6
BLKIF_BE_STATUS_OUT_OF_MEMORY       = 7
BLKIF_BE_STATUS_EXTENT_NOT_FOUND    = 8
BLKIF_BE_STATUS_MAPPING_ERROR       = 9

blkif_formats = {
    'blkif_be_connect_t':
    (CMSG_BLKIF_BE, CMSG_BLKIF_BE_CONNECT),

    'blkif_be_create_t':
    (CMSG_BLKIF_BE, CMSG_BLKIF_BE_CREATE),

    'blkif_be_disconnect_t':
    (CMSG_BLKIF_BE, CMSG_BLKIF_BE_DISCONNECT),

    'blkif_be_destroy_t':
    (CMSG_BLKIF_BE, CMSG_BLKIF_BE_DESTROY),

    'blkif_be_vbd_create_t':
    (CMSG_BLKIF_BE, CMSG_BLKIF_BE_VBD_CREATE),

    'blkif_be_vbd_grow_t':
    (CMSG_BLKIF_BE, CMSG_BLKIF_BE_VBD_GROW),

    'blkif_be_vbd_destroy_t':
    (CMSG_BLKIF_BE, CMSG_BLKIF_BE_VBD_DESTROY),

    'blkif_fe_interface_status_changed_t':
    (CMSG_BLKIF_FE, CMSG_BLKIF_FE_INTERFACE_STATUS_CHANGED),

    'blkif_fe_driver_status_changed_t':
    (CMSG_BLKIF_FE, CMSG_BLKIF_FE_DRIVER_STATUS_CHANGED),

    'blkif_fe_interface_connect_t':
    (CMSG_BLKIF_FE, CMSG_BLKIF_FE_INTERFACE_CONNECT),
}

msg_formats.update(blkif_formats)

#============================================================================
# Network interface message types.
#============================================================================

CMSG_NETIF_BE = 3
CMSG_NETIF_FE = 4

CMSG_NETIF_FE_INTERFACE_STATUS_CHANGED =  0
CMSG_NETIF_FE_DRIVER_STATUS_CHANGED    = 32
CMSG_NETIF_FE_INTERFACE_CONNECT        = 33
CMSG_NETIF_FE_INTERFACE_DISCONNECT     = 34

CMSG_NETIF_BE_CREATE      = 0
CMSG_NETIF_BE_DESTROY     = 1
CMSG_NETIF_BE_CONNECT     = 2
CMSG_NETIF_BE_DISCONNECT  = 3
CMSG_NETIF_BE_DRIVER_STATUS_CHANGED    = 32

NETIF_INTERFACE_STATUS_DESTROYED    = 0 #/* Interface doesn't exist.    */
NETIF_INTERFACE_STATUS_DISCONNECTED = 1 #/* Exists but is disconnected. */
NETIF_INTERFACE_STATUS_CONNECTED    = 2 #/* Exists and is connected.    */

NETIF_DRIVER_STATUS_DOWN   = 0
NETIF_DRIVER_STATUS_UP     = 1

netif_formats = {
    'netif_be_connect_t':
    (CMSG_NETIF_BE, CMSG_NETIF_BE_CONNECT),

    'netif_be_create_t':
    (CMSG_NETIF_BE, CMSG_NETIF_BE_CREATE),

    'netif_be_disconnect_t':
    (CMSG_NETIF_BE, CMSG_NETIF_BE_DISCONNECT),

    'netif_be_destroy_t':
    (CMSG_NETIF_BE, CMSG_NETIF_BE_DESTROY),

    'netif_be_driver_status_changed_t':
    (CMSG_NETIF_BE, CMSG_NETIF_BE_DRIVER_STATUS_CHANGED),

    'netif_fe_driver_status_changed_t':
    (CMSG_NETIF_FE, CMSG_NETIF_FE_DRIVER_STATUS_CHANGED),

    'netif_fe_interface_connect_t':
    (CMSG_NETIF_FE, CMSG_NETIF_FE_INTERFACE_CONNECT),

    'netif_fe_interface_status_changed_t':
    (CMSG_NETIF_FE, CMSG_NETIF_FE_INTERFACE_STATUS_CHANGED),
    }

msg_formats.update(netif_formats)

#============================================================================
CMSG_SHUTDOWN = 6

CMSG_SHUTDOWN_POWEROFF  = 0
CMSG_SHUTDOWN_REBOOT    = 1
CMSG_SHUTDOWN_SUSPEND   = 2

STOPCODE_shutdown       = 0
STOPCODE_reboot         = 1
STOPCODE_suspend        = 2

shutdown_formats = {
    'shutdown_poweroff_t':
    (CMSG_SHUTDOWN, CMSG_SHUTDOWN_POWEROFF),
    
    'shutdown_reboot_t':
    (CMSG_SHUTDOWN, CMSG_SHUTDOWN_REBOOT),

    'shutdown_suspend_t':
    (CMSG_SHUTDOWN, CMSG_SHUTDOWN_SUSPEND),
    }

msg_formats.update(shutdown_formats)

#============================================================================

class Msg:
    pass

def packMsg(ty, params):
    if DEBUG: print '>packMsg', ty, params
    (major, minor) = msg_formats[ty]
    args = {}
    for (k, v) in params.items():
        if k == 'mac':
            for i in range(0, 6):
                args['mac[%d]' % i] = v[i]
        else:
            args[k] = v
    if DEBUG:
        for (k, v) in args.items():
            print 'packMsg>', k, v, type(v)
    msgid = 0
    msg = xend.utils.message(major, minor, msgid, args)
    return msg

def unpackMsg(ty, msg):
    args = msg.get_payload()
    mac = [0, 0, 0, 0, 0, 0]
    macs = []
    for (k, v) in args.items():
        if k.startswith('mac['):
            macs += k
            i = int(k[4:5])
            mac[i] = v
        else:
            pass
    if macs:
        args['mac'] = mac
        for k in macs:
            del args[k]
    if DEBUG: print '<unpackMsg', ty, args
    return args

def msgTypeName(ty, subty):
    for (name, info) in msg_formats.items():
        if info[0] == ty and info[1] == subty:
            return name
    return None

