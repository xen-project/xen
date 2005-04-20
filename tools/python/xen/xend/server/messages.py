import sys
import struct
import types

from xen.lowlevel import xu

DEBUG = False

#PORT_WILDCARD = 0xefffffff

"""Wildcard for the control message types."""
TYPE_WILDCARD = 0xffff

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

CMSG_BLKIF_FE_INTERFACE_STATUS      =  0
CMSG_BLKIF_FE_DRIVER_STATUS         = 32
CMSG_BLKIF_FE_INTERFACE_CONNECT     = 33
CMSG_BLKIF_FE_INTERFACE_DISCONNECT  = 34
CMSG_BLKIF_FE_INTERFACE_QUERY       = 35

CMSG_BLKIF_BE_CREATE                =  0
CMSG_BLKIF_BE_DESTROY               =  1
CMSG_BLKIF_BE_CONNECT               =  2
CMSG_BLKIF_BE_DISCONNECT            =  3
CMSG_BLKIF_BE_VBD_CREATE            =  4
CMSG_BLKIF_BE_VBD_DESTROY           =  5
CMSG_BLKIF_BE_DRIVER_STATUS         = 32

BLKIF_DRIVER_STATUS_DOWN            =  0
BLKIF_DRIVER_STATUS_UP              =  1

BLKIF_INTERFACE_STATUS_CLOSED       =  0 #/* Interface doesn't exist.    */
BLKIF_INTERFACE_STATUS_DISCONNECTED =  1 #/* Exists but is disconnected. */
BLKIF_INTERFACE_STATUS_CONNECTED    =  2 #/* Exists and is connected.    */
BLKIF_INTERFACE_STATUS_CHANGED      =  3 #/* A device has been added or removed. */

BLKIF_BE_STATUS_OKAY                =  0
BLKIF_BE_STATUS_ERROR               =  1
BLKIF_BE_STATUS_INTERFACE_EXISTS    =  2
BLKIF_BE_STATUS_INTERFACE_NOT_FOUND =  3
BLKIF_BE_STATUS_INTERFACE_CONNECTED =  4
BLKIF_BE_STATUS_VBD_EXISTS          =  5
BLKIF_BE_STATUS_VBD_NOT_FOUND       =  6
BLKIF_BE_STATUS_OUT_OF_MEMORY       =  7
BLKIF_BE_STATUS_PHYSDEV_NOT_FOUND   =  8
BLKIF_BE_STATUS_MAPPING_ERROR       =  9

blkif_formats = {
    'blkif_be_connect_t':
    (CMSG_BLKIF_BE, CMSG_BLKIF_BE_CONNECT),
    # Connect be to fe (in response to blkif_fe_interface_connect_t).

    'blkif_be_create_t':
    (CMSG_BLKIF_BE, CMSG_BLKIF_BE_CREATE),
    # Create be.

    'blkif_be_disconnect_t':
    (CMSG_BLKIF_BE, CMSG_BLKIF_BE_DISCONNECT),
    # Disconnect be from fe.

    'blkif_be_destroy_t':
    (CMSG_BLKIF_BE, CMSG_BLKIF_BE_DESTROY),
    # Destroy be (after disconnect).
    # Make be do this even if no disconnect (and destroy all vbd too).

    'blkif_be_vbd_create_t':
    (CMSG_BLKIF_BE, CMSG_BLKIF_BE_VBD_CREATE),
    # Create a vbd device.

    'blkif_be_vbd_destroy_t':
    (CMSG_BLKIF_BE, CMSG_BLKIF_BE_VBD_DESTROY),
    # Destroy a vbd.

    # Add message to query be for state and vbds.

    'blkif_fe_interface_status_t':
    (CMSG_BLKIF_FE, CMSG_BLKIF_FE_INTERFACE_STATUS),
    # Notify device status to fe.
    # Also used to notify 'any' device change with status BLKIF_INTERFACE_STATUS_CHANGED.

    'blkif_fe_driver_status_t':
    (CMSG_BLKIF_FE, CMSG_BLKIF_FE_DRIVER_STATUS),
    # Comes from fe, treated as notifying that fe has come up/changed.
    # Xend sets be(s) to BLKIF_INTERFACE_STATUS_DISCONNECTED,
    # sends blkif_fe_interface_status_t to fe (from each be).
    #
    # Reply with i/f count.
    # The i/f sends probes (using -ve trick), we reply with the info.

    'blkif_fe_interface_connect_t':
    (CMSG_BLKIF_FE, CMSG_BLKIF_FE_INTERFACE_CONNECT),
    # Comes from fe, passing shmem frame to use for be.
    # fe sends when gets blkif_fe_interface_status_t with state NETIF_INTERFACE_STATUS_DISCONNECTED.
    # Xend creates event channel and notifies be.
    # Then notifies fe of event channel with blkif_fe_interface_status_t.

    # Add message to kick fe to probe for devices.
    # Just report new devices to fe?

    # 
    # Add message for fe to probe a device.
    # And probing with id -1 should return first.
    # And probing with id -n should return first device with id > n.
    
    # Add message to query fe for state and vbds.
}

msg_formats.update(blkif_formats)

#============================================================================
# Network interface message types.
#============================================================================

CMSG_NETIF_BE = 3
CMSG_NETIF_FE = 4

CMSG_NETIF_FE_INTERFACE_STATUS      =  0
CMSG_NETIF_FE_DRIVER_STATUS         = 32
CMSG_NETIF_FE_INTERFACE_CONNECT     = 33
CMSG_NETIF_FE_INTERFACE_DISCONNECT  = 34
CMSG_NETIF_FE_INTERFACE_QUERY       = 35

CMSG_NETIF_BE_CREATE                =  0
CMSG_NETIF_BE_DESTROY               =  1
CMSG_NETIF_BE_CONNECT               =  2
CMSG_NETIF_BE_DISCONNECT            =  3
CMSG_NETIF_BE_CREDITLIMIT           =  4
CMSG_NETIF_BE_DRIVER_STATUS         = 32

NETIF_INTERFACE_STATUS_CLOSED       =  0 #/* Interface doesn't exist.    */
NETIF_INTERFACE_STATUS_DISCONNECTED =  1 #/* Exists but is disconnected. */
NETIF_INTERFACE_STATUS_CONNECTED    =  2 #/* Exists and is connected.    */
NETIF_INTERFACE_STATUS_CHANGED      =  3 #/* A device has been added or removed. */

NETIF_DRIVER_STATUS_DOWN            =  0
NETIF_DRIVER_STATUS_UP              =  1

netif_formats = {
    'netif_be_connect_t':
    (CMSG_NETIF_BE, CMSG_NETIF_BE_CONNECT),

    'netif_be_create_t':
    (CMSG_NETIF_BE, CMSG_NETIF_BE_CREATE),

    'netif_be_disconnect_t':
    (CMSG_NETIF_BE, CMSG_NETIF_BE_DISCONNECT),

    'netif_be_destroy_t':
    (CMSG_NETIF_BE, CMSG_NETIF_BE_DESTROY),

    'netif_be_creditlimit_t':
    (CMSG_NETIF_BE, CMSG_NETIF_BE_CREDITLIMIT),

    'netif_be_driver_status_t':
    (CMSG_NETIF_BE, CMSG_NETIF_BE_DRIVER_STATUS),

    'netif_fe_driver_status_t':
    (CMSG_NETIF_FE, CMSG_NETIF_FE_DRIVER_STATUS),

    'netif_fe_interface_connect_t':
    (CMSG_NETIF_FE, CMSG_NETIF_FE_INTERFACE_CONNECT),

    'netif_fe_interface_status_t':
    (CMSG_NETIF_FE, CMSG_NETIF_FE_INTERFACE_STATUS),
    }

msg_formats.update(netif_formats)

#============================================================================
# USB interface message types.
#============================================================================

CMSG_USBIF_BE = 8
CMSG_USBIF_FE = 9

CMSG_USBIF_FE_INTERFACE_STATUS_CHANGED = 0

CMSG_USBIF_FE_DRIVER_STATUS_CHANGED = 32
CMSG_USBIF_FE_INTERFACE_CONNECT     = 33
CMSG_USBIF_FE_INTERFACE_DISCONNECT  = 34

USBIF_DRIVER_STATUS_DOWN = 0
USBIF_DRIVER_STATUS_UP   = 1

USBIF_INTERFACE_STATUS_DESTROYED    = 0 #/* Interface doesn't exist.    */
USBIF_INTERFACE_STATUS_DISCONNECTED = 1 #/* Exists but is disconnected. */
USBIF_INTERFACE_STATUS_CONNECTED    = 2 #/* Exists and is connected.    */

CMSG_USBIF_BE_CREATE = 0
CMSG_USBIF_BE_DESTROY = 1
CMSG_USBIF_BE_CONNECT = 2

CMSG_USBIF_BE_DISCONNECT = 3
CMSG_USBIF_BE_CLAIM_PORT = 4
CMSG_USBIF_BE_RELEASE_PORT = 5

CMSG_USBIF_BE_DRIVER_STATUS_CHANGED = 32

USBIF_BE_STATUS_OKAY = 0
USBIF_BE_STATUS_ERROR = 1

USBIF_BE_STATUS_INTERFACE_EXISTS = 2
USBIF_BE_STATUS_INTERFACE_NOT_FOUND = 3
USBIF_BE_STATUS_INTERFACE_CONNECTED = 4
USBIF_BE_STATUS_OUT_OF_MEMORY = 7
USBIF_BE_STATUS_MAPPING_ERROR = 9

usbif_formats = {
    'usbif_be_create_t':
    (CMSG_USBIF_BE, CMSG_USBIF_BE_CREATE),

    'usbif_be_destroy_t':
    (CMSG_USBIF_BE, CMSG_USBIF_BE_DESTROY),

    'usbif_be_connect_t':
    (CMSG_USBIF_BE, CMSG_USBIF_BE_CONNECT),

    'usbif_be_disconnect_t':
    (CMSG_USBIF_BE, CMSG_USBIF_BE_DISCONNECT),

    'usbif_be_claim_port_t':
    (CMSG_USBIF_BE, CMSG_USBIF_BE_CLAIM_PORT),

    'usbif_be_release_port_t':
    (CMSG_USBIF_BE, CMSG_USBIF_BE_RELEASE_PORT),

    'usbif_fe_interface_status_changed_t':
    (CMSG_USBIF_FE, CMSG_USBIF_FE_INTERFACE_STATUS_CHANGED),

    'usbif_fe_driver_status_changed_t':
    (CMSG_USBIF_FE, CMSG_USBIF_FE_DRIVER_STATUS_CHANGED),

    'usbif_fe_interface_connect_t':
    (CMSG_USBIF_FE, CMSG_USBIF_FE_INTERFACE_CONNECT),

    'usbif_fe_interface_disconnect_t':
    (CMSG_USBIF_FE, CMSG_USBIF_FE_INTERFACE_DISCONNECT),
   
    }
    
msg_formats.update(usbif_formats)

#============================================================================
# Domain shutdown message types.
#============================================================================

CMSG_SHUTDOWN = 6

CMSG_SHUTDOWN_POWEROFF  = 0
CMSG_SHUTDOWN_REBOOT    = 1
CMSG_SHUTDOWN_SUSPEND   = 2
CMSG_SHUTDOWN_SYSRQ     = 3

STOPCODE_shutdown       = 0
STOPCODE_reboot         = 1
STOPCODE_suspend        = 2
STOPCODE_sysrq          = 3

shutdown_formats = {
    'shutdown_poweroff_t':
    (CMSG_SHUTDOWN, CMSG_SHUTDOWN_POWEROFF),
    
    'shutdown_reboot_t':
    (CMSG_SHUTDOWN, CMSG_SHUTDOWN_REBOOT),

    'shutdown_suspend_t':
    (CMSG_SHUTDOWN, CMSG_SHUTDOWN_SUSPEND),
    
    'shutdown_sysrq_t':
    (CMSG_SHUTDOWN, CMSG_SHUTDOWN_SYSRQ)
    }

msg_formats.update(shutdown_formats)

#============================================================================
# Domain memory reservation message.
#============================================================================

CMSG_MEM_REQUEST = 7
CMSG_MEM_REQUEST_SET = 0

mem_request_formats = {
    'mem_request_t':
    (CMSG_MEM_REQUEST, CMSG_MEM_REQUEST_SET)
    }

msg_formats.update(mem_request_formats)

#============================================================================
class Msg:
    pass

_next_msgid = 0

def nextid():
    """Generate the next message id.

    @return: message id
    @rtype: int
    """
    global _next_msgid
    _next_msgid += 1
    return _next_msgid

def packMsg(ty, params):
    """Pack a message.
    Any I{mac} parameter is passed in as an int[6] array and converted.

    @param ty: message type name
    @type ty: string
    @param params: message parameters
    @type params: dicy
    @return: message
    @rtype: xu message
    """
    msgid = nextid()
    if DEBUG: print '>packMsg', msgid, ty, params
    (major, minor) = msg_formats[ty]
    args = {}
    for (k, v) in params.items():
        if k in ['mac', 'be_mac']:
            for i in range(0, 6):
                args['%s[%d]' % (k, i)] = v[i]
        else:
            args[k] = v
    msg = xu.message(major, minor, msgid, args)
    if DEBUG: print '<packMsg', msg.get_header()['id'], ty, args
    return msg

def unpackMsg(ty, msg):
    """Unpack a message.
    Any mac addresses in the message are converted to int[6] array
    in the return dict.

    @param ty:  message type
    @type ty: string
    @param msg: message
    @type msg: xu message
    @return: parameters
    @rtype: dict
    """
    args = msg.get_payload()
    if DEBUG: print '>unpackMsg', args
    if isinstance(args, types.StringType):
        args = {'value': args}
    else:
        mac = [0, 0, 0, 0, 0, 0]
        macs = []
        for (k, v) in args.items():
            if k.startswith('mac['):
                macs.append(k)
                i = int(k[4:5])
                mac[i] = v
            else:
                pass
        if macs:
            args['mac'] = mac
            #print 'macs=', macs
            #print 'args=', args
            for k in macs:
                del args[k]
    if DEBUG:
        msgid = msg.get_header()['id']
        print '<unpackMsg', msgid, ty, args
    return args

def msgTypeName(ty, subty):
    """Convert a message type, subtype pair to a message type name.

    @param ty: message type
    @type ty: int
    @param subty: message subtype
    @type ty: int
    @return: message type name (or None)
    @rtype: string or None
    """
    for (name, info) in msg_formats.items():
        if info[0] == ty and info[1] == subty:
            return name
    return None

def printMsg(msg, out=sys.stdout, all=False):
    """Print a message.

    @param msg: message
    @type msg: xu message
    @param out: where to print to
    @type out: stream
    @param all: print payload if true
    @type all: bool
    """
    hdr = msg.get_header()
    major = hdr['type']
    minor = hdr['subtype']
    msgid = hdr['id']
    ty = msgTypeName(major, minor)
    print >>out, 'message:', 'type=', ty, '%d:%d' % (major, minor), 'id=%d' % msgid
    if all:
        print >>out, 'payload=', msg.get_payload()


def getMessageType(msg):
    """Get a 2-tuple of the message type and subtype.

    @param msg: message
    @type  msg: xu message
    @return: type info
    @rtype:  (int, int)
    """
    hdr = msg.get_header()
    return (hdr['type'], hdr.get('subtype'))

def getMessageId(msg):
    hdr = msg.get_header()
    return hdr['id']
