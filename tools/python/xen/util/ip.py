import os
import re
import socket
import struct
import errno

from xen.xend import util

def _readlines(fd):
    """Version of readlines safe against EINTR.
    """
    import errno
    
    lines = []
    while 1:
        try:
            line = fd.readline()
        except IOError, ex:
            if ex.errno == errno.EINTR:
                continue
            else:
                raise
        if line == '': break
        lines.append(line)
    return lines

def _readline(fd):
    """Version of readline safe against EINTR.
    """
    while 1:
        try:
            return fd.readline()
        except IOError, ex:
            if ex.errno == errno.EINTR:
                continue
            else:
                raise

##### Networking-related functions

"""Bridge for network backend.
When bridging is used, eth0 may not have an IP address,
as it may have been moved onto the bridge.
"""
NBE_BRIDGE = 'xen-br0'

def get_current_ipaddr(dev='eth0'):
    """Get the primary IP address for the given network interface.

    dev     network interface (default eth0)

    returns interface address as a string
    """
    fd = util.popen( '/sbin/ifconfig ' + dev + ' 2>/dev/null' )
    lines = _readlines(fd)
    for line in lines:
        m = re.search( '^\s+inet addr:([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+).*',
                       line )
        if m:
            return m.group(1)
    if dev == 'eth0':
        return get_current_ipaddr(NBE_BRIDGE)
    return None

def get_current_ipmask(dev='eth0'):
    """Get the primary IP netmask for a network interface.

    dev     network interface (default eth0)

    returns interface netmask as a string
    """
    fd = util.popen( '/sbin/ifconfig ' + dev + ' 2>/dev/null' )
    lines = _readlines(fd)
    for line in lines:
        m = re.search( '^.+Mask:([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+).*',
                       line )
        if m:
            return m.group(1)
    if dev == 'eth0':
        return get_current_ipmask(NBE_BRIDGE)
    return None

def get_current_ipgw(dev='eth0'):
    """Get the IP gateway for a network interface.

    dev     network interface (default eth0)

    returns gateway address as a string
    """
    fd = util.popen( '/sbin/route -n' )
    lines = _readlines(fd)
    for line in lines:
        m = re.search( '^\S+\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)' +
                       '\s+\S+\s+\S*G.*' + dev + '.*', line )
        if m:
            return m.group(1)
    if dev == 'eth0':
        return get_current_ipgw(NBE_BRIDGE)
    return None

def inet_aton(addr):
    """Convert an IP addr in IPv4 dot notation into an int.

    addr    IP address as a string

    returns integer
    """
    b = socket.inet_aton(addr)
    return struct.unpack('!I', b)[0]

def inet_ntoa(n):
    """Convert an int into an IP addr in IPv4 dot notation.

    n       IP address

    returns string
    """
    b = struct.pack('!I', n)
    return socket.inet_ntoa(b)

def add_offset_to_ip(addr, offset):
    """Add a numerical offset to an IP addr in IPv4 dot notation.

    addr    IP address
    offset  offset to add

    returns new address
    """
    n = inet_aton(addr)
    n += offset
    return inet_ntoa(n)

def check_subnet( ip, network, netmask ):
    """Check if an IP address is in the subnet defined by
    a network address and mask'.

    ip      IP adress
    network network address
    netmask network mask
    
    returns 1 if it is in the subnet, 0 if not
    """
    n_ip = inet_aton(ip)
    n_net = inet_aton(network)
    n_mask = inet_aton(netmask)
    return (n_ip & n_mask) == (n_net & n_mask)

