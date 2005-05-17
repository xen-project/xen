import os
import re
import socket
import struct
import errno

##### Networking-related functions

def get_defaultroute():
    fd = os.popen('/sbin/ip route list 2>/dev/null')
    for line in fd.readlines():
        m = re.search('^default via ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+) dev ([^ ]*)',
                      line)
        if m:
            return [m.group(1), m.group(2)]
    return [None, None]

def get_current_ipaddr(dev='defaultroute'):
    """Get the primary IP address for the given network interface.

    dev     network interface (default: default route device)

    returns interface address as a string
    """
    if dev == 'defaultroute':
        dev = get_defaultroute()[1]
    if not dev:
        return
    fd = os.popen( '/sbin/ifconfig ' + dev + ' 2>/dev/null' )
    for line in fd.readlines():
        m = re.search( '^\s+inet addr:([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+).*',
                       line )
        if m:
            return m.group(1)
    return None

def get_current_ipmask(dev='defaultroute'):
    """Get the primary IP netmask for a network interface.

    dev     network interface (default: default route device)

    returns interface netmask as a string
    """
    if dev == 'defaultroute':
        dev = get_defaultroute()[1]
    if not dev:
        return
    fd = os.popen( '/sbin/ifconfig ' + dev + ' 2>/dev/null' )
    for line in fd.readlines():
        m = re.search( '^.+Mask:([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+).*',
                       line )
        if m:
            return m.group(1)
    return None

def get_current_ipgw(dev='defaultroute'):
    """Get the IP gateway for a network interface.

    dev     network interface (default: default route device)

    returns gateway address as a string
    """
    if dev == 'defaultroute':
        return get_defaultroute()[0]
    if not dev:
        return
    fd = os.popen( '/sbin/route -n' )
    for line in fd.readlines():
        m = re.search( '^\S+\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)' +
                       '\s+\S+\s+\S*G.*' + dev + '.*', line )
        if m:
            return m.group(1)
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

