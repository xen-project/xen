import os
import re
import socket
import struct

##### Networking-related functions

def get_current_ipaddr(dev='eth0'):
    """Return a string containing the primary IP address for the given
    network interface (default 'eth0').
    """
    fd = os.popen( '/sbin/ifconfig ' + dev + ' 2>/dev/null' )
    lines = readlines(fd)
    for line in lines:
        m = re.search( '^\s+inet addr:([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+).*',
                       line )
        if m:
            return m.group(1)
    return None

def get_current_ipmask(dev='eth0'):
    """Return a string containing the primary IP netmask for the given
    network interface (default 'eth0').
    """
    fd = os.popen( '/sbin/ifconfig ' + dev + ' 2>/dev/null' )
    lines = readlines(fd)
    for line in lines:
        m = re.search( '^.+Mask:([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+).*',
                       line )
        if m:
            return m.group(1)
    return None

def get_current_ipgw(dev='eth0'):
    """Return a string containing the IP gateway for the given
    network interface (default 'eth0').
    """
    fd = os.popen( '/sbin/route -n' )
    lines = readlines(fd)
    for line in lines:
        m = re.search( '^\S+\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)' +
                       '\s+\S+\s+\S*G.*' + dev + '.*', line )
        if m:
            return m.group(1)
    return None

def setup_vfr_rules_for_vif(dom,vif,addr):
    """Takes a tuple ( domain-id, vif-id, ip-addr ), where the ip-addr
    is expressed as a textual dotted quad, and set up appropriate routing
    rules in Xen. No return value.
    """
    fd = os.open( '/proc/xen/vfr', os.O_WRONLY )
    if ( re.search( '169\.254', addr) ):
        os.write( fd, 'ADD ACCEPT srcaddr=' + addr +
                  ' srcaddrmask=255.255.255.255' +
                  ' srcdom=' + str(dom) + ' srcidx=' + str(vif) +
                  ' dstdom=0 dstidx=0 proto=any\n' )
    else:
        os.write( fd, 'ADD ACCEPT srcaddr=' + addr +
                  ' srcaddrmask=255.255.255.255' +
                  ' srcdom=' + str(dom) + ' srcidx=' + str(vif) +
                  ' dst=PHYS proto=any\n' )
    os.write( fd, 'ADD ACCEPT dstaddr=' + addr +
              ' dstaddrmask=255.255.255.255' +
              ' src=ANY' +
              ' dstdom=' + str(dom) + ' dstidx=' + str(vif) +
              ' proto=any\n' )
    os.close( fd )
    return None

def inet_aton(addr):
    """Convert an IP addr in IPv4 dot notation into an int.
    """
    b = socket.inet_aton(addr)
    return struct.unpack('!I', b)[0]

def inet_ntoa(n):
    """Convert an int into an IP addr in IPv4 dot notation.
    """
    b = struct.pack('!I', n)
    return socket.inet_ntoa(b)

def add_offset_to_ip(addr, offset):
    """Add a numerical offset to an IP addr in IPv4 dot notation.
    """
    n = inet_aton(addr)
    n += offset
    return inet_ntoa(n)

def check_subnet( ip, network, netmask ):
    n_ip = inet_aton(ip)
    n_net = inet_aton(network)
    n_mask = inet_aton(netmask)
    return (n_ip & n_mask) == (n_net & n_mask)

