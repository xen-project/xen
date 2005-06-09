
from string import join, split

def macToString(mac):
    return ':'.join(map(lambda x: "%02x" % x, mac))

def macFromString(str):
    mac = [ int(x, 16) for x in str.split(':') ]
    if len(mac) != 6:
        raise ValueError("invalid mac: %s" % str)
    return mac
