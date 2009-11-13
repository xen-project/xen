# netlink wrappers

import socket, struct
import xen.lowlevel.netlink

NETLINK_ROUTE          = 0

NLM_F_REQUEST = 1 # It is request message.
NLM_F_MULTI   = 2 # Multipart message, terminated by NLMSG_DONE
NLM_F_ACK     = 4 # Reply with ack, with zero or error code
NLM_F_ECHO    = 8 # Echo this request

# Modifiers to GET request
NLM_F_ROOT   = 0x100 # specify tree root
NLM_F_MATCH  = 0x200 # return all matching
NLM_F_ATOMIC = 0x400 # atomic GET
NLM_F_DUMP   = NLM_F_ROOT|NLM_F_MATCH

# Modifiers to NEW request
NLM_F_REPLACE = 0x100 # Override existing
NLM_F_EXCL    = 0x200 # Do not touch, if it exists
NLM_F_CREATE  = 0x400 # Create, if it does not exist
NLM_F_APPEND  = 0x800 # Add to end of list

RTM_NEWLINK  = 16
RTM_GETLINK  = 18
RTM_NEWQDISC = 36
RTM_DELQDISC = 37
RTM_GETQDISC = 38

IFLA_UNSPEC    = 0
IFLA_ADDRESS   = 1
IFLA_BROADCAST = 2
IFLA_IFNAME    = 3
IFLA_MTU       = 4
IFLA_LINK      = 5
IFLA_QDISC     = 6
IFLA_STATS     = 7
IFLA_COST      = 8
IFLA_PRIORITY  = 9
IFLA_MASTER    = 10
IFLA_WIRELESS  = 11
IFLA_PROTINFO  = 12
IFLA_TXQLEN    = 13
IFLA_MAP       = 14
IFLA_WEIGHT    = 15

TCA_UNSPEC  = 0
TCA_KIND    = 1
TCA_OPTIONS = 2
TCA_STATS   = 3
TCA_XSTATS  = 4
TCA_RATE    = 5
TCA_FCNT    = 6
TCA_STATS2  = 7

class RTNLException(Exception): pass

def align(l, alignto=4):
    return (l + alignto - 1) & ~(alignto - 1)

class rtattr(object):
    "rtattribute"
    fmt = "HH"
    fmtlen = struct.calcsize(fmt)

    def __init__(self, msg=None):
        if msg:
            self.unpack(msg)
        else:
            self.rta_len = 0
            self.rta_type = 0

            self.body = ''

    def __len__(self):
        return align(self.rta_len)

    def pack(self):
        self.rta_len = align(self.fmtlen + len(self.body))
        s = struct.pack(self.fmt, self.rta_len, self.rta_type) + self.body
        pad = self.rta_len - len(s)
        if pad:
            s += '\0' * pad
        return s

    def unpack(self, msg):
        args = struct.unpack(self.fmt, msg[:self.fmtlen])
        self.rta_len, self.rta_type = args

        self.body = msg[align(self.fmtlen):self.rta_len]

class rtattrlist(object):
    def __init__(self, msg):
        self.start = msg

    def __iter__(self):
        body = self.start
        while len(body) > rtattr.fmtlen:
            rta = rtattr(body)
            yield rta
            body = body[len(rta):]

class nlmsg(object):
    "netlink message header"
    fmt = "IHHII"
    fmtlen = struct.calcsize(fmt)

    def __init__(self, msg=None):
        if msg:
            self.unpack(msg)
        else:
            self.nlmsg_len = 0
            self.nlmsg_type = 0
            self.nlmsg_flags = 0
            self.nlmsg_seq = 0
            self.nlmsg_pid = 0

            self.rta = ''
            self.body = ''

    def __len__(self):
        return align(self.fmtlen + len(self.body) + len(self.rta))

    def addattr(self, type, data):
        attr = rtattr()
        attr.rta_type = type
        attr.body = data
        self.rta += attr.pack()

    def settype(self, cmd):
        self.nlmsg_type = cmd

    def pack(self):
        return struct.pack(self.fmt, len(self), self.nlmsg_type,
                           self.nlmsg_flags, self.nlmsg_seq,
                           self.nlmsg_pid) + self.body + self.rta

    def unpack(self, msg):
        args = struct.unpack(self.fmt, msg[:self.fmtlen])
        self.nlmsg_len, self.nlmsg_type, self.nlmsg_flags = args[:3]
        self.nlmsg_seq, self.nlmsg_pid = args[3:]

        self.body = msg[align(self.fmtlen):]
        self.rta = ''

    def __str__(self):
        return '<netlink message, len %d, type %d>' % \
            (self.nlmsg_len, self.nlmsg_type)

class ifinfomsg(object):
    "interface info message"
    fmt = "BxHiII"
    fmtlen = struct.calcsize(fmt)

    def __init__(self, msg=None):
        if msg:
            self.unpack(msg)
        else:
            self.ifi_family = 0
            self.ifi_type = 0
            self.ifi_index = 0
            self.ifi_flags = 0
            self.ifi_change = 0

            self.body = ''

    def unpack(self, msg):
        args = struct.unpack(self.fmt, msg[:self.fmtlen])
        self.ifi_family, self.ifi_type, self.ifi_index= args[:3]
        self.ifi_flags, self.ifi_change = args[3:]

        self.body = msg[align(self.fmtlen):]

    def __str__(self):
        return '<ifinfo message, family %d, type %d, index %d>' % \
            (self.ifi_family, self.ifi_type, self.ifi_index)

class tcmsg(object):
    "TC message"
    fmt = "BxxxiIII"
    fmtlen = struct.calcsize(fmt)

    def __init__(self, msg=None):
        if msg:
            self.unpack(msg)
        else:
            self.tcm_family = socket.AF_UNSPEC
            self.tcm_ifindex = 0
            self.tcm_handle = 0
            self.tcm_parent = 0
            self.tcm_info = 0

            self.rta = ''

    def unpack(self, msg):
        args = struct.unpack(self.fmt, msg[:self.fmtlen])
        self.tcm_family, self.tcm_ifindex, self.tcm_handle = args[:3]
        self.tcm_parent, self.tcm_info = args[3:]

        self.rta = msg[align(self.fmtlen):]

    def pack(self):
        return struct.pack(self.fmt, self.tcm_family, self.tcm_ifindex,
                           self.tcm_handle, self.tcm_parent, self.tcm_info)

    def __str__(self):
        return '<tc message, family %d, index %d>' % \
            (self.tcm_family, self.tcm_ifindex)

class newlinkmsg(object):
    def __init__(self, nlmsg):
        if nlmsg.nlmsg_type != RTM_NEWLINK:
            raise RTNLException("wrong message type")
        self.nlmsg = nlmsg
        self.ifi = ifinfomsg(self.nlmsg.body)

        self.rtattrs = {}
        for rta in rtattrlist(self.ifi.body):
            self.rtattrs[rta.rta_type] = rta.body

class newqdiscmsg(object):
    def __init__(self, nlmsg):
        if nlmsg.nlmsg_type != RTM_NEWQDISC:
            raise RTNLException("wrong message type")
        self.nlmsg = nlmsg
        self.t = tcmsg(self.nlmsg.body)

        self.rtattrs = {}
        for rta in rtattrlist(self.t.rta):
            self.rtattrs[rta.rta_type] = rta.body

class rtnl(object):
    def __init__(self):
        self._rth = xen.lowlevel.netlink.rtnl()
        self._linkcache = None

    def getlink(self, key, cached=False):
        """returns the interface object corresponding to the key, which
        may be an index number or device name."""
        if not cached:
            self._linkcache = None
        if self._linkcache is None:
            self._linkcache = self.getlinks()

        if isinstance(key, int):
            return self._linkcache.get(key)

        for k, v in self._linkcache.iteritems():
            if v['name'] == key:
                return v

        return None

    def getlinks(self):
        """returns a dictionary of interfaces keyed by kernel
        interface index"""
        links = {}
        def dumpfilter(addr, msgstr):
            msg = newlinkmsg(nlmsg(msgstr))
            idx = msg.ifi.ifi_index
            ifname = msg.rtattrs[IFLA_IFNAME].strip('\0')
            address = msg.rtattrs.get(IFLA_ADDRESS)

            link = {'index': idx,
                    'type': msg.ifi.ifi_type,
                    'name': ifname,
                    'address': address}
            links[idx] = link

        self._rth.wilddump_request(socket.AF_UNSPEC, RTM_GETLINK)
        self._rth.dump_filter(dumpfilter)

        return links

    def getqdisc(self, dev):
        """returns the queueing discipline on device dev, which may be
        specified by kernel index or device name"""
        qdiscs = self.getqdiscs(dev)
        if qdiscs:
            return qdiscs.values()[0]
        return None

    def getqdiscs(self, dev=None):
        """returns a dictionary of queueing disciplines keyed by kernel
        interface index"""
        qdiscs = {}
        def dumpfilter(addr, msgstr):
            msg = newqdiscmsg(nlmsg(msgstr))
            idx = msg.t.tcm_ifindex
            handle = msg.t.tcm_handle
            kind = msg.rtattrs[TCA_KIND].strip('\0')
            opts = msg.rtattrs.get(TCA_OPTIONS)

            qdisc = {'index': idx,
                     'handle': handle,
                     'kind': kind,
                     'options': opts}
            qdiscs[idx] = qdisc

        tcm = tcmsg()
        if dev:
            link = self.getlink(dev)
            if not link:
                raise QdiscException('device %s not found' % dev)
            tcm.tcm_ifindex = link['index']

        msg = tcm.pack()
        self._rth.dump_request(RTM_GETQDISC, msg)
        self._rth.dump_filter(dumpfilter)
        return qdiscs

    def talk(self, req):
        self._rth.talk(req)
