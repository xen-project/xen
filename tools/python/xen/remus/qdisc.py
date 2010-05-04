import socket, struct

import netlink

qdisc_kinds = {}

TC_H_ROOT = 0xFFFFFFFF

class QdiscException(Exception): pass

class request(object):
    "qdisc request message"
    def __init__(self, cmd, flags=0, dev=None, handle=0):
        self.n = netlink.nlmsg()
        self.t = netlink.tcmsg()

        self.n.nlmsg_flags = netlink.NLM_F_REQUEST|flags
        self.n.nlmsg_type = cmd
        self.t.tcm_family = socket.AF_UNSPEC

        if not handle:
            handle = TC_H_ROOT
        self.t.tcm_parent = handle

        if dev:
            self.t.tcm_ifindex = dev

    def pack(self):
        t = self.t.pack()
        self.n.body = t
        return self.n.pack()

class addrequest(request):
    def __init__(self, dev, handle, qdisc):
        flags = netlink.NLM_F_EXCL|netlink.NLM_F_CREATE
        super(addrequest, self).__init__(netlink.RTM_NEWQDISC, flags=flags,
                                         dev=dev, handle=handle)
        self.n.addattr(netlink.TCA_KIND, qdisc.kind + '\0')
        opts = qdisc.pack()
        if opts:
            self.n.addattr(netlink.TCA_OPTIONS, opts)

class delrequest(request):
    def __init__(self, dev, handle):
        super(delrequest, self).__init__(netlink.RTM_DELQDISC, dev=dev,
                                         handle=handle)

class changerequest(request):
    def __init__(self, dev, handle, qdisc):
        super(changerequest, self).__init__(netlink.RTM_NEWQDISC,
                                            dev=dev, handle=handle)
        self.n.addattr(netlink.TCA_KIND, qdisc.kind + '\0')
        opts = qdisc.pack()
        if opts:
            self.n.addattr(netlink.TCA_OPTIONS, opts)

class Qdisc(object):
    def __new__(cls, qdict=None, *args, **opts):
        if qdict:
            kind = qdict.get('kind')
            cls = qdisc_kinds.get(kind, cls)
        obj = super(Qdisc, cls).__new__(cls)
        return obj

    def __init__(self, qdict):
        self._qdict = qdict
        self.kind = qdict['kind']
        self.handle = qdict['handle'] >> 16

    def parse(self, opts):
        if opts:
            raise QdiscException('cannot parse qdisc parameters')

    def optstr(self):
        if self.qdict['options']:
            return '[cannot parse qdisc parameters]'
        else:
            return ''

    def pack(self):
        return ''

TC_PRIO_MAX = 15
class PrioQdisc(Qdisc):
    fmt = 'i%sB' % (TC_PRIO_MAX + 1)

    def __init__(self, qdict):
        super(PrioQdisc, self).__init__(qdict)

        if qdict.get('options'):
            self.unpack(qdict['options'])
        else:
            self.bands = 3
            self.priomap = [1, 2, 2, 2, 1, 2, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1]

    def pack(self):
        #return struct.pack(self.fmt, self.bands, *self.priomap)
        return ''

    def unpack(self, opts):
        args = struct.unpack(self.fmt, opts)
        self.bands = args[0]
        self.priomap = args[1:]

    def optstr(self):
        mapstr = ' '.join([str(p) for p in self.priomap])
        return 'bands %d priomap  %s' % (self.bands, mapstr)

qdisc_kinds['prio'] = PrioQdisc
qdisc_kinds['pfifo_fast'] = PrioQdisc

class CfifoQdisc(Qdisc):
    fmt = 'II'

    def __init__(self, qdict):
        super(CfifoQdisc, self).__init__(qdict)

        if qdict.get('options'):
            self.unpack(qdict['options'])
        else:
            self.epoch = 0
            self.vmid = 0

    def pack(self):
        return struct.pack(self.fmt, self.epoch, self.vmid)

    def unpack(self, opts):
        self.epoch, self.vmid = struct.unpack(self.fmt, opts)

    def parse(self, opts):
        args = list(opts)
        try:
            while args:
                arg = args.pop(0)
                if arg == 'epoch':
                    self.epoch = int(args.pop(0))
                    continue
                if arg.lower() == 'vmid':
                    self.vmid = int(args.pop(0))
                    continue
        except Exception, inst:
            raise QdiscException(str(inst))

    def optstr(self):
        return 'epoch %d vmID %d' % (self.epoch, self.vmid)

qdisc_kinds['cfifo'] = CfifoQdisc

TC_QUEUE_CHECKPOINT = 0
TC_QUEUE_RELEASE = 1

class QueueQdisc(Qdisc):
    fmt = 'I'

    def __init__(self, qdict=None):
        if not qdict:
            qdict = {'kind': 'queue',
                     'handle': TC_H_ROOT}
        super(QueueQdisc, self).__init__(qdict)

        self.action = 0

    def pack(self):
        return struct.pack(self.fmt, self.action)

    def parse(self, args):
        if not args:
            raise QdiscException('no action given')
        arg = args[0]

        if arg == 'checkpoint':
            self.action = TC_QUEUE_CHECKPOINT
        elif arg == 'release':
            self.action = TC_QUEUE_RELEASE
        else:
            raise QdiscException('unknown action')

qdisc_kinds['queue'] = QueueQdisc
