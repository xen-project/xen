# Remus device interface
#
# Coordinates with devices at suspend, resume, and commit hooks

import os

import netlink, qdisc, util

class CheckpointedDevice(object):
    'Base class for buffered devices'

    def postsuspend(self):
        'called after guest has suspended'
        pass

    def preresume(self):
        'called before guest resumes'
        pass

    def commit(self):
        'called when backup has acknowledged checkpoint reception'
        pass

class ReplicatedDiskException(Exception): pass

class ReplicatedDisk(CheckpointedDevice):
    """
    Send a checkpoint message to a replicated disk while the domain
    is paused between epochs.
    """
    FIFODIR = '/var/run/tap'

    def __init__(self, disk):
        # look up disk, make sure it is tap:buffer, and set up socket
        # to request commits.
        self.ctlfd = None

        if not disk.uname.startswith('tap:remus:') and not disk.uname.startswith('tap:tapdisk:remus:'):
            raise ReplicatedDiskException('Disk is not replicated: %s' %
                                        str(disk))
        fifo = re.match("tap:.*(remus.*)\|", disk.uname).group(1).replace(':', '_')
        absfifo = os.path.join(self.FIFODIR, fifo)
        absmsgfifo = absfifo + '.msg'

        self.installed = False
        self.ctlfd = open(absfifo, 'w+b')
        self.msgfd = open(absmsgfifo, 'r+b')

    def __del__(self):
        self.uninstall()

    def uninstall(self):
        if self.ctlfd:
            self.ctlfd.close()
            self.ctlfd = None

    def postsuspend(self):
        os.write(self.ctlfd.fileno(), 'flush')

    def commit(self):
        msg = os.read(self.msgfd.fileno(), 4)
        if msg != 'done':
            print 'Unknown message: %s' % msg

class BufferedNICException(Exception): pass

class BufferedNIC(CheckpointedDevice):
    """
    Buffer a protected domain's network output between rounds so that
    nothing is issued that a failover might not know about.
    """
    # shared rtnetlink handle
    rth = None

    def __init__(self, domid):
        self.installed = False

        if not self.rth:
            self.rth = netlink.rtnl()

        self.devname = self._startimq(domid)
        dev = self.rth.getlink(self.devname)
        if not dev:
            raise BufferedNICException('could not find device %s' % self.devname)
        self.dev = dev['index']
        self.handle = qdisc.TC_H_ROOT
        self.q = qdisc.QueueQdisc()

    def __del__(self):
        self.uninstall()

    def postsuspend(self):
        if not self.installed:
            self._setup()

        self._sendqmsg(qdisc.TC_QUEUE_CHECKPOINT)

    def commit(self):
        '''Called when checkpoint has been acknowledged by
        the backup'''
        self._sendqmsg(qdisc.TC_QUEUE_RELEASE)

    def _sendqmsg(self, action):
        self.q.action = action
        req = qdisc.changerequest(self.dev, self.handle, self.q)
        self.rth.talk(req.pack())

    def _setup(self):
        q = self.rth.getqdisc(self.dev)
        if q:
            if q['kind'] == 'queue':
                self.installed = True
                return
            if q['kind'] != 'pfifo_fast':
                raise BufferedNICException('there is already a queueing '
                                           'discipline on %s' % self.devname)

        print 'installing buffer on %s' % self.devname
        req = qdisc.addrequest(self.dev, self.handle, self.q)
        self.rth.talk(req.pack())
        self.installed = True

    def uninstall(self):
        if self.installed:
            req = qdisc.delrequest(self.dev, self.handle)
            self.rth.talk(req.pack())
            self.installed = False

    def _startimq(self, domid):
        # stopgap hack to set up IMQ for an interface. Wrong in many ways.
        imqebt = '/usr/lib/xen/bin/imqebt'
        imqdev = 'imq0'
        vid = 'vif%d.0' % domid
        for mod in ['sch_queue', 'imq', 'ebt_imq']:
            util.runcmd(['modprobe', mod])
        util.runcmd("ip link set %s up" % (imqdev))
        util.runcmd("%s -F FORWARD" % (imqebt))
        util.runcmd("%s -A FORWARD -i %s -j imq --todev %s" % (imqebt, vid, imqdev))

        return imqdev
