#!/usr/bin/env python

import os, select, socket, threading, time, signal, xmlrpclib

from xen.xend.XendClient import server
from xen.xend.xenstore.xswatch import xswatch

import xen.lowlevel.xc
from xen.xend.xenstore import xsutil
xc = xen.lowlevel.xc.xc()

import xen.lowlevel.checkpoint

import vm, image

XCFLAGS_LIVE =      1

xcsave = '/usr/lib/xen/bin/xc_save'

class _proxy(object):
    "proxy simulates an object without inheritance"
    def __init__(self, obj):
        self._obj = obj

    def __getattr__(self, name):
        return getattr(self._obj, name)

    def proxy(self, obj):
        self._obj = obj

class CheckpointError(Exception): pass

class CheckpointingFile(_proxy):
    """Tee writes into separate file objects for each round.
    This is necessary because xc_save gets a single file descriptor
    for the duration of checkpointing.
    """
    def __init__(self, path):
        self.path = path

        self.round = 0
        self.rfd, self.wfd = os.pipe()
        self.fd = file(path, 'wb')

        # this pipe is used to notify the writer thread of checkpoints
        self.cprfd, self.cpwfd = os.pipe()

        super(CheckpointingFile, self).__init__(self.fd)

        wt = threading.Thread(target=self._wrthread, name='disk-write-thread')
        wt.setDaemon(True)
        wt.start()
        self.wt = wt

    def fileno(self):
        return self.wfd

    def close(self):
        os.close(self.wfd)
        # closing wfd should signal writer to stop
        self.wt.join()
        os.close(self.rfd)
        os.close(self.cprfd)
        os.close(self.cpwfd)
        self.fd.close()
        self.wt = None

    def checkpoint(self):
        os.write(self.cpwfd, '1')

    def _wrthread(self):
        while True:
            r, o, e = select.select((self.rfd, self.cprfd), (), ())
            if self.rfd in r:
                data = os.read(self.rfd, 256 * 1024)
                if not data:
                    break
                self.fd.write(data)
            if self.cprfd in r:
                junk = os.read(self.cprfd, 1)
                self.round += 1
                self.fd = file('%s.%d' % (self.path, self.round), 'wb')
                self.proxy(self.fd)

class MigrationSocket(_proxy):
    def __init__(self, address):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(address)

        sock.send("receive\n")
        sock.recv(80)

        fd = os.fdopen(sock.fileno(), 'w+')

        self.sock = sock
        super(MigrationSocket, self).__init__(fd)

class Keepalive(object):
    "Call a keepalive method at intervals"
    def __init__(self, method, interval=0.1):
        self.keepalive = method
        self.interval = interval

        self.thread = None
        self.running = False

    def start(self):
        if not self.interval:
            return
        self.thread = threading.Thread(target=self.run, name='keepalive-thread')
        self.thread.setDaemon(True)
        self.running = True
        self.thread.start()

    def stop(self):
        if not self.thread:
            return
        self.running = False
        self.thread.join()
        self.thread = None

    def run(self):
        while self.running:
            self.keepalive()
            time.sleep(self.interval)
        self.keepalive(stop=True)

class Saver(object):
    def __init__(self, domid, fd, suspendcb=None, resumecb=None,
                 checkpointcb=None, interval=0):
        """Create a Saver object for taking guest checkpoints.
        domid:        name, number or UUID of a running domain
        fd:           a stream to which checkpoint data will be written.
        suspendcb:    callback invoked after guest is suspended
        resumecb:     callback invoked before guest resumes
        checkpointcb: callback invoked when a checkpoint is complete. Return
                      True to take another checkpoint, or False to stop.
        """
        self.fd = fd
        self.suspendcb = suspendcb
        self.resumecb = resumecb
        self.checkpointcb = checkpointcb
        self.interval = interval

        self.vm = vm.VM(domid)

        self.checkpointer = None

    def start(self):
        vm.getshadowmem(self.vm)

        hdr = image.makeheader(self.vm.dominfo)
        self.fd.write(hdr)
        self.fd.flush()

        self.checkpointer = xen.lowlevel.checkpoint.checkpointer()
        try:
            self.checkpointer.open(self.vm.domid)
            self.checkpointer.start(self.fd, self.suspendcb, self.resumecb,
                                    self.checkpointcb, self.interval)
            self.checkpointer.close()
        except xen.lowlevel.checkpoint.error, e:
            raise CheckpointError(e)

    def _resume(self):
        """low-overhead version of XendDomainInfo.resumeDomain"""
        # TODO: currently assumes SUSPEND_CANCEL is available
        if True:
            xc.domain_resume(self.vm.domid, 1)
            xsutil.ResumeDomain(self.vm.domid)
        else:
            server.xend.domain.resumeDomain(self.vm.domid)
