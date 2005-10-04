# Copyright (C) 2005 Christian Limpach <Christian.Limpach@cl.cam.ac.uk>
# Copyright (C) 2005 XenSource Ltd

# This file is subject to the terms and conditions of the GNU General
# Public License.  See the file "COPYING" in the main directory of
# this archive for more details.

import os
import re
import select
import sxp
from string import join
from struct import pack, unpack, calcsize

from xen.util.xpopen import xPopen3

import xen.lowlevel.xc

from xen.xend.xenstore.xsutil import IntroduceDomain

from XendError import XendError
from XendLogging import log

SIGNATURE = "LinuxGuestRecord"
PATH_XC_SAVE = "/usr/libexec/xen/xc_save"
PATH_XC_RESTORE = "/usr/libexec/xen/xc_restore"

sizeof_int = calcsize("i")
sizeof_unsigned_long = calcsize("L")


xc = xen.lowlevel.xc.new()


def write_exact(fd, buf, errmsg):
    if os.write(fd, buf) != len(buf):
        raise XendError(errmsg)

def read_exact(fd, size, errmsg):
    buf = os.read(fd, size)
    if len(buf) != size:
        raise XendError(errmsg)
    return buf

def save(fd, dominfo, live):
    write_exact(fd, SIGNATURE, "could not write guest state file: signature")

    config = sxp.to_string(dominfo.sxpr())

    domain_name = dominfo.getName()

    if live:
        dominfo.setName('migrating-' + domain_name)

    try:
        write_exact(fd, pack("!i", len(config)),
                    "could not write guest state file: config len")
        write_exact(fd, config, "could not write guest state file: config")

        # xc_save takes three customization parameters: maxit, max_f, and
        # flags the last controls whether or not save is 'live', while the
        # first two further customize behaviour when 'live' save is
        # enabled. Passing "0" simply uses the defaults compiled into
        # libxenguest; see the comments and/or code in xc_linux_save() for
        # more information.
        cmd = [PATH_XC_SAVE, str(xc.handle()), str(fd),
               str(dominfo.getDomid()), "0", "0", str(int(live)) ]
        log.info("[xc_save] " + join(cmd))
        child = xPopen3(cmd, True, -1, [fd, xc.handle()])
    
        lasterr = ""
        p = select.poll()
        p.register(child.fromchild.fileno())
        p.register(child.childerr.fileno())
        while True: 
            r = p.poll()
            for (fd, event) in r:
                if not event & select.POLLIN:
                    continue
                if fd == child.childerr.fileno():
                    l = child.childerr.readline()
                    log.error(l.rstrip())
                    lasterr = l.rstrip()
                if fd == child.fromchild.fileno():
                    l = child.fromchild.readline()
                    if l.rstrip() == "suspend":
                        log.info("suspending %d", dominfo.getDomid())
                        dominfo.shutdown('suspend')
                        dominfo.waitForShutdown()
                        log.info("suspend %d done", dominfo.getDomid())
                        child.tochild.write("done\n")
                        child.tochild.flush()
            if filter(lambda (fd, event): event & select.POLLHUP, r):
                break

        if child.wait() >> 8 == 127:
            lasterr = "popen %s failed" % PATH_XC_SAVE
        if child.wait() != 0:
            raise XendError("xc_save failed: %s" % lasterr)

        dominfo.destroyDomain()
    except Exception, exn:
        log.exception("Save failed on domain %s (%d).", domain_name,
                      dominfo.getDomid())
        try:
            if live:
                dominfo.setName(domain_name)
        except:
            log.exception("Failed to reset the migrating domain's name")
        raise Exception, exn


def restore(xd, fd):
    signature = read_exact(fd, len(SIGNATURE),
        "not a valid guest state file: signature read")
    if signature != SIGNATURE:
        raise XendError("not a valid guest state file: found '%s'" %
                        signature)

    l = read_exact(fd, sizeof_int,
                   "not a valid guest state file: config size read")
    vmconfig_size = unpack("!i", l)[0]
    vmconfig_buf = read_exact(fd, vmconfig_size,
        "not a valid guest state file: config read")

    p = sxp.Parser()
    p.input(vmconfig_buf)
    if not p.ready:
        raise XendError("not a valid guest state file: config parse")

    vmconfig = p.get_val()

    dominfo = xd.restore_(vmconfig)

    assert dominfo.store_channel
    assert dominfo.console_channel

    try:
        l = read_exact(fd, sizeof_unsigned_long,
                       "not a valid guest state file: pfn count read")
        nr_pfns = unpack("=L", l)[0]   # XXX endianess
        if nr_pfns > 1024*1024:     # XXX
            raise XendError(
                "not a valid guest state file: pfn count out of range")

        store_evtchn = dominfo.store_channel.port2
        console_evtchn = dominfo.console_channel.port2

        cmd = [PATH_XC_RESTORE, str(xc.handle()), str(fd),
               str(dominfo.getDomid()), str(nr_pfns),
               str(store_evtchn), str(console_evtchn)]
        log.info("[xc_restore] " + join(cmd))
        child = xPopen3(cmd, True, -1, [fd, xc.handle()])
        child.tochild.close()

        lasterr = ""
        p = select.poll()
        p.register(child.fromchild.fileno())
        p.register(child.childerr.fileno())
        while True:
            r = p.poll()
            for (fd, event) in r:
                if not event & select.POLLIN:
                    continue
                if fd == child.childerr.fileno():
                    l = child.childerr.readline()
                    log.error(l.rstrip())
                    lasterr = l.rstrip()
                if fd == child.fromchild.fileno():
                    l = child.fromchild.readline()
                    while l:
                        log.info(l.rstrip())
                        m = re.match(r"^(store-mfn) (\d+)\n$", l)
                        if m:
                            store_mfn = int(m.group(2))
                            dominfo.setStoreRef(store_mfn)
                            IntroduceDomain(dominfo.getDomid(),
                                            store_mfn,
                                            dominfo.store_channel.port1,
                                            dominfo.getDomainPath())
                        m = re.match(r"^(console-mfn) (\d+)\n$", l)
                        if m:
                            dominfo.setConsoleRef(int(m.group(2)))
                        try:
                            l = child.fromchild.readline()
                        except:
                            l = None
            if filter(lambda (fd, event): event & select.POLLHUP, r):
                break

        if child.wait() >> 8 == 127:
            lasterr = "popen %s failed" % PATH_XC_RESTORE
        if child.wait() != 0:
            raise XendError("xc_restore failed: %s" % lasterr)

        return dominfo
    except:
        log.exception("Restore failed")
        dominfo.destroy()
        raise
