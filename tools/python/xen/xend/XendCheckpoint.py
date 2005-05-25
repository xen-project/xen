# Copyright (C) 2005 Christian Limpach <Christian.Limpach@cl.cam.ac.uk>

# This file is subject to the terms and conditions of the GNU General
# Public License.  See the file "COPYING" in the main directory of
# this archive for more details.

import errno
import os
import select
import sxp
from string import join
from struct import pack, unpack, calcsize
from xen.util.xpopen import xPopen3
import xen.lowlevel.xc; xc = xen.lowlevel.xc.new()

from XendLogging import log

SIGNATURE = "LinuxGuestRecord"
PAGE_SIZE = 4096
PATH_XC_SAVE = "/usr/libexec/xen/xc_save"
PATH_XC_RESTORE = "/usr/libexec/xen/xc_restore"

sizeof_int = calcsize("i")
sizeof_unsigned_long = calcsize("L")

def save(xd, fd, dominfo):
    if os.write(fd, SIGNATURE) != len(SIGNATURE):
        raise XendError("could not write guest state file: signature")

    config = sxp.to_string(dominfo.sxpr())
    if os.write(fd, pack("!i", len(config))) != sizeof_int:
        raise XendError("could not write guest state file: config len")
    if os.write(fd, config) != len(config):
        raise XendError("could not write guest state file: config")

    cmd = [PATH_XC_SAVE, str(xc.handle()), str(fd),
           dominfo.id]
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
                    log.info("suspending %s" % dominfo.id)
                    xd.domain_shutdown(dominfo.id, reason='suspend')
                    dominfo.state_wait("suspended")
                    log.info("suspend %s done" % dominfo.id)
                    child.tochild.write("done\n")
                    child.tochild.flush()
        if filter(lambda (fd, event): event & select.POLLHUP, r):
            break

    if child.wait() >> 8 == 127:
        lasterr = "popen %s failed" % PATH_XC_SAVE
    if child.wait() != 0:
        raise XendError("xc_save failed: %s" % lasterr)

    xd.domain_destroy(dominfo.id)
    return None

def restore(xd, fd):
    try:
        signature = fd.read_exact(len(SIGNATURE),
            "not a valid guest state file: signature read")
        if signature != SIGNATURE:
            raise XendError("not a valid guest state file: found '%s'" %
                            signature)
    
        l = fd.read_exact(sizeof_int,
                          "not a valid guest state file: config size read")
        vmconfig_size = unpack("!i", l)[0]
        vmconfig_buf = fd.read_exact(vmconfig_size,
            "not a valid guest state file: config read")
    
        p = sxp.Parser()
        p.input(vmconfig_buf)
        if not p.ready:
            raise XendError("not a valid guest state file: config parse")
    
        vmconfig = p.get_val()
        dominfo = xd.domain_configure(vmconfig)
    
        l = fd.read_exact(sizeof_unsigned_long,
                          "not a valid guest state file: pfn count read")
        nr_pfns = unpack("=L", l)[0]   # XXX endianess
        if nr_pfns > 1024*1024:     # XXX
            raise XendError(
                "not a valid guest state file: pfn count out of range")
    
        # XXXcl hack: fd.tell will sync up the object and
        #             underlying file descriptor
        ignore = fd.tell()
    
        cmd = [PATH_XC_RESTORE, str(xc.handle()), str(fd.fileno()),
               dominfo.id, str(nr_pfns)]
        log.info("[xc_restore] " + join(cmd))
        child = xPopen3(cmd, True, -1, [fd.fileno(), xc.handle()])
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
                    log.info(l.rstrip())
            if filter(lambda (fd, event): event & select.POLLHUP, r):
                break
    
        if child.wait() >> 8 == 127:
            lasterr = "popen %s failed" % PATH_XC_RESTORE
        if child.wait() != 0:
            raise XendError("xc_restore failed: %s" % lasterr)
    
        return dominfo

    except IOError, ex:
        if ex.errno == errno.ENOENT:
            raise XendError("can't open guest state file %s" % src)
        else:
            raise
