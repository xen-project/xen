# Copyright (C) 2005 Christian Limpach <Christian.Limpach@cl.cam.ac.uk>
# Copyright (C) 2005 XenSource Ltd

# This file is subject to the terms and conditions of the GNU General
# Public License.  See the file "COPYING" in the main directory of
# this archive for more details.

import os
import re
import string
import sxp
import threading
from struct import pack, unpack, calcsize

from xen.util.xpopen import xPopen3

import xen.util.auxbin

import xen.lowlevel.xc

import balloon
from XendError import XendError
from XendLogging import log
from XendDomainInfo import DEV_MIGRATE_STEP1, DEV_MIGRATE_STEP2
from XendDomainInfo import DEV_MIGRATE_STEP3

SIGNATURE = "LinuxGuestRecord"
XC_SAVE = "xc_save"
XC_RESTORE = "xc_restore"


sizeof_int = calcsize("i")
sizeof_unsigned_long = calcsize("L")


xc = xen.lowlevel.xc.xc()


def write_exact(fd, buf, errmsg):
    if os.write(fd, buf) != len(buf):
        raise XendError(errmsg)

def read_exact(fd, size, errmsg):
    buf  = '' 
    while size != 0: 
        str = os.read(fd, size)
        if not len(str):
            log.error("read_exact: EOF trying to read %d (buf='%s')" % \
                      (size, buf))
            raise XendError(errmsg)
        size = size - len(str)
        buf  = buf + str
    return buf



def save(fd, dominfo, network, live, dst):
    write_exact(fd, SIGNATURE, "could not write guest state file: signature")

    config = sxp.to_string(dominfo.sxpr())

    domain_name = dominfo.getName()
    # Rename the domain temporarily, so that we don't get a name clash if this
    # domain is migrating (live or non-live) to the local host.  Doing such a
    # thing is useful for debugging.
    dominfo.setName('migrating-' + domain_name)

    try:
        dominfo.migrateDevices(network, dst, DEV_MIGRATE_STEP1, domain_name)

        write_exact(fd, pack("!i", len(config)),
                    "could not write guest state file: config len")
        write_exact(fd, config, "could not write guest state file: config")

        # xc_save takes three customization parameters: maxit, max_f, and
        # flags the last controls whether or not save is 'live', while the
        # first two further customize behaviour when 'live' save is
        # enabled. Passing "0" simply uses the defaults compiled into
        # libxenguest; see the comments and/or code in xc_linux_save() for
        # more information.
        cmd = [xen.util.auxbin.pathTo(XC_SAVE), str(xc.handle()), str(fd),
               str(dominfo.getDomid()), "0", "0", str(int(live)) ]
        log.debug("[xc_save]: %s", string.join(cmd))

        def saveInputHandler(line, tochild):
            log.debug("In saveInputHandler %s", line)
            if line == "suspend":
                log.debug("Suspending %d ...", dominfo.getDomid())
                dominfo.shutdown('suspend')
                dominfo.waitForShutdown()
                dominfo.migrateDevices(network, dst, DEV_MIGRATE_STEP2,
                                       domain_name)
                log.info("Domain %d suspended.", dominfo.getDomid())
                dominfo.migrateDevices(network, dst, DEV_MIGRATE_STEP3,
                                       domain_name)
                tochild.write("done\n")
                tochild.flush()
                log.debug('Written done')

        forkHelper(cmd, fd, saveInputHandler, False)

        dominfo.destroyDomain()

    except Exception, exn:
        log.exception("Save failed on domain %s (%d).", domain_name,
                      dominfo.getDomid())
        try:
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

    store_port   = dominfo.getStorePort()
    console_port = dominfo.getConsolePort()

    assert store_port
    assert console_port

    try:
        l = read_exact(fd, sizeof_unsigned_long,
                       "not a valid guest state file: pfn count read")
        nr_pfns = unpack("L", l)[0]    # native sizeof long
        if nr_pfns > 16*1024*1024:     # XXX 
            raise XendError(
                "not a valid guest state file: pfn count out of range")

        balloon.free(xc.pages_to_kib(nr_pfns))

        cmd = map(str, [xen.util.auxbin.pathTo(XC_RESTORE),
                        xc.handle(), fd, dominfo.getDomid(), nr_pfns,
                        store_port, console_port])
        log.debug("[xc_restore]: %s", string.join(cmd))

        handler = RestoreInputHandler()

        forkHelper(cmd, fd, handler.handler, True)

        if handler.store_mfn is None or handler.console_mfn is None:
            raise XendError('Could not read store/console MFN')

        dominfo.unpause()

        dominfo.completeRestore(handler.store_mfn, handler.console_mfn)

        return dominfo
    except:
        dominfo.destroy()
        raise


class RestoreInputHandler:
    def __init__(self):
        self.store_mfn = None
        self.console_mfn = None


    def handler(self, line, _):
        m = re.match(r"^(store-mfn) (\d+)$", line)
        if m:
            self.store_mfn = int(m.group(2))
        else:
            m = re.match(r"^(console-mfn) (\d+)$", line)
            if m:
                self.console_mfn = int(m.group(2))


def forkHelper(cmd, fd, inputHandler, closeToChild):
    child = xPopen3(cmd, True, -1, [fd, xc.handle()])

    if closeToChild:
        child.tochild.close()

    thread = threading.Thread(target = slurp, args = (child.childerr,))
    thread.start()

    try:
        try:
            while 1:
                line = child.fromchild.readline()
                if line == "":
                    break
                else:
                    line = line.rstrip()
                    log.debug('%s', line)
                    inputHandler(line, child.tochild)

            thread.join()

        except IOError, exn:
            raise XendError('Error reading from child process for %s: %s' %
                            (cmd, exn))
    finally:
        child.fromchild.close()
        child.childerr.close()
        if not closeToChild:
            child.tochild.close()

    status = child.wait()
    if status >> 8 == 127:
        raise XendError("%s failed: popen failed" % string.join(cmd))
    elif status != 0:
        raise XendError("%s failed" % string.join(cmd))


def slurp(infile):
    while 1:
        line = infile.readline()
        if line == "":
            break
        else:
            log.error('%s', line.strip())
