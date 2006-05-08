#
# XendBootloader.py - Framework to run a boot loader for picking the kernel
#
# Copyright 2005-2006 Red Hat, Inc.
# Jeremy Katz <katzj@redhat.com>
#
# This software may be freely redistributed under the terms of the GNU
# general public license.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#

import os, select, errno
import random
import sxp

from XendLogging import log
from XendError import VmError

def bootloader(blexec, disk, quiet = 0, blargs = None, imgcfg = None):
    """Run the boot loader executable on the given disk and return a
    config image.
    @param blexec  Binary to use as the boot loader
    @param disk Disk to run the boot loader on.
    @param quiet Run in non-interactive mode, just booting the default.
    @param blargs Arguments to pass to the bootloader."""
    
    if not os.access(blexec, os.X_OK):
        msg = "Bootloader isn't executable"
        log.error(msg)
        raise VmError(msg)
    if not os.access(disk, os.R_OK):
        msg = "Disk isn't accessible"
        log.error(msg)
        raise VmError(msg)

    while True:
        fifo = "/var/lib/xen/xenbl.%s" %(random.randint(0, 32000),)
        if not os.path.exists(fifo):
            break
    os.mkfifo(fifo, 0600)

    child = os.fork()
    if (not child):
        args = [ blexec ]
        if quiet:
            args.append("-q")
        args.append("--output=%s" %(fifo,))
        if blargs is not None:
            args.extend(blargs.split())
        args.append(disk)

        try:
            os.execvp(args[0], args)
        except OSError, e:
            print e
            pass
        os._exit(1)

    while 1:
        try:
            r = os.open(fifo, os.O_RDONLY)
        except OSError, e:
            if e.errno == errno.EINTR:
                continue
        break
    ret = ""
    while 1:
        select.select([r], [], [])
        s = os.read(r, 1024)
        ret = ret + s
        if len(s) == 0:
            break
        
    os.waitpid(child, 0)
    os.close(r)
    os.unlink(fifo)

    if len(ret) == 0:
        msg = "Boot loader didn't return any data!"
        log.error(msg)
        raise VmError, msg

    pin = sxp.Parser()
    pin.input(ret)
    pin.input_eof()
    blcfg = pin.val

    if imgcfg is None:
        return blcfg
    else:
        c = sxp.merge(blcfg, imgcfg)
        return c
