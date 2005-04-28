#
# XendBootloader.py - Framework to run a boot loader for picking the kernel
#
# Copyright 2005 Red Hat, Inc.
# Jeremy Katz <katzj@xxxxxxxxxx>
#
# This software may be freely redistributed under the terms of the GNU
# general public license.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#

import os, sys, select
import sxp

from XendLogging import log
from XendError import VmError

BL_FIFO = "/var/lib/xen/xenbl"

def bootloader(blexec, disk, quiet = 0, vcpus = None, entry = None):
    """Run the boot loader executable on the given disk and return a
    config image.
    @param blexec  Binary to use as the boot loader
    @param disk Disk to run the boot loader on.
    @param quiet Run in non-interactive mode, just booting the default.
    @param vcpus Number of vcpus for the domain.
    @param entry Default entry to boot."""
    
    if not os.access(blexec, os.X_OK):
        msg = "Bootloader isn't executable"
        log.error(msg)
        raise VmError(msg)
    if not os.access(disk, os.R_OK):
        msg = "Disk isn't accessible"
        log.error(msg)
        raise VmError(msg)

    os.mkfifo(BL_FIFO, 0600)

    child = os.fork()
    if (not child):
        args = [ blexec ]
        if quiet:
            args.append("-q")
        args.append("--output=%s" %(BL_FIFO,))
        if entry is not None:
            args.append("--entry=%s" %(entry,))
        args.append(disk)

        try:
            os.execvp(args[0], args)
        except OSError, e:
            print e
            pass
        os._exit(1)

    while 1:
        try:
            r = os.open(BL_FIFO, os.O_RDONLY)
        except OSError, e:
            if e.errno == 4:
                continue
        break
    ret = ""
    while 1:
        select.select([r], [], [])
        s = os.read(r, 1024)
        ret = ret + s
        if len(s) == 0:
            break
        
    (pid, status) = os.waitpid(child, 0)
    os.close(r)
    os.unlink(BL_FIFO)

    if len(ret) == 0:
        msg = "Boot loader didn't return any data!"
        log.error(msg)
        raise VmError, msg

    pin = sxp.Parser()
    pin.input(ret)
    pin.input_eof()

    config_image = pin.val
    if vcpus and sxp.child_value(config_image, "vcpus") is None:
        config_image.append(['vcpus', vcpus])

    config = ['image', config_image]
    return config

