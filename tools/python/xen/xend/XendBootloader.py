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

import os, select, errno, stat, signal
import random
import shlex
from xen.xend import sxp

from xen.util import mkdir
from XendLogging import log
from XendError import VmError

import pty, ptsname, termios, fcntl

def bootloader(blexec, disk, dom, quiet = False, blargs = '', kernel = '',
               ramdisk = '', kernel_args = ''):
    """Run the boot loader executable on the given disk and return a
    config image.
    @param blexec  Binary to use as the boot loader
    @param disk Disk to run the boot loader on.
    @param dom DomainInfo representing the domain being booted.
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

    mkdir.parents("/var/run/xend/boot/", stat.S_IRWXU)

    while True:
        fifo = "/var/run/xend/boot/xenbl.%s" %(random.randint(0, 32000),)
        try:
            os.mkfifo(fifo, 0600)
        except OSError, e:
            if (e.errno != errno.EEXIST):
                raise
        break

    # We need to present the bootloader's tty as a pty slave that xenconsole
    # can access.  Since the bootloader itself needs a pty slave, 
    # we end up with a connection like this:
    #
    # xenconsole -- (slave pty1 master) <-> (master pty2 slave) -- bootloader
    #
    # where we copy characters between the two master fds, as well as
    # listening on the bootloader's fifo for the results.

    # Termios runes for very raw access to the pty master fds.
    attr = [ 0, 0, termios.CS8 | termios.CREAD | termios.CLOCAL,
             0, 0, 0, [0] * 32 ]

    (m1, s1) = pty.openpty()
    termios.tcsetattr(m1, termios.TCSANOW, attr)
    fcntl.fcntl(m1, fcntl.F_SETFL, os.O_NDELAY);
    os.close(s1)
    slavename = ptsname.ptsname(m1)
    dom.storeDom("console/tty", slavename)

    # Release the domain lock here, because we definitely don't want 
    # a stuck bootloader to deny service to other xend clients.
    from xen.xend import XendDomain
    domains = XendDomain.instance()
    domains.domains_lock.release()
    
    (child, m2) = pty.fork()
    if (not child):
        args = [ blexec ]
        if kernel:
            args.append("--kernel=%s" % kernel)
        if ramdisk:
            args.append("--ramdisk=%s" % ramdisk)
        if kernel_args:
            args.append("--args=%s" % kernel_args)
        if quiet:
            args.append("-q")
        args.append("--output=%s" % fifo)
        if blargs:
            args.extend(shlex.split(blargs))
        args.append(disk)

        try:
            log.debug("Launching bootloader as %s." % str(args))
            env = os.environ.copy()
            env['TERM'] = 'vt100'
            os.execvpe(args[0], args, env)
        except OSError, e:
            print e
            pass
        os._exit(1)

    # record that this domain is bootloading
    dom.bootloader_pid = child

    termios.tcsetattr(m2, termios.TCSANOW, attr)
    fcntl.fcntl(m2, fcntl.F_SETFL, os.O_NDELAY);
    while True:
        try:
            r = os.open(fifo, os.O_RDONLY)
        except OSError, e:
            if e.errno == errno.EINTR:
                continue
        break
    ret = ""
    inbuf=""; outbuf="";
    while True:
        sel = select.select([r, m1, m2], [m1, m2], [])
        try: 
            if m1 in sel[0]:
                s = os.read(m1, 1)
                inbuf += s
            if m2 in sel[1] and len(inbuf) != 0:
                os.write(m2, inbuf[0])
                inbuf = inbuf[1:]
        except OSError, e:
            if e.errno == errno.EIO:
                pass
        try:
            if m2 in sel[0]:
                s = os.read(m2, 1)
                outbuf += s
            if m1 in sel[1] and len(outbuf) != 0:
                os.write(m1, outbuf[0])
                outbuf = outbuf[1:]
        except OSError, e:
            if e.errno == errno.EIO:
                pass
        if r in sel[0]:
            s = os.read(r, 1)
            ret = ret + s
            if len(s) == 0:
                break
    del inbuf
    del outbuf
    os.waitpid(child, 0)
    os.close(r)
    os.close(m2)
    os.close(m1)
    os.unlink(fifo)

    # Re-acquire the lock to cover the changes we're about to make
    # when we return to domain creation.
    domains.domains_lock.acquire()    

    if dom.bootloader_pid is None:
        msg = "Domain was died while the bootloader was running."
        log.error(msg)
        raise VmError, msg        
        
    dom.bootloader_pid = None

    if len(ret) == 0:
        msg = "Boot loader didn't return any data!"
        log.error(msg)
        raise VmError, msg

    pin = sxp.Parser()
    pin.input(ret)
    pin.input_eof()
    blcfg = pin.val
    return blcfg


def bootloader_tidy(dom):
    if hasattr(dom, "bootloader_pid") and dom.bootloader_pid is not None:
        pid = dom.bootloader_pid
        dom.bootloader_pid = None
        os.kill(pid, signal.SIGKILL)


