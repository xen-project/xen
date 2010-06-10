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

import os, select, errno, stat, signal, tty
import random
import shlex
from xen.xend import sxp

from xen.util import mkdir, oshelp
from XendLogging import log
from XendError import VmError

import pty, termios, fcntl
from xen.lowlevel import ptsname

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
    attempt = 0
    while True:
        if not os.access(disk, os.R_OK) and attempt > 3:
            msg = "Disk isn't accessible"
            log.error(msg)
            raise VmError(msg)
        else:
            break
        attempt = attempt + 1

    if os.uname()[0] == "NetBSD" and disk.startswith('/dev/'):
       disk = disk.replace("/dev/", "/dev/r")

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

    (m1, s1) = pty.openpty()

    # On Solaris, the pty master side will get cranky if we try
    # to write to it while there is no slave. To work around this,
    # keep the slave descriptor open until we're done. Set it
    # to raw terminal parameters, otherwise it will echo back
    # characters, which will confuse the I/O loop below.
    # Furthermore, a raw master pty device has no terminal
    # semantics on Solaris, so don't try to set any attributes
    # for it.
    if os.uname()[0] != 'SunOS' and os.uname()[0] != 'NetBSD':
        tty.setraw(m1)
        os.close(s1)
    else:
        tty.setraw(s1)

    fcntl.fcntl(m1, fcntl.F_SETFL, os.O_NDELAY)

    slavename = ptsname.ptsname(m1)
    dom.storeDom("serial/0/tty", slavename)

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
            oshelp.close_fds()
            os.execvpe(args[0], args, env)
        except OSError, e:
            print e
            pass
        os._exit(1)

    # record that this domain is bootloading
    dom.bootloader_pid = child

    # On Solaris, the master pty side does not have terminal semantics,
    # so don't try to set any attributes, as it will fail.
    if os.uname()[0] != 'SunOS':
        tty.setraw(m2);

    fcntl.fcntl(m2, fcntl.F_SETFL, os.O_NDELAY);
    while True:
        try:
            r = os.open(fifo, os.O_RDONLY)
        except OSError, e:
            if e.errno == errno.EINTR:
                continue
        break

    fcntl.fcntl(r, fcntl.F_SETFL, os.O_NDELAY);

    ret = ""
    inbuf=""; outbuf="";
    # filedescriptors:
    #   r - input from the bootloader (bootstring output)
    #   m1 - input/output from/to xenconsole
    #   m2 - input/output from/to pty that controls the bootloader
    # The filedescriptors are NDELAY, so it's ok to try to read
    # bigger chunks than may be available, to keep e.g. curses
    # screen redraws in the bootloader efficient. m1 is the side that
    # gets xenconsole input, which will be keystrokes, so a small number
    # is sufficient. m2 is pygrub output, which will be curses screen
    # updates, so a larger number (1024) is appropriate there.
    #
    # For writeable descriptors, only include them in the set for select
    # if there is actual data to write, otherwise this would loop too fast,
    # eating up CPU time.

    while True:
        wsel = []
        if len(outbuf) != 0:
            wsel = wsel + [m1]
        if len(inbuf) != 0:
            wsel = wsel + [m2]
        sel = select.select([r, m1, m2], wsel, [])
        try: 
            if m1 in sel[0]:
                s = os.read(m1, 16)
                inbuf += s
            if m2 in sel[1]:
                n = os.write(m2, inbuf)
                inbuf = inbuf[n:]
        except OSError, e:
            if e.errno == errno.EIO:
                pass
        try:
            if m2 in sel[0]:
                s = os.read(m2, 1024)
                outbuf += s
            if m1 in sel[1]:
                n = os.write(m1, outbuf)
                outbuf = outbuf[n:]
        except OSError, e:
            if e.errno == errno.EIO:
                pass
        if r in sel[0]:
            s = os.read(r, 128)
            ret = ret + s
            if len(s) == 0:
                break
    del inbuf
    del outbuf
    os.waitpid(child, 0)
    os.close(r)
    os.close(m2)
    os.close(m1)
    if os.uname()[0] == 'SunOS' or os.uname()[0] == 'NetBSD':
        os.close(s1)
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


