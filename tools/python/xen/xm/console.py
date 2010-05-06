#============================================================================
# This library is free software; you can redistribute it and/or
# modify it under the terms of version 2.1 of the GNU Lesser General Public
# License as published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#============================================================================
# Copyright (C) 2005 XenSource Ltd
#============================================================================

import xen.util.auxbin
import xen.lowlevel.xs
import os
import sys
import signal
from xen.util import utils

XENCONSOLE = "xenconsole"

def execConsole(domid, num = 0):
    xen.util.auxbin.execute(XENCONSOLE, [str(domid), "--num", str(num)])


class OurXenstoreConnection:
    def __init__(self):
        self.handle = xen.lowlevel.xs.xs()
    def read_eventually(self, path):
        watch = None
        trans = None
        try:
            signal.alarm(10)
            watch = self.handle.watch(path, None)
            while True:
                result = self.handle.read('0', path)
                if result is not None:
                    signal.alarm(0)
                    return result
                self.handle.read_watch()
        finally:
            signal.alarm(0)
            if watch is not None: self.handle.unwatch(path, watch)
    def read_maybe(self, path):
        return self.handle.read('0', path)

def runVncViewer(domid, do_autopass, do_daemonize=False):
    xs = OurXenstoreConnection()
    d = '/local/domain/%d/' % domid
    vnc_port = xs.read_eventually(d + 'console/vnc-port')
    vfb_backend = xs.read_maybe(d + 'device/vfb/0/backend')
    vnc_listen = None
    vnc_password = None
    vnc_password_tmpfile = None
    cmdl = ['vncviewer']
    if vfb_backend is not None:
        vnc_listen = xs.read_maybe(vfb_backend + '/vnclisten')
        if do_autopass:
            vnc_password = xs.read_maybe(vfb_backend + '/vncpasswd')
            if vnc_password is not None:
                cmdl.append('-autopass')
                vnc_password_tmpfile = os.tmpfile()
                print >>vnc_password_tmpfile, vnc_password
                vnc_password_tmpfile.seek(0)
                vnc_password_tmpfile.flush()
    if vnc_listen is None:
        vnc_listen = 'localhost'
    cmdl.append('%s:%d' % (vnc_listen, int(vnc_port) - 5900))
    if do_daemonize:
        pid = utils.daemonize('vncviewer', cmdl, vnc_password_tmpfile)
        if pid == 0:
            print >>sys.stderr, 'failed to invoke vncviewer'
            os._exit(-1)
    else:
        print 'invoking ', ' '.join(cmdl)
        if vnc_password_tmpfile is not None:
            os.dup2(vnc_password_tmpfile.fileno(), 0)
        try:
            os.execvp('vncviewer', cmdl)
        except OSError:
            print >>sys.stderr, 'Error: external vncviewer missing or not \
in the path\nExiting'
            os._exit(-1)
