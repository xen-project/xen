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
#
# Copyright (c) 2005 XenSource Ltd


import random
import sys
import threading
import time

import xen.lowlevel.xs

from xen.xend.xenstore import xsutil
from xen.xend.xenstore.xstransact import xstransact
from xen.xend.xenstore.xswatch import xswatch


PATH = '/tool/stress_xs'


def stress():
    xstransact.Remove(PATH)
    xstransact.Mkdir(PATH)

    xswatch(PATH, watch_callback)

    def do(f):
        t = threading.Thread(target=stress_write)
        t.setDaemon(True)
        t.start()

    do(stress_write)
    do(stress_get_domain_path)
    do(stress_get_domain_path_xsutil)
    do(stress_open_close)

    while True:
        # Wait for Ctrl-C.
        time.sleep(100000000)


def stress_write():
    xstransact.Write(PATH, 'key', '1')
    while True:
        val = xstransact.Gather(PATH, ('key', int))
        xstransact.Store(PATH, ('key', val + 1))

        random_sleep()


def stress_get_domain_path():
    xs_handle = xen.lowlevel.xs.xs()

    domid = 0
    while True:
        xs_handle.get_domain_path(domid)
        domid += 1

        random_sleep()


def stress_get_domain_path_xsutil():
    domid = 0
    while True:
        xsutil.GetDomainPath(domid)
        domid += 1

        random_sleep()


def stress_open_close():
    while True:
        xs_handle = xen.lowlevel.xs.xs()

        try:
            try:
                trans = xs_handle.transaction_start()
                val = int(xs_handle.read(trans, PATH + '/key'))
                xs_handle.write(trans, PATH + '/key', str(val + 1))
                xs_handle.transaction_end(trans, False)
            except:
                xs_handle.transaction_end(trans, True)

            random_sleep()
        finally:
            del xs_handle


def watch_callback(path):
    random_sleep()
    return True


def random_sleep():
    d = random.randint(-50000, 500)
    if d > 0:
        time.sleep(d / 1000.0)


def main(argv = None):
    if argv is None:
        argv = sys.argv

    stress()

    return 0


if __name__ == "__main__":
    sys.exit(main())
