# Copyright (C) 2005 Christian Limpach <Christian.Limpach@cl.cam.ac.uk>

# This file is subject to the terms and conditions of the GNU General
# Public License.  See the file "COPYING" in the main directory of
# this archive for more details.

import threading
from xen.lowlevel import xs

handles = {}

# XXX need to g/c handles from dead threads
def xshandle():
    if not handles.has_key(threading.currentThread()):
        handles[threading.currentThread()] = xs.open()
    return handles[threading.currentThread()]


def IntroduceDomain(domid, page, port, path):
    return xshandle().introduce_domain(domid, page, port, path)

def GetDomainPath(domid):
    return xshandle().get_domain_path(domid)
