# Copyright (C) 2005 Christian Limpach <Christian.Limpach@cl.cam.ac.uk>

# This file is subject to the terms and conditions of the GNU General
# Public License.  See the file "COPYING" in the main directory of
# this archive for more details.

import threading
import xen.lowlevel.xs

xs_lock = threading.Lock()
xs_handle = None

def xshandle():
    global xs_handle, xs_lock
    if not xs_handle:
        xs_lock.acquire()
        if not xs_handle:
            xs_handle = xen.lowlevel.xs.xs()
        xs_lock.release()
    return xs_handle

def IntroduceDomain(domid, page, port):
    return xshandle().introduce_domain(domid, page, port)

def GetDomainPath(domid):
    return xshandle().get_domain_path(domid)

def ResumeDomain(domid):
    return xshandle().resume_domain(domid)
