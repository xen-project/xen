#===========================================================================
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
# Copyright (C) 2004, 2005 Mike Wray <mike.wray@hp.com>
# Copyright (C) 2005 XenSource Ltd
#============================================================================


import time

import xen.lowlevel.xc

import XendDomain
import XendRoot
from XendLogging import log
from XendError import VmError


PROC_XEN_BALLOON = "/proc/xen/balloon"
BALLOON_OUT_SLACK = 1 # MiB.  We need this because the physinfo details are
                      # rounded.


def free(required):
    """Balloon out memory from the privileged domain so that there is the
    specified required amount (in KiB) free.
    """
    
    xc = xen.lowlevel.xc.xc()
    xroot = XendRoot.instance()

    try:
        free_mem = xc.physinfo()['free_memory']
        need_mem = (required + 1023) / 1024 + BALLOON_OUT_SLACK

        log.debug("Balloon: free %d; need %d.", free_mem, need_mem)
        
        if free_mem >= need_mem:
            return

        dom0_min_mem = xroot.get_dom0_min_mem()
        if dom0_min_mem == 0:
            raise VmError('Not enough free memory and dom0_min_mem is 0.')

        dom0_alloc = _get_dom0_alloc()
        dom0_new_alloc = dom0_alloc - (need_mem - free_mem)
        if dom0_new_alloc < dom0_min_mem:
            raise VmError(
                ('I need %d MiB, but dom0_min_mem is %d and shrinking to '
                 '%d MiB would leave only %d MiB free.') %
                (need_mem, dom0_min_mem, dom0_min_mem,
                 free_mem + (dom0_alloc - dom0_min_mem)))

        dom0 = XendDomain.instance().privilegedDomain()
        dom0.setMemoryTarget(dom0_new_alloc)

        timeout = 20 # 2 sec
        while timeout > 0:
            time.sleep(0.1)

            free_mem = xc.physinfo()['free_memory']
            if free_mem >= need_mem:
                return

            timeout -= 1

        raise VmError('The privileged domain did not balloon!')
    finally:
        del xc


def _get_dom0_alloc():
    """Return current allocation memory of dom0 (in MiB). Return 0 on error"""

    f = file(PROC_XEN_BALLOON, 'r')
    try:
        line = f.readline()
        for x in line.split():
            for n in x:
                if not n.isdigit():
                    break
            else:
                return int(x) / 1024
        return 0
    finally:
        f.close()
