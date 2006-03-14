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


PROC_XEN_BALLOON = '/proc/xen/balloon'

BALLOON_OUT_SLACK = 1 # MiB.  We need this because the physinfo details are
                      # rounded.
RETRY_LIMIT = 10
##
# The time to sleep between retries grows linearly, using this value (in
# seconds).  When the system is lightly loaded, memory should be scrubbed and
# returned to the system very quickly, whereas when it is loaded, the system
# needs idle time to get the scrubbing done.  This linear growth accommodates
# such requirements.
SLEEP_TIME_GROWTH = 0.1

# A mapping between easy-to-remember labels and the more verbose
# label actually shown in the PROC_XEN_BALLOON file.
labels = { 'current'      : 'Current allocation',
           'target'       : 'Requested target',
           'low-balloon'  : 'Low-mem balloon',
           'high-balloon' : 'High-mem balloon',
           'limit'        : 'Xen hard limit' }

def _get_proc_balloon(label):
    """Returns the value for the named label.  Returns None if the label was
       not found or the value was non-numeric."""

    f = file(PROC_XEN_BALLOON, 'r')
    try:
        for line in f:
            keyvalue = line.split(':')
            if keyvalue[0] == label:
                values = keyvalue[1].split()
                if values[0].isdigit():
                    return int(values[0])
                else:
                    return None
        return None
    finally:
        f.close()

def get_dom0_current_alloc():
    """Returns the current memory allocation (in MiB) of dom0."""

    kb = _get_proc_balloon(labels['current'])
    if kb == None:
        raise VmError('Failed to query current memory allocation of dom0.')
    return kb / 1024

def get_dom0_target_alloc():
    """Returns the target memory allocation (in MiB) of dom0."""

    kb = _get_proc_balloon(labels['target'])
    if kb == None:
        raise VmError('Failed to query target memory allocation of dom0.')
    return kb / 1024

def free(required):
    """Balloon out memory from the privileged domain so that there is the
    specified required amount (in KiB) free.
    """

    # We check whether there is enough free memory, and if not, instruct dom0
    # to balloon out to free some up.  Memory freed by a destroyed domain may
    # not appear in the free_memory field immediately, because it needs to be
    # scrubbed before it can be released to the free list, which is done
    # asynchronously by Xen; ballooning is asynchronous also.  No matter where
    # we expect the free memory to come from, therefore, we need to wait for
    # it to become available.
    #
    # We are not allowed to balloon below dom0_min_mem, or if dom0_min_mem
    # is 0, we cannot balloon at all.  Memory can still become available
    # through a rebooting domain, however.
    #
    # Eventually, we time out (presumably because there really isn't enough
    # free memory).
    #
    # We don't want to set the memory target (triggering a watch) when that
    # has already been done, but we do want to respond to changing memory
    # usage, so we recheck the required alloc each time around the loop, but
    # track the last used value so that we don't trigger too many watches.

    need_mem = (required + 1023) / 1024 + BALLOON_OUT_SLACK

    xroot = XendRoot.instance()
    xc = xen.lowlevel.xc.xc()

    try:
        dom0_min_mem = xroot.get_dom0_min_mem()

        retries = 0
        sleep_time = SLEEP_TIME_GROWTH
        last_new_alloc = None
        while retries < RETRY_LIMIT:
            free_mem = xc.physinfo()['free_memory']

            if free_mem >= need_mem:
                log.debug("Balloon: free %d; need %d; done.", free_mem,
                          need_mem)
                return

            if retries == 0:
                log.debug("Balloon: free %d; need %d.", free_mem, need_mem)

            if dom0_min_mem > 0:
                dom0_alloc = get_dom0_current_alloc()
                new_alloc = dom0_alloc - (need_mem - free_mem)

                if (new_alloc >= dom0_min_mem and
                    new_alloc != last_new_alloc):
                    log.debug("Balloon: setting dom0 target to %d.",
                              new_alloc)
                    dom0 = XendDomain.instance().privilegedDomain()
                    dom0.setMemoryTarget(new_alloc)
                    last_new_alloc = new_alloc
                    # Continue to retry, waiting for ballooning.

            time.sleep(sleep_time)
            retries += 1
            sleep_time += SLEEP_TIME_GROWTH

        # Not enough memory; diagnose the problem.
        if dom0_min_mem == 0:
            raise VmError(('Not enough free memory and dom0_min_mem is 0, so '
                           'I cannot release any more.  I need %d MiB but '
                           'only have %d.') %
                          (need_mem, free_mem))
        elif new_alloc >= dom0_min_mem:
            raise VmError(
                ('I need %d MiB, but dom0_min_mem is %d and shrinking to '
                 '%d MiB would leave only %d MiB free.') %
                (need_mem, dom0_min_mem, dom0_min_mem,
                 free_mem + dom0_alloc - dom0_min_mem))
        else:
            raise VmError('The privileged domain did not balloon!')

    finally:
        del xc
