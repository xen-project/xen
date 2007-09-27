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
import XendOptions
from XendLogging import log
from XendError import VmError
import osdep

RETRY_LIMIT = 20
RETRY_LIMIT_INCR = 5
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

    return osdep.lookup_balloon_stat(label)

def get_dom0_current_alloc():
    """Returns the current memory allocation (in KiB) of dom0."""

    kb = _get_proc_balloon(labels['current'])
    if kb == None:
        raise VmError('Failed to query current memory allocation of dom0.')
    return kb

def get_dom0_target_alloc():
    """Returns the target memory allocation (in KiB) of dom0."""

    kb = _get_proc_balloon(labels['target'])
    if kb == None:
        raise VmError('Failed to query target memory allocation of dom0.')
    return kb

def free(need_mem):
    """Balloon out memory from the privileged domain so that there is the
    specified required amount (in KiB) free.
    """

    # We check whether there is enough free memory, and if not, instruct dom0
    # to balloon out to free some up.  Memory freed by a destroyed domain may
    # not appear in the free_memory field immediately, because it needs to be
    # scrubbed before it can be released to the free list, which is done
    # asynchronously by Xen; ballooning is asynchronous also.  Such memory
    # does, however, need to be accounted for when calculating how much dom0
    # needs to balloon.  No matter where we expect the free memory to come
    # from, we need to wait for it to become available.
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

    xoptions = XendOptions.instance()
    dom0 = XendDomain.instance().privilegedDomain()
    xc = xen.lowlevel.xc.xc()
    dom0_start_alloc_mb = get_dom0_current_alloc() / 1024

    try:
        dom0_min_mem = xoptions.get_dom0_min_mem() * 1024
        dom0_alloc = get_dom0_current_alloc()

        retries = 0
        sleep_time = SLEEP_TIME_GROWTH
        new_alloc = 0
        last_new_alloc = None
        last_free = None
        rlimit = RETRY_LIMIT

        # If unreasonable memory size is required, we give up waiting
        # for ballooning or scrubbing, as if had retried.
        physinfo = xc.physinfo()
        free_mem = physinfo['free_memory']
        scrub_mem = physinfo['scrub_memory']
        total_mem = physinfo['total_memory']
        if dom0_min_mem > 0:
            max_free_mem = total_mem - dom0_min_mem
        else:
            max_free_mem = total_mem - dom0_alloc
        if need_mem >= max_free_mem:
            retries = rlimit

        while retries < rlimit:
            physinfo = xc.physinfo()
            free_mem = physinfo['free_memory']
            scrub_mem = physinfo['scrub_memory']

            if free_mem >= need_mem:
                log.debug("Balloon: %d KiB free; need %d; done.",
                          free_mem, need_mem)
                return

            if retries == 0:
                rlimit += ((need_mem - free_mem)/1024/1024) * RETRY_LIMIT_INCR
                log.debug("Balloon: %d KiB free; %d to scrub; need %d; retries: %d.",
                          free_mem, scrub_mem, need_mem, rlimit)

            if dom0_min_mem > 0:
                dom0_alloc = get_dom0_current_alloc()
                new_alloc = dom0_alloc - (need_mem - free_mem - scrub_mem)

                if free_mem + scrub_mem >= need_mem:
                    if last_new_alloc == None:
                        log.debug("Balloon: waiting on scrubbing")
                        last_new_alloc = dom0_alloc
                else:
                    if (new_alloc >= dom0_min_mem and
                        new_alloc != last_new_alloc):
                        new_alloc_mb = new_alloc / 1024  # Round down
                        log.debug("Balloon: setting dom0 target to %d MiB.",
                                  new_alloc_mb)
                        dom0.setMemoryTarget(new_alloc_mb)
                        last_new_alloc = new_alloc
                # Continue to retry, waiting for ballooning or scrubbing.

            time.sleep(sleep_time)
            if retries < 2 * RETRY_LIMIT:
                sleep_time += SLEEP_TIME_GROWTH
            if last_free != None and last_free >= free_mem + scrub_mem:
                retries += 1
            last_free = free_mem + scrub_mem

        # Not enough memory; diagnose the problem.
        if dom0_min_mem == 0:
            raise VmError(('Not enough free memory and dom0_min_mem is 0, so '
                           'I cannot release any more.  I need %d KiB but '
                           'only have %d.') %
                          (need_mem, free_mem))
        elif new_alloc < dom0_min_mem:
            raise VmError(
                ('I need %d KiB, but dom0_min_mem is %d and shrinking to '
                 '%d KiB would leave only %d KiB free.') %
                (need_mem, dom0_min_mem, dom0_min_mem,
                 free_mem + scrub_mem + dom0_alloc - dom0_min_mem))
        else:
            dom0.setMemoryTarget(dom0_start_alloc_mb)
            raise VmError(
                ('Not enough memory is available, and dom0 cannot'
                 ' be shrunk any further'))

    finally:
        del xc
