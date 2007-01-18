/******************************************************************************
 * xc_hvm_restore.c
 *
 * Restore the state of a HVM guest.
 *
 * Copyright (c) 2003, K A Fraser.
 * Copyright (c) 2006 Intel Corperation
 * rewriten for hvm guest by Zhai Edwin <edwin.zhai@intel.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 *
 */

#include <stdlib.h>
#include <unistd.h>

#include "xg_private.h"
#include "xg_save_restore.h"

#include <xen/hvm/ioreq.h>
#include <xen/hvm/params.h>
#include <xen/hvm/e820.h>

int xc_hvm_restore(int xc_handle, int io_fd,
                     uint32_t dom, unsigned long nr_pfns,
                     unsigned int store_evtchn, unsigned long *store_mfn,
                     unsigned int console_evtchn, unsigned long *console_mfn,
                     unsigned int pae, unsigned int apic)
{
    return 0;
}
