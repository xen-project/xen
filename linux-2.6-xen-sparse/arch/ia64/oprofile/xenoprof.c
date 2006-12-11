/******************************************************************************
 * xenoprof ia64 specific part
 *
 * Copyright (c) 2006 Isaku Yamahata <yamahata at valinux co jp>
 *                    VA Linux Systems Japan K.K.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */
#include <linux/init.h>
#include <linux/oprofile.h>
#include <linux/ioport.h>

#include <xen/driver_util.h>
#include <xen/interface/xen.h>
#include <xen/interface/xenoprof.h>
#include <xen/xenoprof.h>

#include "oprofile_perfmon.h"

void __init xenoprof_arch_init_counter(struct xenoprof_init *init)
{
	init->num_events = 0; /* perfmon manages. */
}

void xenoprof_arch_counter(void)
{
	/* nothing. perfmon does. */
}

void xenoprof_arch_start(void) 
{
	perfmon_start();
}

void xenoprof_arch_stop(void)
{
	perfmon_stop();
}

/* XXX move them to an appropriate header file. */
struct resource* xen_ia64_allocate_resource(unsigned long size); 
void xen_ia64_release_resource(struct resource* res); 
void xen_ia64_unmap_resource(struct resource* res); 

struct resource*
xenoprof_ia64_allocate_resource(int32_t max_samples)
{
	unsigned long bufsize;

	/* XXX add hypercall to get bufsize? */
	/*     this value is taken from alloc_xenoprof_struct(). */
#if 0
	bufsize = NR_CPUS * (sizeof(struct xenoprof_buf) +
			     (max_samples - 1) * sizeof(struct event_log));
	bufsize = PAGE_ALIGN(bufsize) + PAGE_SIZE;
#else
#define MAX_OPROF_SHARED_PAGES 32
	bufsize = (MAX_OPROF_SHARED_PAGES + 1) * PAGE_SIZE;
#endif
	return xen_ia64_allocate_resource(bufsize);
}

void xenoprof_arch_unmap_shared_buffer(struct xenoprof_shared_buffer* sbuf)
{
	if (sbuf->buffer) {
		xen_ia64_unmap_resource(sbuf->arch.res);
		sbuf->buffer = NULL;
		sbuf->arch.res = NULL;
	}
}

int xenoprof_arch_map_shared_buffer(struct xenoprof_get_buffer* get_buffer,
                                    struct xenoprof_shared_buffer* sbuf)
{
	int ret;
	struct resource* res;

	sbuf->buffer = NULL;
	sbuf->arch.res = NULL;

	res = xenoprof_ia64_allocate_resource(get_buffer->max_samples);
	if (IS_ERR(res))
		return PTR_ERR(res);

	get_buffer->buf_gmaddr = res->start;

	ret = HYPERVISOR_xenoprof_op(XENOPROF_get_buffer, get_buffer);
	if (ret) {
		xen_ia64_release_resource(res);
		return ret;
	}

	BUG_ON((res->end - res->start + 1) <
	       get_buffer->bufsize * get_buffer->nbuf);

	sbuf->buffer = __va(res->start);
	sbuf->arch.res = res;

	return ret;
}

int xenoprof_arch_set_passive(struct xenoprof_passive* pdomain,
                              struct xenoprof_shared_buffer* sbuf)
{
	int ret;
	struct resource* res;

	sbuf->buffer = NULL;
	sbuf->arch.res = NULL;

	res = xenoprof_ia64_allocate_resource(pdomain->max_samples);
	if (IS_ERR(res))
		return PTR_ERR(res);

	pdomain->buf_gmaddr = res->start;

	ret = HYPERVISOR_xenoprof_op(XENOPROF_set_passive, pdomain);
	if (ret) {
		xen_ia64_release_resource(res);
		return ret;
	}

	BUG_ON((res->end - res->start + 1) < pdomain->bufsize * pdomain->nbuf);

	sbuf->buffer = __va(res->start);
	sbuf->arch.res = res;

	return ret;
}
