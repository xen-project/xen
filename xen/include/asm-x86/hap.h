/******************************************************************************
 * include/asm-x86/hap.h
 *
 * hardware-assisted paging
 * Copyright (c) 2007 Advanced Micro Devices (Wei Huang)
 *
 * Parts of this code are Copyright (c) 2006 by XenSource Inc.
 * Parts of this code are Copyright (c) 2006 by Michael A Fetterman
 * Parts based on earlier work by Michael A Fetterman, Ian Pratt et al.
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
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _XEN_HAP_H
#define _XEN_HAP_H

#define HAP_PRINTK(_f, _a...)                                         \
    debugtrace_printk("hap: %s(): " _f, __func__, ##_a)

/************************************************/
/*        hap domain level functions            */
/************************************************/
void  hap_domain_init(struct domain *d);
int   hap_domctl(struct domain *d, struct xen_domctl_shadow_op *sc,
                 XEN_GUEST_HANDLE_PARAM(xen_domctl_t) u_domctl);
int   hap_enable(struct domain *d, u32 mode);
void  hap_final_teardown(struct domain *d);
void  hap_teardown(struct domain *d, bool *preempted);
void  hap_vcpu_init(struct vcpu *v);
int   hap_track_dirty_vram(struct domain *d,
                           unsigned long begin_pfn,
                           unsigned long nr,
                           XEN_GUEST_HANDLE_PARAM(void) dirty_bitmap);

extern const struct paging_mode *hap_paging_get_mode(struct vcpu *);
int hap_set_allocation(struct domain *d, unsigned int pages, bool *preempted);
unsigned int hap_get_allocation(struct domain *d);

#endif /* XEN_HAP_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
