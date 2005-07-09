/* -*-  Mode:C; c-basic-offset:4; tab-width:4; indent-tabs-mode:nil -*- */
/*
 * vmx_hyparcall.c: handling hypercall from domain
 * Copyright (c) 2005, Intel Corporation.
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
 *  Xuefei Xu (Anthony Xu) (Anthony.xu@intel.com)
 */

#include <xen/config.h>
#include <xen/errno.h>
#include <asm/vmx_vcpu.h>
#include <public/xen.h>
#include <public/event_channel.h>
#include <asm/vmmu.h>
#include <asm/tlb.h>
#include <asm/regionreg.h>
#include <asm/page.h>
#include <xen/mm.h>


void hyper_not_support(void)
{
    VCPU *vcpu=current;
    vmx_vcpu_set_gr(vcpu, 8, -1, 0);
    vmx_vcpu_increment_iip(vcpu);
}

void hyper_mmu_update(void)
{
    VCPU *vcpu=current;
    u64 r32,r33,r34,r35,ret;
    vmx_vcpu_get_gr(vcpu,16,&r32);
    vmx_vcpu_get_gr(vcpu,17,&r33);
    vmx_vcpu_get_gr(vcpu,18,&r34);
    vmx_vcpu_get_gr(vcpu,19,&r35);
    ret=do_mmu_update((mmu_update_t*)r32,r33,r34,r35);
    vmx_vcpu_set_gr(vcpu, 8, ret, 0);
    vmx_vcpu_increment_iip(vcpu);
}

void hyper_dom_mem_op(void)
{
    VCPU *vcpu=current;
    u64 r32,r33,r34,r35,r36;
    u64 ret;
    vmx_vcpu_get_gr(vcpu,16,&r32);
    vmx_vcpu_get_gr(vcpu,17,&r33);
    vmx_vcpu_get_gr(vcpu,18,&r34);
    vmx_vcpu_get_gr(vcpu,19,&r35);
    vmx_vcpu_get_gr(vcpu,20,&r36);
    ret=do_dom_mem_op(r32,(u64 *)r33,r34,r35,r36);
    printf("do_dom_mem return value: %lx\n", ret);
    vmx_vcpu_set_gr(vcpu, 8, ret, 0);

    vmx_vcpu_increment_iip(vcpu);
}


void hyper_sched_op(void)
{
    VCPU *vcpu=current;
    u64 r32,ret;
    vmx_vcpu_get_gr(vcpu,16,&r32);
    ret=do_sched_op(r32);
    vmx_vcpu_set_gr(vcpu, 8, ret, 0);

    vmx_vcpu_increment_iip(vcpu);
}

void hyper_dom0_op(void)
{
    VCPU *vcpu=current;
    u64 r32,ret;
    vmx_vcpu_get_gr(vcpu,16,&r32);
    ret=do_dom0_op((dom0_op_t *)r32);
    vmx_vcpu_set_gr(vcpu, 8, ret, 0);

    vmx_vcpu_increment_iip(vcpu);
}

void hyper_event_channel_op(void)
{
    VCPU *vcpu=current;
    u64 r32,ret;
    vmx_vcpu_get_gr(vcpu,16,&r32);
    ret=do_event_channel_op((evtchn_op_t *)r32);
    vmx_vcpu_set_gr(vcpu, 8, ret, 0);
    vmx_vcpu_increment_iip(vcpu);
}

void hyper_xen_version(void)
{
    VCPU *vcpu=current;
    u64 r32,ret;
    vmx_vcpu_get_gr(vcpu,16,&r32);
    ret=do_xen_version((int )r32);
    vmx_vcpu_set_gr(vcpu, 8, ret, 0);
    vmx_vcpu_increment_iip(vcpu);
}

static int do_lock_page(VCPU *vcpu, u64 va, u64 lock)
{
    int i;
    ia64_rr rr;
    thash_cb_t *hcb;
    hcb = vmx_vcpu_get_vtlb(vcpu);
    rr = vmx_vcpu_rr(vcpu, va);
    return thash_lock_tc(hcb, va ,1U<<rr.ps, rr.rid, DSIDE_TLB, lock);
}

/*
 * Lock guest page in vTLB, so that it's not relinquished by recycle
 * session when HV is servicing that hypercall.
 */
void hyper_lock_page(void)
{
//TODO:
    VCPU *vcpu=current;
    u64 va,lock, ret;
    vmx_vcpu_get_gr(vcpu,16,&va);
    vmx_vcpu_get_gr(vcpu,17,&lock);
    ret=do_lock_page(vcpu, va, lock);
    vmx_vcpu_set_gr(vcpu, 8, ret, 0);

    vmx_vcpu_increment_iip(vcpu);
}

static int do_set_shared_page(VCPU *vcpu, u64 gpa)
{
    u64 shared_info, o_info;
    struct domain *d = vcpu->domain;
    struct vcpu *v;
    if(vcpu->domain!=dom0)
        return -EPERM;
    shared_info = __gpa_to_mpa(vcpu->domain, gpa);
    o_info = (u64)vcpu->domain->shared_info;
    d->shared_info= (shared_info_t *)__va(shared_info);

    /* Copy existing shared info into new page */
    if (o_info) {
    	memcpy((void*)d->shared_info, (void*)o_info, PAGE_SIZE);
    	for_each_vcpu(d, v) {
	        v->vcpu_info = &d->shared_info->vcpu_data[v->vcpu_id];
    	}
    	/* If original page belongs to xen heap, then relinguish back
    	 * to xen heap. Or else, leave to domain itself to decide.
    	 */
    	if (likely(IS_XEN_HEAP_FRAME(virt_to_page(o_info))))
	    	free_xenheap_page(o_info);
    } else
        memset(d->shared_info, 0, PAGE_SIZE);
    return 0;
}

void hyper_set_shared_page(void)
{
    VCPU *vcpu=current;
    u64 gpa,ret;
    vmx_vcpu_get_gr(vcpu,16,&gpa);

    ret=do_set_shared_page(vcpu, gpa);
    vmx_vcpu_set_gr(vcpu, 8, ret, 0);

    vmx_vcpu_increment_iip(vcpu);
}

/*
void hyper_grant_table_op(void)
{
    VCPU *vcpu=current;
    u64 r32,r33,r34,ret;
    vmx_vcpu_get_gr(vcpu,16,&r32);
    vmx_vcpu_get_gr(vcpu,17,&r33);
    vmx_vcpu_get_gr(vcpu,18,&r34);

    ret=do_grant_table_op((unsigned int)r32, (void *)r33, (unsigned int)r34);
    vmx_vcpu_set_gr(vcpu, 8, ret, 0);
}
*/
