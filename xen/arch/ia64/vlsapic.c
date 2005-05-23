
/* -*-  Mode:C; c-basic-offset:4; tab-width:4; indent-tabs-mode:nil -*- */
/*
 * vlsapic.c: virtual lsapic model including ITC timer.
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
 *  Yaozu Dong (Eddie Dong) (Eddie.dong@intel.com)
 */

#include <linux/sched.h>
#include <public/arch-ia64.h>
#include <asm/ia64_int.h>
#include <asm/vcpu.h>
#include <asm/regionreg.h>
#include <asm/tlb.h>
#include <asm/processor.h>
#include <asm/delay.h>
#include <asm/vmx_vcpu.h>
#include <asm/vmx_vcpu.h>
#include <asm/regs.h>
#include <asm/gcc_intrin.h>
#include <asm/vmx_mm_def.h>
#include <asm/vmx.h>
#include <asm/hw_irq.h>
#include <asm/vmx_pal_vsa.h>
#include <asm/kregs.h>

//u64  fire_itc;
//u64  fire_itc2;
//u64  fire_itm;
//u64  fire_itm2;
/*
 * Update the checked last_itc.
 */
static void update_last_itc(vtime_t *vtm, uint64_t cur_itc)
{
    vtm->last_itc = cur_itc;
}

/*
 * ITC value saw in guest (host+offset+drift).
 */
static uint64_t now_itc(vtime_t *vtm)
{
        uint64_t guest_itc=vtm->vtm_offset+ia64_get_itc();
        
        if ( vtm->vtm_local_drift ) {
//          guest_itc -= vtm->vtm_local_drift;
        }       
        if ( (long)(guest_itc - vtm->last_itc) > 0 ) {
            return guest_itc;

        }
        else {
            /* guest ITC backwarded due after LP switch */
            return vtm->last_itc;
        }
}

/*
 * Interval time components reset.
 */
static void vtm_reset(VCPU *vcpu)
{
    uint64_t    cur_itc;
    vtime_t     *vtm;
    
    vtm=&(vcpu->arch.arch_vmx.vtm);
    vtm->vtm_offset = 0;
    vtm->vtm_local_drift = 0;
    VPD_CR(vcpu, itm) = 0;
    VPD_CR(vcpu, itv) = 0x10000;
    cur_itc = ia64_get_itc();
    vtm->last_itc = vtm->vtm_offset + cur_itc;
}

/* callback function when vtm_timer expires */
static void vtm_timer_fn(unsigned long data)
{
    vtime_t *vtm;
    VCPU    *vcpu = (VCPU*)data;
    u64	    cur_itc,vitm;

    UINT64  vec;
    
    vec = VPD_CR(vcpu, itv) & 0xff;
    vmx_vcpu_pend_interrupt(vcpu, vec);

    vtm=&(vcpu->arch.arch_vmx.vtm);
    cur_itc = now_itc(vtm);
    vitm =VPD_CR(vcpu, itm);
 //fire_itc2 = cur_itc;
 //fire_itm2 = vitm;
    update_last_itc(vtm,cur_itc);  // pseudo read to update vITC
    vtm->timer_hooked = 0;
}

void vtm_init(VCPU *vcpu)
{
    vtime_t     *vtm;
    uint64_t    itc_freq;
    
    vtm=&(vcpu->arch.arch_vmx.vtm);

    itc_freq = local_cpu_data->itc_freq;
    vtm->cfg_max_jump=itc_freq*MAX_JUMP_STEP/1000;
    vtm->cfg_min_grun=itc_freq*MIN_GUEST_RUNNING_TIME/1000;
    /* set up the actimer */
    init_ac_timer(&(vtm->vtm_timer));
    vtm->timer_hooked = 0;
    vtm->vtm_timer.cpu = 0;     /* Init value for SMP case */
    vtm->vtm_timer.data = (unsigned long)vcpu;
    vtm->vtm_timer.function = vtm_timer_fn;
    vtm_reset(vcpu);
}

/*
 * Action when guest read ITC.
 */
uint64_t vtm_get_itc(VCPU *vcpu)
{
    uint64_t    guest_itc, spsr;
    vtime_t    *vtm;

    vtm=&(vcpu->arch.arch_vmx.vtm);
    // FIXME: should use local_irq_disable & local_irq_enable ??
    local_irq_save(spsr);
    guest_itc = now_itc(vtm);
    update_last_itc(vtm, guest_itc);

    local_irq_restore(spsr);
    return guest_itc;
}

void vtm_set_itc(VCPU *vcpu, uint64_t new_itc)
{
    uint64_t    spsr;
    vtime_t     *vtm;

    vtm=&(vcpu->arch.arch_vmx.vtm);
    local_irq_save(spsr);
    vtm->vtm_offset = new_itc - ia64_get_itc();
    vtm->last_itc = new_itc;
    vtm_interruption_update(vcpu, vtm);
    local_irq_restore(spsr);
}

void vtm_set_itv(VCPU *vcpu)
{
    uint64_t    spsr,itv;
    vtime_t     *vtm;

    vtm=&(vcpu->arch.arch_vmx.vtm);
    local_irq_save(spsr);
    itv = VPD_CR(vcpu, itv);
    if ( ITV_IRQ_MASK(itv) && vtm->timer_hooked ) {
        rem_ac_timer(&(vtm->vtm_timer));
        vtm->timer_hooked = 0;
    }
    vtm_interruption_update(vcpu, vtm);
    local_irq_restore(spsr);
}


/*
 * Update interrupt or hook the vtm ac_timer for fire 
 * At this point vtm_timer should be removed if itv is masked.
 */
/* Interrupt must be disabled at this point */

extern u64 tick_to_ns(u64 tick);
#define TIMER_SLOP (50*1000) /* ns */	/* copy from ac_timer.c */
void vtm_interruption_update(VCPU *vcpu, vtime_t* vtm)
{
    uint64_t    cur_itc,vitm,vitv;
    uint64_t    expires;
    long     	diff_now, diff_last;
    uint64_t    spsr;
    
    vitv = VPD_CR(vcpu, itv);
    if ( ITV_IRQ_MASK(vitv) ) {
        return;
    }
    
    vitm =VPD_CR(vcpu, itm);
    local_irq_save(spsr);
    cur_itc =now_itc(vtm);
    diff_last = vtm->last_itc - vitm;
    diff_now = cur_itc - vitm;
    update_last_itc (vtm,cur_itc);
    
    if ( diff_last >= 0 ) {
        // interrupt already fired.
        if ( vtm->timer_hooked ) {
            rem_ac_timer(&(vtm->vtm_timer));
            vtm->timer_hooked = 0;          
        }
    }
    else if ( diff_now >= 0 ) {
        // ITV is fired.
        vmx_vcpu_pend_interrupt(vcpu, vitv&0xff);
    }
    /* Both last_itc & cur_itc < itm, wait for fire condition */
    else if ( vtm->timer_hooked ) {
        expires = NOW() + tick_to_ns(0-diff_now) + TIMER_SLOP;
        mod_ac_timer (&(vtm->vtm_timer), expires);
	printf("mod vtm_timer\n");
//fire_itc = cur_itc;
//fire_itm = vitm;
    }
    else {
        vtm->vtm_timer.expires = NOW() + tick_to_ns(0-diff_now) + TIMER_SLOP;
        vtm->vtm_timer.cpu = vcpu->processor;
            add_ac_timer(&(vtm->vtm_timer));
            vtm->timer_hooked = 1;
//fire_itc = cur_itc;
//fire_itm = vitm;
    }
    local_irq_restore(spsr);
}

/*
 * Action for vtm when the domain is scheduled out.
 * Remove the ac_timer for vtm.
 */
void vtm_domain_out(VCPU *vcpu)
{
    vtime_t     *vtm;
    uint64_t    spsr;
    
    vtm=&(vcpu->arch.arch_vmx.vtm);
    local_irq_save(spsr);
    if ( vtm->timer_hooked ) {
        rem_ac_timer(&(vtm->vtm_timer));
        vtm->timer_hooked = 0;
    }
    local_irq_restore(spsr);
}

/*
 * Action for vtm when the domain is scheduled in.
 * Fire vtm IRQ or add the ac_timer for vtm.
 */
void vtm_domain_in(VCPU *vcpu)
{
    vtime_t     *vtm;
    
    vtm=&(vcpu->arch.arch_vmx.vtm);
    vtm_interruption_update(vcpu, vtm);
}



/*
 * Next for vLSapic
 */

#define  NMI_VECTOR         2
#define  ExtINT_VECTOR      0

#define  VLSAPIC_INSVC(vcpu, i) ((vcpu)->arch.arch_vmx.in_service[i])
/*
 * LID-CR64: Keep in vpd.
 * IVR-CR65: (RO) see guest_read_ivr().
 * TPR-CR66: Keep in vpd, acceleration enabled.
 * EOI-CR67: see guest_write_eoi().
 * IRR0-3 - CR68-71: (RO) Keep in vpd irq_pending[]
 *          can move to vpd for optimization.
 * ITV: in time virtualization.
 * PMV: Keep in vpd initialized as 0x10000.
 * CMCV: Keep in vpd initialized as 0x10000.
 * LRR0-1: Keep in vpd, initialized as 0x10000.
 *
 */

void vlsapic_reset(VCPU *vcpu)
{
    int     i;
    VPD_CR(vcpu, lid) = 0;
    VPD_CR(vcpu, ivr) = 0;
    VPD_CR(vcpu,tpr) = 0x10000;
    VPD_CR(vcpu, eoi) = 0;
    VPD_CR(vcpu, irr[0]) = 0;
    VPD_CR(vcpu, irr[1]) = 0;
    VPD_CR(vcpu, irr[2]) = 0;
    VPD_CR(vcpu, irr[3]) = 0;
    VPD_CR(vcpu, pmv) = 0x10000;
    VPD_CR(vcpu, cmcv) = 0x10000;
    VPD_CR(vcpu, lrr0) = 0x10000;   // default reset value?
    VPD_CR(vcpu, lrr1) = 0x10000;   // default reset value?
    for ( i=0; i<4; i++) {
        VLSAPIC_INSVC(vcpu,i) = 0;
    }
}

/*
 *  Find highest signaled bits in 4 words (long). 
 *
 *  return 0-255: highest bits.
 *          -1 : Not found.
 */
static __inline__ int highest_bits(uint64_t *dat)
{
    uint64_t  bits, bitnum=-1;
    int i;
    
    /* loop for all 256 bits */
    for ( i=3; i >= 0 ; i -- ) {
        bits = dat[i];
        if ( bits ) {
            bitnum = ia64_fls(bits);
            return i*64+bitnum;
        }
    }
   return -1;
}

/*
 * Return 0-255 for pending irq.
 *        -1 when no pending.
 */
static int highest_pending_irq(VCPU *vcpu)
{
    if ( VPD_CR(vcpu, irr[0]) & (1UL<<NMI_VECTOR) ) return NMI_VECTOR;
    if ( VPD_CR(vcpu, irr[0]) & (1UL<<ExtINT_VECTOR) ) return ExtINT_VECTOR;
    return highest_bits(&VPD_CR(vcpu, irr[0]));
}

static int highest_inservice_irq(VCPU *vcpu)
{
    if ( VLSAPIC_INSVC(vcpu, 0) & (1UL<<NMI_VECTOR) ) return NMI_VECTOR;
    if ( VLSAPIC_INSVC(vcpu, 0) & (1UL<<ExtINT_VECTOR) ) return ExtINT_VECTOR;
    return highest_bits(&(VLSAPIC_INSVC(vcpu, 0)));
}

/*
 * The pending irq is higher than the inservice one.
 *
 */
static int is_higher_irq(int pending, int inservice)
{
    return ( (pending >> 4) > (inservice>>4) || 
                ((pending != -1) && (inservice == -1)) );
}

static int is_higher_class(int pending, int mic)
{
    return ( (pending >> 4) > mic );
}

static int is_invalid_irq(int vec)
{
    return (vec == 1 || ((vec <= 14 && vec >= 3)));
}

/* See Table 5-8 in SDM vol2 for the definition */
static int
irq_masked(VCPU *vcpu, int h_pending, int h_inservice)
{
    uint64_t    vtpr;
    
    vtpr = VPD_CR(vcpu, tpr);

    if ( h_pending == NMI_VECTOR && h_inservice != NMI_VECTOR )
        // Non Maskable Interrupt
        return 0;

    if ( h_pending == ExtINT_VECTOR && h_inservice >= 16)
        return (vtpr>>16)&1;    // vtpr.mmi

    if ( !(vtpr&(1UL<<16)) &&
          is_higher_irq(h_pending, h_inservice) &&
          is_higher_class(h_pending, (vtpr>>4)&0xf) )
        return 0;

    return 1;
}

void vmx_vcpu_pend_interrupt(VCPU *vcpu, UINT64 vector)
{
    uint64_t    spsr;

    if (vector & ~0xff) {
        printf("vmx_vcpu_pend_interrupt: bad vector\n");
        return;
    }
    local_irq_save(spsr);
    VPD_CR(vcpu,irr[vector>>6]) |= 1UL<<(vector&63);
    local_irq_restore(spsr);
}

/*
 * If the new pending interrupt is enabled and not masked, we directly inject 
 * it into the guest. Otherwise, we set the VHPI if vac.a_int=1 so that when 
 * the interrupt becomes unmasked, it gets injected.
 * RETURN:
 *  TRUE:   Interrupt is injected.
 *  FALSE:  Not injected but may be in VHPI when vac.a_int=1
 *
 * Optimization: We defer setting the VHPI until the EOI time, if a higher 
 *               priority interrupt is in-service. The idea is to reduce the 
 *               number of unnecessary calls to inject_vhpi.
 */
int vmx_check_pending_irq(VCPU *vcpu)
{
    uint64_t  spsr;
    int     h_pending, h_inservice;
    int injected=0;
    uint64_t    isr;
    IA64_PSR    vpsr;

    local_irq_save(spsr);
    h_pending = highest_pending_irq(vcpu);
    if ( h_pending == -1 ) goto chk_irq_exit;
    h_inservice = highest_inservice_irq(vcpu);

    vpsr.val = vmx_vcpu_get_psr(vcpu);
    if (  vpsr.i &&
        !irq_masked(vcpu, h_pending, h_inservice) ) {
        //inject_guest_irq(v);
        isr = vpsr.val & IA64_PSR_RI;
        if ( !vpsr.ic )
            panic("Interrupt when IC=0\n");
        vmx_reflect_interruption(0,isr,0, 12 ); // EXT IRQ
        injected = 1;
    }
    else if ( VMX_VPD(vcpu,vac).a_int && 
            is_higher_irq(h_pending,h_inservice) ) {
        vmx_inject_vhpi(vcpu,h_pending);
    }

chk_irq_exit:
    local_irq_restore(spsr);
    return injected;
}

void guest_write_eoi(VCPU *vcpu)
{
    int vec;
    uint64_t  spsr;

    vec = highest_inservice_irq(vcpu);
    if ( vec < 0 ) panic("Wrong vector to EOI\n");
    local_irq_save(spsr);
    VLSAPIC_INSVC(vcpu,vec>>6) &= ~(1UL <<(vec&63));
    local_irq_restore(spsr);
    VPD_CR(vcpu, eoi)=0;    // overwrite the data
}

uint64_t guest_read_vivr(VCPU *vcpu)
{
    int vec, next, h_inservice;
    uint64_t  spsr;

    local_irq_save(spsr);
    vec = highest_pending_irq(vcpu);
    h_inservice = highest_inservice_irq(vcpu);
    if ( vec < 0 || irq_masked(vcpu, vec, h_inservice) ) {
        local_irq_restore(spsr);
        return IA64_SPURIOUS_INT_VECTOR;
    }
 
    VLSAPIC_INSVC(vcpu,vec>>6) |= (1UL <<(vec&63));
    VPD_CR(vcpu, irr[vec>>6]) &= ~(1UL <<(vec&63));

    h_inservice = highest_inservice_irq(vcpu);
    next = highest_pending_irq(vcpu);
    if ( VMX_VPD(vcpu,vac).a_int &&
        (is_higher_irq(next, h_inservice) || (next == -1)) )
        vmx_inject_vhpi(vcpu, next);
    local_irq_restore(spsr);
    return (uint64_t)vec;
}

void vmx_inject_vhpi(VCPU *vcpu, u8 vec)
{
        VMX_VPD(vcpu,vhpi) = vec / 16;


        // non-maskable
        if ( vec == NMI_VECTOR ) // NMI
                VMX_VPD(vcpu,vhpi) = 32;
        else if (vec == ExtINT_VECTOR) //ExtINT
                VMX_VPD(vcpu,vhpi) = 16;
        else if (vec == -1)
                VMX_VPD(vcpu,vhpi) = 0; /* Nothing pending */

        ia64_call_vsa ( PAL_VPS_SET_PENDING_INTERRUPT, 
            (uint64_t) &(vcpu->arch.arch_vmx.vpd), 0, 0,0,0,0,0);
}

