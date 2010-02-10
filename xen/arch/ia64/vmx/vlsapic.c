
/* -*-  Mode:C; c-basic-offset:4; tab-width:4; indent-tabs-mode:nil -*- */
/*
 * vlsapic.c: virtual lsapic model including ITC timer.
 * Copyright (c) 2005, Intel Corporation.
 *
 * Copyright (c) 2007, Isaku Yamahata <yamahata at valinux co jp>
 *                     VA Linux Systems Japan K.K.
 *                     save/restore support
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
#include <public/xen.h>
#include <asm/ia64_int.h>
#include <asm/vcpu.h>
#include <asm/regionreg.h>
#include <asm/processor.h>
#include <asm/delay.h>
#include <asm/vmx_vcpu.h>
#include <asm/regs.h>
#include <asm/gcc_intrin.h>
#include <asm/vmx_mm_def.h>
#include <asm/vmx.h>
#include <asm/vmx_vpd.h>
#include <asm/hw_irq.h>
#include <asm/vmx_pal_vsa.h>
#include <asm/kregs.h>
#include <asm/vmx_platform.h>
#include <asm/viosapic.h>
#include <asm/vlsapic.h>
#include <asm/vmx_phy_mode.h>
#include <asm/linux/jiffies.h>
#include <xen/domain.h>
#include <asm/hvm/support.h>
#include <public/hvm/save.h>
#include <public/arch-ia64/hvm/memmap.h>

#ifdef IPI_DEBUG
#define IPI_DPRINTK(x...) printk(x)
#else
#define IPI_DPRINTK(x...)
#endif

//u64  fire_itc;
//u64  fire_itc2;
//u64  fire_itm;
//u64  fire_itm2;
/*
 * Update the checked last_itc.
 */

extern void vmx_reflect_interruption(u64 ifa, u64 isr, u64 iim,
                                     u64 vector, REGS *regs);
static void update_last_itc(vtime_t *vtm, uint64_t cur_itc)
{
    vtm->last_itc = cur_itc;
}

/*
 * Next for vLSapic
 */

#define NMI_VECTOR		2
#define ExtINT_VECTOR		0
#define NULL_VECTOR		-1

static void update_vhpi(VCPU *vcpu, int vec)
{
    u64 vhpi;

    if (vec == NULL_VECTOR)
        vhpi = 0;
    else if (vec == NMI_VECTOR)
        vhpi = 32;
    else if (vec == ExtINT_VECTOR)
        vhpi = 16;
    else
        vhpi = vec >> 4;

    VCPU(vcpu,vhpi) = vhpi;
    // TODO: Add support for XENO
    if (VCPU(vcpu,vac).a_int) {
        vmx_vpd_pin(vcpu);
        ia64_call_vsa(PAL_VPS_SET_PENDING_INTERRUPT, 
                      (uint64_t)vcpu->arch.privregs, 0, 0, 0, 0, 0, 0);
        vmx_vpd_unpin(vcpu);
    }
}


/*
 * May come from virtualization fault or
 * nested host interrupt.
 */
static int vmx_vcpu_unpend_interrupt(VCPU *vcpu, uint8_t vector)
{
    int ret;

    if (vector & ~0xff) {
        dprintk(XENLOG_WARNING, "vmx_vcpu_pend_interrupt: bad vector\n");
        return -1;
    }

    ret = test_and_clear_bit(vector, &VCPU(vcpu, irr[0]));

    if (ret) {
        vcpu->arch.irq_new_pending = 1;
        wmb();
    }

    return ret;
}

/*
 * ITC value saw in guest (host+offset+drift).
 */
static uint64_t now_itc(vtime_t *vtm)
{
    uint64_t guest_itc = vtm->vtm_offset + ia64_get_itc();

    if (guest_itc >= vtm->last_itc)
        return guest_itc;
    else
        /* guest ITC went backward due to LP switch */
        return vtm->last_itc;
}

/*
 * Interval time components reset.
 */
static void vtm_reset(VCPU *vcpu)
{
    int i;
    u64 vtm_offset;
    VCPU *v;
    struct domain *d = vcpu->domain;
    vtime_t *vtm = &VMX(vcpu, vtm);

    if (vcpu->vcpu_id == 0) {
        vtm_offset = 0UL - ia64_get_itc();
        for (i = d->max_vcpus - 1; i >= 0; i--) {
            if ((v = d->vcpu[i]) != NULL) {
                VMX(v, vtm).vtm_offset = vtm_offset;
                VMX(v, vtm).last_itc = 0;
            }
        }
    }
    vtm->vtm_local_drift = 0;
    VCPU(vcpu, itm) = 0;
    VCPU(vcpu, itv) = 0x10000;
    vtm->last_itc = 0;
}

/* callback function when vtm_timer expires */
static void vtm_timer_fn(void *data)
{
    VCPU *vcpu = data;
    vtime_t *vtm = &VMX(vcpu, vtm);
    u64 vitv;

    vitv = VCPU(vcpu, itv);
    if (!ITV_IRQ_MASK(vitv)) {
        vmx_vcpu_pend_interrupt(vcpu, ITV_VECTOR(vitv));
        vcpu_unblock(vcpu);
    } else
        vtm->pending = 1;

    /*
     * "+ 1" is for fixing oops message at timer_interrupt() on VTI guest. 
     * If oops checking condition changed to timer_after_eq() on VTI guest,
     * this parameter should be erased.
     */
    update_last_itc(vtm, VCPU(vcpu, itm) + 1);  // update vITC
}

void vtm_init(VCPU *vcpu)
{
    vtime_t     *vtm;
    uint64_t    itc_freq;

    vtm = &VMX(vcpu, vtm);

    itc_freq = local_cpu_data->itc_freq;
    vtm->cfg_max_jump=itc_freq*MAX_JUMP_STEP/1000;
    vtm->cfg_min_grun=itc_freq*MIN_GUEST_RUNNING_TIME/1000;
    init_timer(&vtm->vtm_timer, vtm_timer_fn, vcpu, vcpu->processor);
    vtm_reset(vcpu);
}

/*
 * Action when guest read ITC.
 */
uint64_t vtm_get_itc(VCPU *vcpu)
{
    uint64_t guest_itc;
    vtime_t *vtm = &VMX(vcpu, vtm);

    guest_itc = now_itc(vtm);
    return guest_itc;
}


void vtm_set_itc(VCPU *vcpu, uint64_t new_itc)
{
    int i;
    uint64_t vitm, vtm_offset;
    vtime_t *vtm;
    VCPU *v;
    struct domain *d = vcpu->domain;

    vitm = VCPU(vcpu, itm);
    vtm = &VMX(vcpu, vtm);
    if (vcpu->vcpu_id == 0) {
        vtm_offset = new_itc - ia64_get_itc();
        for (i = d->max_vcpus - 1; i >= 0; i--) {
            if ((v = d->vcpu[i]) != NULL) {
                VMX(v, vtm).vtm_offset = vtm_offset;
                VMX(v, vtm).last_itc = 0;
            }
        }
    }
    vtm->last_itc = 0;
    if (vitm <= new_itc)
        stop_timer(&vtm->vtm_timer);
    else
        vtm_set_itm(vcpu, vitm);
}


extern u64 cycle_to_ns(u64 cyle);


void vtm_set_itm(VCPU *vcpu, uint64_t val)
{
    vtime_t *vtm;
    uint64_t   vitv, cur_itc, expires;

    vitv = VCPU(vcpu, itv);
    vtm = &VMX(vcpu, vtm);
    VCPU(vcpu, itm) = val;
    if (val > vtm->last_itc) {
        cur_itc = now_itc(vtm);
        if (time_before(val, cur_itc))
            val = cur_itc;
        expires = NOW() + cycle_to_ns(val-cur_itc);
        vmx_vcpu_unpend_interrupt(vcpu, ITV_VECTOR(vitv));
        set_timer(&vtm->vtm_timer, expires);
    }else{
        stop_timer(&vtm->vtm_timer);
    }
}


void vtm_set_itv(VCPU *vcpu, uint64_t val)
{
    vtime_t *vtm = &VMX(vcpu, vtm);

    VCPU(vcpu, itv) = val;

    if (!ITV_IRQ_MASK(val) && vtm->pending) {
        vmx_vcpu_pend_interrupt(vcpu, ITV_VECTOR(val));
        vtm->pending = 0;
    }
}


void vlsapic_reset(VCPU *vcpu)
{
    int     i;

    VCPU(vcpu, lid) = VCPU_LID(vcpu);
    VCPU(vcpu, ivr) = 0;
    VCPU(vcpu,tpr) = 0x10000;
    VCPU(vcpu, eoi) = 0;
    VCPU(vcpu, irr[0]) = 0;
    VCPU(vcpu, irr[1]) = 0;
    VCPU(vcpu, irr[2]) = 0;
    VCPU(vcpu, irr[3]) = 0;
    VCPU(vcpu, pmv) = 0x10000;
    VCPU(vcpu, cmcv) = 0x10000;
    VCPU(vcpu, lrr0) = 0x10000;   // default reset value?
    VCPU(vcpu, lrr1) = 0x10000;   // default reset value?
    update_vhpi(vcpu, NULL_VECTOR);
    VLSAPIC_XTP(vcpu) = 0x80;   // disabled
    for ( i=0; i<4; i++) {
        VLSAPIC_INSVC(vcpu,i) = 0;
    }

    dprintk(XENLOG_INFO, "VLSAPIC inservice base=%p\n", &VLSAPIC_INSVC(vcpu,0) );
}

/*
 *  Find highest signaled bits in 4 words (long). 
 *
 *  return 0-255: highest bits.
 *          -1 : Not found.
 */
static __inline__ int highest_bits(uint64_t *dat)
{
    uint64_t  bits, bitnum;
    int i;

    /* loop for all 256 bits */
    for ( i=3; i >= 0 ; i -- ) {
        bits = dat[i];
        if ( bits ) {
            bitnum = ia64_fls(bits);
            return i*64+bitnum;
        }
    }
   return NULL_VECTOR;
}

/*
 * Return 0-255 for pending irq.
 *        NULL_VECTOR: when no pending.
 */
static int highest_pending_irq(VCPU *vcpu)
{
    if ( VCPU(vcpu, irr[0]) & (1UL<<NMI_VECTOR) ) return NMI_VECTOR;
    if ( VCPU(vcpu, irr[0]) & (1UL<<ExtINT_VECTOR) ) return ExtINT_VECTOR;
    return highest_bits(&VCPU(vcpu, irr[0]));
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
    return ( (pending > inservice) || 
                ((pending != NULL_VECTOR) && (inservice == NULL_VECTOR)) );
}

static int is_higher_class(int pending, int mic)
{
    return ( (pending >> 4) > mic );
}

#define   IRQ_NO_MASKED         0
#define   IRQ_MASKED_BY_VTPR    1
#define   IRQ_MASKED_BY_INSVC   2   // masked by inservice IRQ

/* See Table 5-8 in SDM vol2 for the definition */
static int
_xirq_masked(VCPU *vcpu, int h_pending, int h_inservice)
{
    tpr_t    vtpr;

    vtpr.val = VCPU(vcpu, tpr);

    if ( h_inservice == NMI_VECTOR ) {
        return IRQ_MASKED_BY_INSVC;
    }
    if ( h_pending == NMI_VECTOR ) {
        // Non Maskable Interrupt
        return IRQ_NO_MASKED;
    }
    if ( h_inservice == ExtINT_VECTOR ) {
        return IRQ_MASKED_BY_INSVC;
    }

    if ( h_pending == ExtINT_VECTOR ) {
        if ( vtpr.mmi ) {
            // mask all external IRQ
            return IRQ_MASKED_BY_VTPR;
        }
        else {
            return IRQ_NO_MASKED;
        }
    }

    if ( is_higher_irq(h_pending, h_inservice) ) {
        if ( is_higher_class(h_pending, vtpr.mic + (vtpr.mmi << 4)) ) {
            return IRQ_NO_MASKED;
        }
        else {
            return IRQ_MASKED_BY_VTPR;
        }
    }
    else {
        return IRQ_MASKED_BY_INSVC;
    }
}

static int irq_masked(VCPU *vcpu, int h_pending, int h_inservice)
{
    int mask;

    mask = _xirq_masked(vcpu, h_pending, h_inservice);
    return mask;
}


/*
 * May come from virtualization fault or
 * nested host interrupt.
 */
int vmx_vcpu_pend_interrupt(VCPU *vcpu, uint8_t vector)
{
    int ret;

    if (vector & ~0xff) {
        gdprintk(XENLOG_INFO, "vmx_vcpu_pend_interrupt: bad vector\n");
        return -1;
    }
    ret = test_and_set_bit(vector, &VCPU(vcpu, irr[0]));

    if (!ret) {
        vcpu->arch.irq_new_pending = 1;
        wmb();
    }

    return ret;
}


/*
 * Add batch of pending interrupt.
 * The interrupt source is contained in pend_irr[0-3] with
 * each bits stand for one interrupt.
 */
void vmx_vcpu_pend_batch_interrupt(VCPU *vcpu, u64 *pend_irr)
{
    uint64_t    spsr;
    int     i;

    local_irq_save(spsr);
    for (i=0 ; i<4; i++ ) {
        VCPU(vcpu,irr[i]) |= pend_irr[i];
    }
    local_irq_restore(spsr);
    vcpu->arch.irq_new_pending = 1;
    wmb();
}

/*
 * If the new pending interrupt is enabled and not masked, we directly inject 
 * it into the guest. Otherwise, we set the VHPI if vac.a_int=1 so that when 
 * the interrupt becomes unmasked, it gets injected.
 * RETURN:
 *    the highest unmasked interrupt.
 *
 * Optimization: We defer setting the VHPI until the EOI time, if a higher 
 *               priority interrupt is in-service. The idea is to reduce the 
 *               number of unnecessary calls to inject_vhpi.
 */
int vmx_check_pending_irq(VCPU *vcpu)
{
    int  mask, h_pending, h_inservice;
    uint64_t isr;
    IA64_PSR vpsr;
    REGS *regs=vcpu_regs(vcpu);
    h_pending = highest_pending_irq(vcpu);
    if ( h_pending == NULL_VECTOR ) {
        update_vhpi(vcpu, NULL_VECTOR);
        h_pending = SPURIOUS_VECTOR;
        goto chk_irq_exit;
    }
    h_inservice = highest_inservice_irq(vcpu);

    vpsr.val = VCPU(vcpu, vpsr);
    mask = irq_masked(vcpu, h_pending, h_inservice);
    if (  vpsr.i && IRQ_NO_MASKED == mask ) {
        isr = vpsr.val & IA64_PSR_RI;
        if ( !vpsr.ic )
            panic_domain(regs,"Interrupt when IC=0\n");
        update_vhpi(vcpu, h_pending);
        vmx_reflect_interruption(0, isr, 0, 12, regs); // EXT IRQ
    } else if (mask == IRQ_MASKED_BY_INSVC) {
        if (VCPU(vcpu, vhpi))
            update_vhpi(vcpu, NULL_VECTOR);
    }
    else {
        // masked by vpsr.i or vtpr.
        update_vhpi(vcpu,h_pending);
    }

chk_irq_exit:
    return h_pending;
}

/*
 * Set a INIT interruption request to vcpu[0] of target domain.
 * The INIT interruption is injected into each vcpu by guest firmware.
 */
void vmx_pend_pal_init(struct domain *d)
{
    VCPU *vcpu;

    vcpu = d->vcpu[0];
    vcpu->arch.arch_vmx.pal_init_pending = 1;
}

/*
 * Only coming from virtualization fault.
 */
void guest_write_eoi(VCPU *vcpu)
{
    int vec;

    vec = highest_inservice_irq(vcpu);
    if (vec == NULL_VECTOR) {
        gdprintk(XENLOG_WARNING, "vcpu(%d): Wrong vector to EOI\n",
                 vcpu->vcpu_id);
        return;
    }
    VLSAPIC_INSVC(vcpu,vec>>6) &= ~(1UL <<(vec&63));
    VCPU(vcpu, eoi)=0;    // overwrite the data
    vcpu->arch.irq_new_pending=1;
    wmb();
}

int is_unmasked_irq(VCPU *vcpu)
{
    int h_pending, h_inservice;

    h_pending = highest_pending_irq(vcpu);
    h_inservice = highest_inservice_irq(vcpu);
    if ( h_pending == NULL_VECTOR || 
        irq_masked(vcpu, h_pending, h_inservice) != IRQ_NO_MASKED ) {
        return 0;
    }
    else
        return 1;
}

uint64_t guest_read_vivr(VCPU *vcpu)
{
    int vec, h_inservice, mask;
    vec = highest_pending_irq(vcpu);
    h_inservice = highest_inservice_irq(vcpu);
    mask = irq_masked(vcpu, vec, h_inservice);
    if (vec == NULL_VECTOR || mask == IRQ_MASKED_BY_INSVC) {
        if (VCPU(vcpu, vhpi))
            update_vhpi(vcpu, NULL_VECTOR);
        return IA64_SPURIOUS_INT_VECTOR;
    }
    if (mask == IRQ_MASKED_BY_VTPR) {
        update_vhpi(vcpu, vec);
        return IA64_SPURIOUS_INT_VECTOR;
    }
    VLSAPIC_INSVC(vcpu,vec>>6) |= (1UL <<(vec&63));
    vmx_vcpu_unpend_interrupt(vcpu, vec);
    return (uint64_t)vec;
}

static void generate_exirq(VCPU *vcpu)
{
    IA64_PSR    vpsr;
    uint64_t    isr;
    REGS *regs=vcpu_regs(vcpu);
    vpsr.val = VCPU(vcpu, vpsr);
    isr = vpsr.val & IA64_PSR_RI;
    if ( !vpsr.ic )
        panic_domain(regs,"Interrupt when IC=0\n");
    vmx_reflect_interruption(0,isr,0, 12, regs); // EXT IRQ
}

void vhpi_detection(VCPU *vcpu)
{
    uint64_t    threshold,vhpi;
    tpr_t       vtpr;
    IA64_PSR    vpsr;
    vpsr.val = VCPU(vcpu, vpsr);
    vtpr.val = VCPU(vcpu, tpr);

    threshold = ((!vpsr.i) << 5) | (vtpr.mmi << 4) | vtpr.mic;
    vhpi = VCPU(vcpu,vhpi);
    if ( vhpi > threshold ) {
        // interrupt actived
        generate_exirq (vcpu);
    }
}

void vmx_vexirq(VCPU *vcpu)
{
    generate_exirq (vcpu);
}

struct vcpu *lid_to_vcpu(struct domain *d, uint16_t dest)
{
    int id = dest >> 8;

    /* Fast look: assume EID=0 ID=vcpu_id.  */
    if ((dest & 0xff) == 0 && id < d->max_vcpus)
        return d->vcpu[id];
    return NULL;
}

/*
 * To inject INIT to guest, we must set the PAL_INIT entry 
 * and set psr to switch to physical mode
 */
#define PSR_SET_BITS (IA64_PSR_DT | IA64_PSR_IT | IA64_PSR_RT | \
                      IA64_PSR_IC | IA64_PSR_RI | IA64_PSR_I | IA64_PSR_CPL)

static void vmx_inject_guest_pal_init(VCPU *vcpu)
{
    REGS *regs = vcpu_regs(vcpu);
    uint64_t psr = vmx_vcpu_get_psr(vcpu);

    regs->cr_iip = PAL_INIT_ENTRY;

    psr = psr & ~PSR_SET_BITS;
    vmx_vcpu_set_psr(vcpu, psr);
}


/*
 * Deliver IPI message. (Only U-VP is supported now)
 *  offset: address offset to IPI space.
 *  value:  deliver value.
 */
static int vcpu_deliver_int(VCPU *vcpu, uint64_t dm, uint64_t vector)
{
    int running = vcpu->is_running;

    IPI_DPRINTK("deliver_int %lx %lx\n", dm, vector);

    switch (dm) {
    case SAPIC_FIXED:     // INT
        vmx_vcpu_pend_interrupt(vcpu, vector);
        break;
    case SAPIC_LOWEST_PRIORITY:
    {
        struct vcpu *lowest = vcpu_viosapic(vcpu)->lowest_vcpu;

        if (lowest == NULL)
            lowest = vcpu;
        vmx_vcpu_pend_interrupt(lowest, vector);
        break;
    }
    case SAPIC_PMI:
        // TODO -- inject guest PMI
        panic_domain(NULL, "Inject guest PMI!\n");
        break;
    case SAPIC_NMI:
        vmx_vcpu_pend_interrupt(vcpu, 2);
        break;
    case SAPIC_INIT:
        vmx_inject_guest_pal_init(vcpu);
        break;
    case SAPIC_EXTINT:     // ExtINT
        vmx_vcpu_pend_interrupt(vcpu, 0);
        break;
    default:
        return -EINVAL;
    }

    /* Kick vcpu.  */
    vcpu_unblock(vcpu);
    if (running)
        smp_send_event_check_cpu(vcpu->processor);

    return 0;
}

int vlsapic_deliver_int(struct domain *d,
			uint16_t dest, uint64_t dm, uint64_t vector)
{
    VCPU *vcpu;

    vcpu = lid_to_vcpu(d, dest);
    if (vcpu == NULL)
        return -ESRCH;

    if (!vcpu->is_initialised || test_bit(_VPF_down, &vcpu->pause_flags))
        return -ENOEXEC;

    return vcpu_deliver_int (vcpu, dm, vector);
}

/*
 * Deliver the INIT interruption to guest.
 */
void deliver_pal_init(VCPU *vcpu)
{
    vcpu_deliver_int(vcpu, SAPIC_INIT, 0);
}

/*
 * execute write IPI op.
 */
static void vlsapic_write_ipi(VCPU *vcpu, uint64_t addr, uint64_t value)
{
    VCPU   *targ;
    struct domain *d = vcpu->domain; 

    targ = lid_to_vcpu(vcpu->domain,
                       (((ipi_a_t)addr).id << 8) | ((ipi_a_t)addr).eid);
    if (targ == NULL)
        panic_domain(NULL, "Unknown IPI cpu\n");

    if (!targ->is_initialised ||
        test_bit(_VPF_down, &targ->pause_flags)) {

        struct pt_regs *targ_regs = vcpu_regs(targ);

        if (arch_set_info_guest(targ, NULL) != 0) {
            printk("arch_boot_vcpu: failure\n");
            return;
        }
        /* First or next rendez-vous: set registers. */
        vcpu_init_regs(targ);
        targ_regs->cr_iip = d->arch.sal_data->boot_rdv_ip;
        targ_regs->r1 = d->arch.sal_data->boot_rdv_r1;

        if (test_and_clear_bit(_VPF_down,&targ->pause_flags)) {
            vcpu_wake(targ);
            printk(XENLOG_DEBUG "arch_boot_vcpu: vcpu %d awaken %016lx!\n",
                   targ->vcpu_id, targ_regs->cr_iip);
        } else {
            printk("arch_boot_vcpu: huh, already awake!");
        }
    } else {
        if (((ipi_d_t)value).dm == SAPIC_LOWEST_PRIORITY ||
            vcpu_deliver_int(targ, ((ipi_d_t)value).dm, 
                             ((ipi_d_t)value).vector) < 0)
            panic_domain(NULL, "Deliver reserved interrupt!\n");
    }
    return;
}


unsigned long vlsapic_read(struct vcpu *v,
                           unsigned long addr,
                           unsigned long length)
{
    uint64_t result = 0;

    addr &= (PIB_SIZE - 1);

    switch (addr) {
    case PIB_OFST_INTA:
        if (length == 1) // 1 byte load
            ; // There is no i8259, there is no INTA access
        else
            panic_domain(NULL,"Undefined read on PIB INTA\n");

        break;
    case PIB_OFST_XTP:
        if (length == 1) {
            result = VLSAPIC_XTP(v);
            // printk("read xtp %lx\n", result);
        } else {
            panic_domain(NULL, "Undefined read on PIB XTP\n");
        }
        break;
    default:
        if (PIB_LOW_HALF(addr)) {  // lower half
            if (length != 8 )
                panic_domain(NULL, "Undefined IPI-LHF read!\n");
            else
                IPI_DPRINTK("IPI-LHF read %lx\n", pib_off);
        } else {  // upper half
            IPI_DPRINTK("IPI-UHF read %lx\n", addr);
        }
        break;
    }
    return result;
}

static void vlsapic_write_xtp(struct vcpu *v, uint8_t val)
{
    struct viosapic * viosapic;
    struct vcpu *lvcpu, *vcpu;
    viosapic = vcpu_viosapic(v); 

    spin_lock(&viosapic->lock);
    lvcpu = viosapic->lowest_vcpu;
    VLSAPIC_XTP(v) = val;
    
    for_each_vcpu(v->domain, vcpu) {
        if (VLSAPIC_XTP(lvcpu) > VLSAPIC_XTP(vcpu))
            lvcpu = vcpu;
    }
        
    if (VLSAPIC_XTP(lvcpu) & 0x80)  // Disabled
        lvcpu = NULL;

    viosapic->lowest_vcpu = lvcpu;
    spin_unlock(&viosapic->lock);
}

void vlsapic_write(struct vcpu *v,
                      unsigned long addr,
                      unsigned long length,
                      unsigned long val)
{
    addr &= (PIB_SIZE - 1);

    switch (addr) {
    case PIB_OFST_INTA:
        panic_domain(NULL, "Undefined write on PIB INTA\n");
        break;
    case PIB_OFST_XTP:
        if (length == 1) {
            // printk("write xtp %lx\n", val);
            vlsapic_write_xtp(v, val);
        } else {
            panic_domain(NULL, "Undefined write on PIB XTP\n");
        }
        break;
    default:
        if (PIB_LOW_HALF(addr)) {   // lower half
            if (length != 8)
                panic_domain(NULL, "Undefined IPI-LHF write with size %ld!\n",
                             length);
            else
                vlsapic_write_ipi(v, addr, val);
        }
        else {   // upper half
            // printk("IPI-UHF write %lx\n",addr);
            panic_domain(NULL, "No support for SM-VP yet\n");
        }
        break;
    }
}

static int vlsapic_save(struct domain *d, hvm_domain_context_t *h)
{
    struct vcpu *v;

    for_each_vcpu(d, v) {
        struct hvm_hw_ia64_vlsapic vlsapic;
        int i;

        if (test_bit(_VPF_down, &v->pause_flags))
            continue;

        memset(&vlsapic, 0, sizeof(vlsapic));
        for (i = 0; i < 4; i++)
            vlsapic.insvc[i] = VLSAPIC_INSVC(v,i);

        vlsapic.vhpi = VCPU(v, vhpi);
        vlsapic.xtp = VLSAPIC_XTP(v);
        vlsapic.pal_init_pending = v->arch.arch_vmx.pal_init_pending;

        if (hvm_save_entry(VLSAPIC, v->vcpu_id, h, &vlsapic))
            return -EINVAL;
    }

    return 0;
}

static int vlsapic_load(struct domain *d, hvm_domain_context_t *h)
{
    uint16_t vcpuid;
    struct vcpu *v;
    struct hvm_hw_ia64_vlsapic vlsapic;
    int i;

    vcpuid = hvm_load_instance(h);
    if (vcpuid >= d->max_vcpus || (v = d->vcpu[vcpuid]) == NULL) {
        gdprintk(XENLOG_ERR,
                 "%s: domain has no vlsapic %u\n", __func__, vcpuid);
        return -EINVAL;
    }

    if (hvm_load_entry(VLSAPIC, h, &vlsapic) != 0) 
        return -EINVAL;

    for (i = 0; i < 4; i++)
        VLSAPIC_INSVC(v,i) = vlsapic.insvc[i];

    VCPU(v, vhpi) = vlsapic.vhpi;
    VLSAPIC_XTP(v) = vlsapic.xtp;
    v->arch.arch_vmx.pal_init_pending = vlsapic.pal_init_pending;
    v->arch.irq_new_pending = 1; /* to force checking irq */

    return 0;
}

HVM_REGISTER_SAVE_RESTORE(VLSAPIC, vlsapic_save, vlsapic_load,
                          1, HVMSR_PER_VCPU);

static int vtime_save(struct domain *d, hvm_domain_context_t *h)
{
    struct vcpu *v;

    for_each_vcpu(d, v) {
        vtime_t *vtm = &VMX(v, vtm);
        struct hvm_hw_ia64_vtime vtime;

        if (test_bit(_VPF_down, &v->pause_flags))
            continue;

        stop_timer(&vtm->vtm_timer);//XXX should wait for callback not running.

        memset(&vtime, 0, sizeof(vtime));
        vtime.itc = now_itc(vtm);
        vtime.itm = VCPU(v, itm);
        vtime.last_itc = vtm->last_itc;
        vtime.pending = vtm->pending;

        vtm_set_itm(v, vtime.itm);// this may start timer.

        if (hvm_save_entry(VTIME, v->vcpu_id, h, &vtime))
            return -EINVAL;
    }

    return 0;
}

static int vtime_load(struct domain *d, hvm_domain_context_t *h)
{
    uint16_t vcpuid;
    struct vcpu *v;
    struct hvm_hw_ia64_vtime vtime;
    vtime_t *vtm;

    vcpuid = hvm_load_instance(h);
    if (vcpuid >= d->max_vcpus || (v = d->vcpu[vcpuid]) == NULL) {
        gdprintk(XENLOG_ERR,
                 "%s: domain has no vtime %u\n", __func__, vcpuid);
        return -EINVAL;
    }

    if (hvm_load_entry(VTIME, h, &vtime) != 0)
        return -EINVAL;

    vtm = &VMX(v, vtm);
    stop_timer(&vtm->vtm_timer); //XXX should wait for callback not running.

    vtm->last_itc = vtime.last_itc;
    vtm->pending = vtime.pending;

    migrate_timer(&vtm->vtm_timer, v->processor);
    vtm_set_itm(v, vtime.itm);
    vtm_set_itc(v, vtime.itc); // This may start timer.

    if (test_and_clear_bit(_VPF_down, &v->pause_flags))
        vcpu_wake(v);

    return 0;
}

HVM_REGISTER_SAVE_RESTORE(VTIME, vtime_save, vtime_load, 1, HVMSR_PER_VCPU);
