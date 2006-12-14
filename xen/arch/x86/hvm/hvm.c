/*
 * hvm.c: Common hardware virtual machine abstractions.
 *
 * Copyright (c) 2004, Intel Corporation.
 * Copyright (c) 2005, International Business Machines Corporation.
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
 */

#include <xen/config.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/trace.h>
#include <xen/sched.h>
#include <xen/irq.h>
#include <xen/softirq.h>
#include <xen/domain.h>
#include <xen/domain_page.h>
#include <xen/hypercall.h>
#include <xen/guest_access.h>
#include <xen/event.h>
#include <xen/shadow.h>
#include <asm/current.h>
#include <asm/e820.h>
#include <asm/io.h>
#include <asm/shadow.h>
#include <asm/regs.h>
#include <asm/cpufeature.h>
#include <asm/processor.h>
#include <asm/types.h>
#include <asm/msr.h>
#include <asm/mc146818rtc.h>
#include <asm/spinlock.h>
#include <asm/hvm/hvm.h>
#include <asm/hvm/vpt.h>
#include <asm/hvm/support.h>
#include <public/sched.h>
#include <public/hvm/ioreq.h>
#include <public/version.h>
#include <public/memory.h>

int hvm_enabled = 0;

unsigned int opt_hvm_debug_level = 0;
integer_param("hvm_debug", opt_hvm_debug_level);

struct hvm_function_table hvm_funcs;

void hvm_stts(struct vcpu *v)
{
    /* FPU state already dirty? Then no need to setup_fpu() lazily. */
    if ( !test_bit(_VCPUF_fpu_dirtied, &v->vcpu_flags) )
        hvm_funcs.stts(v);
}

void hvm_set_guest_time(struct vcpu *v, u64 gtime)
{
    u64 host_tsc;

    rdtscll(host_tsc);

    v->arch.hvm_vcpu.cache_tsc_offset = gtime - host_tsc;
    hvm_funcs.set_tsc_offset(v, v->arch.hvm_vcpu.cache_tsc_offset);
}

u64 hvm_get_guest_time(struct vcpu *v)
{
    u64    host_tsc;

    rdtscll(host_tsc);
    return host_tsc + v->arch.hvm_vcpu.cache_tsc_offset;
}

void hvm_freeze_time(struct vcpu *v)
{
    struct periodic_time *pt=&v->domain->arch.hvm_domain.pl_time.periodic_tm;

    if ( pt->enabled && pt->first_injected
            && (v->vcpu_id == pt->bind_vcpu)
            && !v->arch.hvm_vcpu.guest_time ) {
        v->arch.hvm_vcpu.guest_time = hvm_get_guest_time(v);
        if ( !test_bit(_VCPUF_blocked, &v->vcpu_flags) )
        {
            stop_timer(&pt->timer);
            rtc_freeze(v);
        }
    }
}

void hvm_migrate_timers(struct vcpu *v)
{
    struct periodic_time *pt = &v->domain->arch.hvm_domain.pl_time.periodic_tm;
    struct PMTState *vpmt = &v->domain->arch.hvm_domain.pl_time.vpmt;

    if ( pt->enabled )
    {
        migrate_timer(&pt->timer, v->processor);
    }
    migrate_timer(&vcpu_vlapic(v)->vlapic_timer, v->processor);
    migrate_timer(&vpmt->timer, v->processor);
    rtc_migrate_timers(v);
}

void hvm_do_resume(struct vcpu *v)
{
    ioreq_t *p;
    struct periodic_time *pt = &v->domain->arch.hvm_domain.pl_time.periodic_tm;

    hvm_stts(v);

    /* Pick up the elapsed PIT ticks and re-enable pit_timer. */
    if ( pt->enabled && (v->vcpu_id == pt->bind_vcpu) && pt->first_injected )
    {
        if ( v->arch.hvm_vcpu.guest_time )
        {
            hvm_set_guest_time(v, v->arch.hvm_vcpu.guest_time);
            v->arch.hvm_vcpu.guest_time = 0;
        }
        pickup_deactive_ticks(pt);
    }

    /* Re-enable the RTC timer if needed */
    rtc_thaw(v);

    /* NB. Optimised for common case (p->state == STATE_IOREQ_NONE). */
    p = &get_vio(v->domain, v->vcpu_id)->vp_ioreq;
    while ( p->state != STATE_IOREQ_NONE )
    {
        switch ( p->state )
        {
        case STATE_IORESP_READY: /* IORESP_READY -> NONE */
            hvm_io_assist(v);
            break;
        case STATE_IOREQ_READY:  /* IOREQ_{READY,INPROCESS} -> IORESP_READY */
        case STATE_IOREQ_INPROCESS:
            wait_on_xen_event_channel(v->arch.hvm_vcpu.xen_port,
                                      (p->state != STATE_IOREQ_READY) &&
                                      (p->state != STATE_IOREQ_INPROCESS));
            break;
        default:
            gdprintk(XENLOG_ERR, "Weird HVM iorequest state %d.\n", p->state);
            domain_crash_synchronous();
        }
    }
}

int hvm_domain_initialise(struct domain *d)
{
    int rc;

    if ( !hvm_enabled )
    {
        gdprintk(XENLOG_WARNING, "Attempt to create a HVM guest "
                 "on a non-VT/AMDV platform.\n");
        return -EINVAL;
    }

    spin_lock_init(&d->arch.hvm_domain.pbuf_lock);
    spin_lock_init(&d->arch.hvm_domain.buffered_io_lock);
    spin_lock_init(&d->arch.hvm_domain.irq.lock);

    rc = shadow_enable(d, SHM2_refcounts|SHM2_translate|SHM2_external);
    if ( rc != 0 )
        return rc;

    vpic_init(d);
    vioapic_init(d);

    return 0;
}

void hvm_domain_destroy(struct domain *d)
{
    kill_timer(&d->arch.hvm_domain.pl_time.periodic_tm.timer);
    rtc_deinit(d);
    pmtimer_deinit(d);

    if ( d->arch.hvm_domain.shared_page_va )
        unmap_domain_page_global(
            (void *)d->arch.hvm_domain.shared_page_va);

    if ( d->arch.hvm_domain.buffered_io_va )
        unmap_domain_page_global((void *)d->arch.hvm_domain.buffered_io_va);
}

int hvm_vcpu_initialise(struct vcpu *v)
{
    struct hvm_domain *platform;
    int rc;

    if ( (rc = vlapic_init(v)) != 0 )
        return rc;

    if ( (rc = hvm_funcs.vcpu_initialise(v)) != 0 )
    {
        vlapic_destroy(v);
        return rc;
    }

    /* Create ioreq event channel. */
    v->arch.hvm_vcpu.xen_port = alloc_unbound_xen_event_channel(v, 0);
    if ( get_sp(v->domain) && get_vio(v->domain, v->vcpu_id) )
        get_vio(v->domain, v->vcpu_id)->vp_eport =
            v->arch.hvm_vcpu.xen_port;

    if ( v->vcpu_id != 0 )
        return 0;

    /* XXX Below should happen in hvm_domain_initialise(). */
    platform = &v->domain->arch.hvm_domain;

    init_timer(&platform->pl_time.periodic_tm.timer,
               pt_timer_fn, v, v->processor);
    rtc_init(v, RTC_PORT(0), RTC_IRQ);
    pmtimer_init(v, ACPI_PM_TMR_BLK_ADDRESS);

    /* Init guest TSC to start from zero. */
    hvm_set_guest_time(v, 0);

    return 0;
}

void hvm_vcpu_destroy(struct vcpu *v)
{
    vlapic_destroy(v);
    hvm_funcs.vcpu_destroy(v);

    /* Event channel is already freed by evtchn_destroy(). */
    /*free_xen_event_channel(v, v->arch.hvm_vcpu.xen_port);*/
}

int cpu_get_interrupt(struct vcpu *v, int *type)
{
    int vector;

    if ( (vector = cpu_get_apic_interrupt(v, type)) != -1 )
        return vector;

    if ( (v->vcpu_id == 0) &&
         ((vector = cpu_get_pic_interrupt(v, type)) != -1) )
        return vector;

    return -1;
}

static void hvm_vcpu_down(void)
{
    struct vcpu *v = current;
    struct domain *d = v->domain;
    int online_count = 0;

    gdprintk(XENLOG_INFO, "DOM%d/VCPU%d: going offline.\n",
           d->domain_id, v->vcpu_id);

    /* Doesn't halt us immediately, but we'll never return to guest context. */
    set_bit(_VCPUF_down, &v->vcpu_flags);
    vcpu_sleep_nosync(v);

    /* Any other VCPUs online? ... */
    LOCK_BIGLOCK(d);
    for_each_vcpu ( d, v )
        if ( !test_bit(_VCPUF_down, &v->vcpu_flags) )
            online_count++;
    UNLOCK_BIGLOCK(d);

    /* ... Shut down the domain if not. */
    if ( online_count == 0 )
    {
        gdprintk(XENLOG_INFO, "DOM%d: all CPUs offline -- powering off.\n",
                d->domain_id);
        domain_shutdown(d, SHUTDOWN_poweroff);
    }
}

void hvm_send_assist_req(struct vcpu *v)
{
    ioreq_t *p;

    p = &get_vio(v->domain, v->vcpu_id)->vp_ioreq;
    if ( unlikely(p->state != STATE_IOREQ_NONE) )
    {
        /* This indicates a bug in the device model.  Crash the domain. */
        gdprintk(XENLOG_ERR, "Device model set bad IO state %d.\n", p->state);
        domain_crash_synchronous();
    }

    prepare_wait_on_xen_event_channel(v->arch.hvm_vcpu.xen_port);

    /*
     * Following happens /after/ blocking and setting up ioreq contents.
     * prepare_wait_on_xen_event_channel() is an implicit barrier.
     */
    p->state = STATE_IOREQ_READY;
    notify_via_xen_event_channel(v->arch.hvm_vcpu.xen_port);
}

void hvm_hlt(unsigned long rflags)
{
    /*
     * If we halt with interrupts disabled, that's a pretty sure sign that we
     * want to shut down. In a real processor, NMIs are the only way to break
     * out of this.
     */
    if ( unlikely(!(rflags & X86_EFLAGS_IF)) )
        return hvm_vcpu_down();

    do_sched_op_compat(SCHEDOP_block, 0);
}

/*
 * __hvm_copy():
 *  @buf  = hypervisor buffer
 *  @addr = guest address to copy to/from
 *  @size = number of bytes to copy
 *  @dir  = copy *to* guest (TRUE) or *from* guest (FALSE)?
 *  @virt = addr is *virtual* (TRUE) or *guest physical* (FALSE)?
 * Returns number of bytes failed to copy (0 == complete success).
 */
static int __hvm_copy(void *buf, paddr_t addr, int size, int dir, int virt)
{
    unsigned long mfn;
    char *p;
    int count, todo;

    todo = size;
    while ( todo > 0 )
    {
        count = min_t(int, PAGE_SIZE - (addr & ~PAGE_MASK), todo);

        if ( virt )
            mfn = get_mfn_from_gpfn(shadow_gva_to_gfn(current, addr));
        else
            mfn = get_mfn_from_gpfn(addr >> PAGE_SHIFT);

        if ( mfn == INVALID_MFN )
            return todo;

        p = (char *)map_domain_page(mfn) + (addr & ~PAGE_MASK);

        if ( dir )
            memcpy(p, buf, count); /* dir == TRUE:  *to* guest */
        else
            memcpy(buf, p, count); /* dir == FALSE: *from guest */

        unmap_domain_page(p);

        addr += count;
        buf  += count;
        todo -= count;
    }

    return 0;
}

int hvm_copy_to_guest_phys(paddr_t paddr, void *buf, int size)
{
    return __hvm_copy(buf, paddr, size, 1, 0);
}

int hvm_copy_from_guest_phys(void *buf, paddr_t paddr, int size)
{
    return __hvm_copy(buf, paddr, size, 0, 0);
}

int hvm_copy_to_guest_virt(unsigned long vaddr, void *buf, int size)
{
    return __hvm_copy(buf, vaddr, size, 1, 1);
}

int hvm_copy_from_guest_virt(void *buf, unsigned long vaddr, int size)
{
    return __hvm_copy(buf, vaddr, size, 0, 1);
}


/* HVM specific printbuf. Mostly used for hvmloader chit-chat. */
void hvm_print_line(struct vcpu *v, const char c)
{
    struct hvm_domain *hd = &v->domain->arch.hvm_domain;

    spin_lock(&hd->pbuf_lock);
    hd->pbuf[hd->pbuf_idx++] = c;
    if ( (hd->pbuf_idx == (sizeof(hd->pbuf) - 2)) || (c == '\n') )
    {
        if ( c != '\n' )
            hd->pbuf[hd->pbuf_idx++] = '\n';
        hd->pbuf[hd->pbuf_idx] = '\0';
        printk(XENLOG_G_DEBUG "HVM%u: %s", v->domain->domain_id, hd->pbuf);
        hd->pbuf_idx = 0;
    }
    spin_unlock(&hd->pbuf_lock);
}

typedef unsigned long hvm_hypercall_t(
    unsigned long, unsigned long, unsigned long, unsigned long, unsigned long);

#define HYPERCALL(x)                                        \
    [ __HYPERVISOR_ ## x ] = (hvm_hypercall_t *) do_ ## x
#define HYPERCALL_COMPAT32(x)                               \
    [ __HYPERVISOR_ ## x ] = (hvm_hypercall_t *) do_ ## x ## _compat32

#if defined(__i386__)

static hvm_hypercall_t *hvm_hypercall_table[NR_hypercalls] = {
    HYPERCALL(memory_op),
    HYPERCALL(multicall),
    HYPERCALL(xen_version),
    HYPERCALL(event_channel_op),
    HYPERCALL(hvm_op)
};

void hvm_do_hypercall(struct cpu_user_regs *pregs)
{
    if ( unlikely(ring_3(pregs)) )
    {
        pregs->eax = -EPERM;
        return;
    }

    if ( (pregs->eax >= NR_hypercalls) || !hvm_hypercall_table[pregs->eax] )
    {
        gdprintk(XENLOG_WARNING, "HVM vcpu %d:%d did a bad hypercall %d.\n",
                current->domain->domain_id, current->vcpu_id,
                pregs->eax);
        pregs->eax = -ENOSYS;
        return;
    }

    pregs->eax = hvm_hypercall_table[pregs->eax](
        pregs->ebx, pregs->ecx, pregs->edx, pregs->esi, pregs->edi);
}

#else /* defined(__x86_64__) */

static long do_memory_op_compat32(int cmd, XEN_GUEST_HANDLE(void) arg)
{
    extern long do_add_to_physmap(struct xen_add_to_physmap *xatp);
    long rc;

    switch ( cmd )
    {
    case XENMEM_add_to_physmap:
    {
        struct {
            domid_t domid;
            uint32_t space;
            uint32_t idx;
            uint32_t gpfn;
        } u;
        struct xen_add_to_physmap h;

        if ( copy_from_guest(&u, arg, 1) )
            return -EFAULT;

        h.domid = u.domid;
        h.space = u.space;
        h.idx = u.idx;
        h.gpfn = u.gpfn;

        this_cpu(guest_handles_in_xen_space) = 1;
        rc = do_memory_op(cmd, guest_handle_from_ptr(&h, void));
        this_cpu(guest_handles_in_xen_space) = 0;

        break;
    }

    default:
        gdprintk(XENLOG_WARNING, "memory_op %d.\n", cmd);
        rc = -ENOSYS;
        break;
    }

    return rc;
}

static hvm_hypercall_t *hvm_hypercall64_table[NR_hypercalls] = {
    HYPERCALL(memory_op),
    HYPERCALL(xen_version),
    HYPERCALL(hvm_op),
    HYPERCALL(event_channel_op)
};

static hvm_hypercall_t *hvm_hypercall32_table[NR_hypercalls] = {
    HYPERCALL_COMPAT32(memory_op),
    HYPERCALL(xen_version),
    HYPERCALL(hvm_op),
    HYPERCALL(event_channel_op)
};

void hvm_do_hypercall(struct cpu_user_regs *pregs)
{
    if ( unlikely(ring_3(pregs)) )
    {
        pregs->rax = -EPERM;
        return;
    }

    pregs->rax = (uint32_t)pregs->eax; /* mask in case compat32 caller */
    if ( (pregs->rax >= NR_hypercalls) || !hvm_hypercall64_table[pregs->rax] )
    {
        gdprintk(XENLOG_WARNING, "HVM vcpu %d:%d did a bad hypercall %ld.\n",
                current->domain->domain_id, current->vcpu_id,
                pregs->rax);
        pregs->rax = -ENOSYS;
        return;
    }

    if ( current->arch.shadow.mode->guest_levels == 4 )
    {
        pregs->rax = hvm_hypercall64_table[pregs->rax](pregs->rdi,
                                                       pregs->rsi,
                                                       pregs->rdx,
                                                       pregs->r10,
                                                       pregs->r8);
    }
    else
    {
        pregs->eax = hvm_hypercall32_table[pregs->eax]((uint32_t)pregs->ebx,
                                                       (uint32_t)pregs->ecx,
                                                       (uint32_t)pregs->edx,
                                                       (uint32_t)pregs->esi,
                                                       (uint32_t)pregs->edi);
    }
}

#endif /* defined(__x86_64__) */

/* Initialise a hypercall transfer page for a VMX domain using
   paravirtualised drivers. */
void hvm_hypercall_page_initialise(struct domain *d,
                                   void *hypercall_page)
{
    hvm_funcs.init_hypercall_page(d, hypercall_page);
}


/*
 * only called in HVM domain BSP context
 * when booting, vcpuid is always equal to apic_id
 */
int hvm_bringup_ap(int vcpuid, int trampoline_vector)
{
    struct vcpu *bsp = current, *v;
    struct domain *d = bsp->domain;
    struct vcpu_guest_context *ctxt;
    int rc = 0;

    BUG_ON(!is_hvm_domain(d));

    if ( bsp->vcpu_id != 0 )
    {
        gdprintk(XENLOG_ERR, "Not calling hvm_bringup_ap from BSP context.\n");
        domain_crash(bsp->domain);
        return -EINVAL;
    }

    if ( (v = d->vcpu[vcpuid]) == NULL )
        return -ENOENT;

    if ( (ctxt = xmalloc(struct vcpu_guest_context)) == NULL )
    {
        gdprintk(XENLOG_ERR,
                "Failed to allocate memory in hvm_bringup_ap.\n");
        return -ENOMEM;
    }

    hvm_init_ap_context(ctxt, vcpuid, trampoline_vector);

    /* Sync AP's TSC with BSP's. */
    v->arch.hvm_vcpu.cache_tsc_offset =
        v->domain->vcpu[0]->arch.hvm_vcpu.cache_tsc_offset;
    hvm_funcs.set_tsc_offset(v, v->arch.hvm_vcpu.cache_tsc_offset);

    LOCK_BIGLOCK(d);
    rc = -EEXIST;
    if ( !test_bit(_VCPUF_initialised, &v->vcpu_flags) )
        rc = boot_vcpu(d, vcpuid, ctxt);
    UNLOCK_BIGLOCK(d);

    if ( rc != 0 )
    {
        gdprintk(XENLOG_ERR,
               "AP %d bringup failed in boot_vcpu %x.\n", vcpuid, rc);
        goto out;
    }

    if ( test_and_clear_bit(_VCPUF_down, &d->vcpu[vcpuid]->vcpu_flags) )
        vcpu_wake(d->vcpu[vcpuid]);
    gdprintk(XENLOG_INFO, "AP %d bringup suceeded.\n", vcpuid);

 out:
    xfree(ctxt);
    return rc;
}

static int hvmop_set_pci_intx_level(
    XEN_GUEST_HANDLE(xen_hvm_set_pci_intx_level_t) uop)
{
    struct xen_hvm_set_pci_intx_level op;
    struct domain *d;
    int rc;

    if ( copy_from_guest(&op, uop, 1) )
        return -EFAULT;

    if ( !IS_PRIV(current->domain) )
        return -EPERM;

    if ( (op.domain > 0) || (op.bus > 0) || (op.device > 31) || (op.intx > 3) )
        return -EINVAL;

    d = find_domain_by_id(op.domid);
    if ( d == NULL )
        return -ESRCH;

    rc = -EINVAL;
    if ( !is_hvm_domain(d) )
        goto out;

    rc = 0;
    switch ( op.level )
    {
    case 0:
        hvm_pci_intx_deassert(d, op.device, op.intx);
        break;
    case 1:
        hvm_pci_intx_assert(d, op.device, op.intx);
        break;
    default:
        rc = -EINVAL;
        break;
    }

 out:
    put_domain(d);
    return rc;
}

static int hvmop_set_isa_irq_level(
    XEN_GUEST_HANDLE(xen_hvm_set_isa_irq_level_t) uop)
{
    struct xen_hvm_set_isa_irq_level op;
    struct domain *d;
    int rc;

    if ( copy_from_guest(&op, uop, 1) )
        return -EFAULT;

    if ( !IS_PRIV(current->domain) )
        return -EPERM;

    if ( op.isa_irq > 15 )
        return -EINVAL;

    d = find_domain_by_id(op.domid);
    if ( d == NULL )
        return -ESRCH;

    rc = -EINVAL;
    if ( !is_hvm_domain(d) )
        goto out;

    rc = 0;
    switch ( op.level )
    {
    case 0:
        hvm_isa_irq_deassert(d, op.isa_irq);
        break;
    case 1:
        hvm_isa_irq_assert(d, op.isa_irq);
        break;
    default:
        rc = -EINVAL;
        break;
    }

 out:
    put_domain(d);
    return rc;
}

static int hvmop_set_pci_link_route(
    XEN_GUEST_HANDLE(xen_hvm_set_pci_link_route_t) uop)
{
    struct xen_hvm_set_pci_link_route op;
    struct domain *d;
    int rc;

    if ( copy_from_guest(&op, uop, 1) )
        return -EFAULT;

    if ( !IS_PRIV(current->domain) )
        return -EPERM;

    if ( (op.link > 3) || (op.isa_irq > 15) )
        return -EINVAL;

    d = find_domain_by_id(op.domid);
    if ( d == NULL )
        return -ESRCH;

    rc = -EINVAL;
    if ( !is_hvm_domain(d) )
        goto out;

    rc = 0;
    hvm_set_pci_link_route(d, op.link, op.isa_irq);

 out:
    put_domain(d);
    return rc;
}

long do_hvm_op(unsigned long op, XEN_GUEST_HANDLE(void) arg)

{
    long rc = 0;

    switch ( op )
    {
    case HVMOP_set_param:
    case HVMOP_get_param:
    {
        struct xen_hvm_param a;
        struct domain *d;
        struct vcpu *v;
        unsigned long mfn;
        void *p;

        if ( copy_from_guest(&a, arg, 1) )
            return -EFAULT;

        if ( a.index >= HVM_NR_PARAMS )
            return -EINVAL;

        if ( a.domid == DOMID_SELF )
        {
            get_knownalive_domain(current->domain);
            d = current->domain;
        }
        else if ( IS_PRIV(current->domain) )
        {
            d = find_domain_by_id(a.domid);
            if ( d == NULL )
                return -ESRCH;
        }
        else
        {
            return -EPERM;
        }

        rc = -EINVAL;
        if ( !is_hvm_domain(d) )
            goto param_fail;

        if ( op == HVMOP_set_param )
        {
            switch ( a.index )
            {
            case HVM_PARAM_IOREQ_PFN:
                if ( d->arch.hvm_domain.shared_page_va )
                    goto param_fail;
                mfn = gmfn_to_mfn(d, a.value);
                if ( mfn == INVALID_MFN )
                    goto param_fail;
                p = map_domain_page_global(mfn);
                if ( p == NULL )
                    goto param_fail;
                d->arch.hvm_domain.shared_page_va = (unsigned long)p;
                /* Initialise evtchn port info if VCPUs already created. */
                for_each_vcpu ( d, v )
                    get_vio(d, v->vcpu_id)->vp_eport =
                    v->arch.hvm_vcpu.xen_port;
                break;
            case HVM_PARAM_BUFIOREQ_PFN:
                if ( d->arch.hvm_domain.buffered_io_va )
                    goto param_fail;
                mfn = gmfn_to_mfn(d, a.value);
                if ( mfn == INVALID_MFN )
                    goto param_fail;
                p = map_domain_page_global(mfn);
                if ( p == NULL )
                    goto param_fail;
                d->arch.hvm_domain.buffered_io_va = (unsigned long)p;
                break;
            case HVM_PARAM_CALLBACK_IRQ:
                hvm_set_callback_gsi(d, a.value);
                break;
            }
            d->arch.hvm_domain.params[a.index] = a.value;
            rc = 0;
        }
        else
        {
            a.value = d->arch.hvm_domain.params[a.index];
            rc = copy_to_guest(arg, &a, 1) ? -EFAULT : 0;
        }

    param_fail:
        put_domain(d);
        break;
    }

    case HVMOP_set_pci_intx_level:
        rc = hvmop_set_pci_intx_level(
            guest_handle_cast(arg, xen_hvm_set_pci_intx_level_t));
        break;

    case HVMOP_set_isa_irq_level:
        rc = hvmop_set_isa_irq_level(
            guest_handle_cast(arg, xen_hvm_set_isa_irq_level_t));
        break;

    case HVMOP_set_pci_link_route:
        rc = hvmop_set_pci_link_route(
            guest_handle_cast(arg, xen_hvm_set_pci_link_route_t));
        break;

    default:
    {
        gdprintk(XENLOG_WARNING, "Bad HVM op %ld.\n", op);
        rc = -ENOSYS;
        break;
    }
    }

    return rc;
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */

