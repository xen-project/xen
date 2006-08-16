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
#include <asm/spinlock.h>
#include <asm/hvm/hvm.h>
#include <asm/hvm/support.h>
#include <public/sched.h>
#include <public/hvm/ioreq.h>
#include <public/version.h>
#include <public/memory.h>

int hvm_enabled = 0;

unsigned int opt_hvm_debug_level = 0;
integer_param("hvm_debug", opt_hvm_debug_level);

struct hvm_function_table hvm_funcs;

static void hvm_zap_mmio_range(
    struct domain *d, unsigned long pfn, unsigned long nr_pfn)
{
    unsigned long i;

    ASSERT(d == current->domain);

    for ( i = 0; i < nr_pfn; i++ )
    {
        if ( pfn + i >= 0xfffff )
            break;

        if ( VALID_MFN(gmfn_to_mfn(d, pfn + i)) )
            guest_remove_page(d, pfn + i);
    }
}

static void e820_zap_iommu_callback(struct domain *d,
                                    struct e820entry *e,
                                    void *ign)
{
    if ( e->type == E820_IO )
        hvm_zap_mmio_range(d, e->addr >> PAGE_SHIFT, e->size >> PAGE_SHIFT);
}

static void e820_foreach(struct domain *d,
                         void (*cb)(struct domain *d,
                                    struct e820entry *e,
                                    void *data),
                         void *data)
{
    int i;
    unsigned char e820_map_nr;
    struct e820entry *e820entry;
    unsigned char *p;
    unsigned long mfn;

    mfn = gmfn_to_mfn(d, E820_MAP_PAGE >> PAGE_SHIFT);
    if ( mfn == INVALID_MFN )
    {
        printk("Can not find E820 memory map page for HVM domain.\n");
        domain_crash_synchronous();
    }

    p = map_domain_page(mfn);
    if ( p == NULL )
    {
        printk("Can not map E820 memory map page for HVM domain.\n");
        domain_crash_synchronous();
    }

    e820_map_nr = *(p + E820_MAP_NR_OFFSET);
    e820entry = (struct e820entry *)(p + E820_MAP_OFFSET);

    for ( i = 0; i < e820_map_nr; i++ )
        cb(d, e820entry + i, data);

    unmap_domain_page(p);
}

static void hvm_zap_iommu_pages(struct domain *d)
{
    e820_foreach(d, e820_zap_iommu_callback, NULL);
}

static void e820_map_io_shared_callback(struct domain *d,
                                        struct e820entry *e,
                                        void *data)
{
    unsigned long *mfn = data;
    if ( e->type == E820_SHARED_PAGE )
    {
        ASSERT(*mfn == INVALID_MFN);
        *mfn = gmfn_to_mfn(d, e->addr >> PAGE_SHIFT);
    }
}

static void e820_map_buffered_io_callback(struct domain *d,
                                          struct e820entry *e,
                                          void *data)
{
    unsigned long *mfn = data;
    if ( e->type == E820_BUFFERED_IO ) {
        ASSERT(*mfn == INVALID_MFN);
        *mfn = gmfn_to_mfn(d, e->addr >> PAGE_SHIFT);
    }
}

void hvm_map_io_shared_pages(struct vcpu *v)
{
    unsigned long mfn;
    void *p;
    struct domain *d = v->domain;

    if ( d->arch.hvm_domain.shared_page_va ||
         d->arch.hvm_domain.buffered_io_va )
        return;

    mfn = INVALID_MFN;
    e820_foreach(d, e820_map_io_shared_callback, &mfn);

    if ( mfn == INVALID_MFN )
    {
        printk("Can not find io request shared page for HVM domain.\n");
        domain_crash_synchronous();
    }

    p = map_domain_page_global(mfn);
    if ( p == NULL )
    {
        printk("Can not map io request shared page for HVM domain.\n");
        domain_crash_synchronous();
    }

    d->arch.hvm_domain.shared_page_va = (unsigned long)p;

    mfn = INVALID_MFN;
    e820_foreach(d, e820_map_buffered_io_callback, &mfn);
    if ( mfn != INVALID_MFN ) {
        p = map_domain_page_global(mfn);
        if ( p )
            d->arch.hvm_domain.buffered_io_va = (unsigned long)p;
    }
}

void hvm_create_event_channels(struct vcpu *v)
{
    vcpu_iodata_t *p;
    struct vcpu *o;

    if ( v->vcpu_id == 0 ) {
        /* Ugly: create event channels for every vcpu when vcpu 0
           starts, so that they're available for ioemu to bind to. */
        for_each_vcpu(v->domain, o) {
            p = get_vio(v->domain, o->vcpu_id);
            o->arch.hvm_vcpu.xen_port = p->vp_eport =
                alloc_unbound_xen_event_channel(o, 0);
            DPRINTK("Allocated port %d for hvm.\n", o->arch.hvm_vcpu.xen_port);
        }
    }
}


void hvm_stts(struct vcpu *v)
{
    /* FPU state already dirty? Then no need to setup_fpu() lazily. */
    if ( test_bit(_VCPUF_fpu_dirtied, &v->vcpu_flags) )
        return;
    
    hvm_funcs.stts(v);
}

void hvm_set_guest_time(struct vcpu *v, u64 gtime)
{
    u64 host_tsc;
   
    rdtscll(host_tsc);
    
    v->arch.hvm_vcpu.cache_tsc_offset = gtime - host_tsc;
    hvm_funcs.set_tsc_offset(v, v->arch.hvm_vcpu.cache_tsc_offset);
}

void hvm_do_resume(struct vcpu *v)
{
    ioreq_t *p;
    struct periodic_time *pt =
        &v->domain->arch.hvm_domain.pl_time.periodic_tm;

    hvm_stts(v);

    /* pick up the elapsed PIT ticks and re-enable pit_timer */
    if ( pt->enabled && pt->first_injected ) {
        if ( v->arch.hvm_vcpu.guest_time ) {
            hvm_set_guest_time(v, v->arch.hvm_vcpu.guest_time);
            v->arch.hvm_vcpu.guest_time = 0;
        }
        pickup_deactive_ticks(pt);
    }

    p = &get_vio(v->domain, v->vcpu_id)->vp_ioreq;
    wait_on_xen_event_channel(v->arch.hvm.xen_port,
                              p->state != STATE_IOREQ_READY &&
                              p->state != STATE_IOREQ_INPROCESS);
    if ( p->state == STATE_IORESP_READY )
        hvm_io_assist(v);
    if ( p->state != STATE_INVALID ) {
        printf("Weird HVM iorequest state %d.\n", p->state);
        domain_crash(v->domain);
    }
}

void hvm_release_assist_channel(struct vcpu *v)
{
    free_xen_event_channel(v, v->arch.hvm_vcpu.xen_port);
}


void hvm_setup_platform(struct domain* d)
{
    struct hvm_domain *platform;
    struct vcpu *v=current;

    if ( !hvm_guest(v) || (v->vcpu_id != 0) )
        return;

#if 0 /* SHADOW2 does not have this */
    if ( shadow_direct_map_init(d) == 0 )
    {
        printk("Can not allocate shadow direct map for HVM domain.\n");
        domain_crash_synchronous();
    }
#endif

    hvm_zap_iommu_pages(d);

    platform = &d->arch.hvm_domain;
    pic_init(&platform->vpic, pic_irq_request, &platform->interrupt_request);
    register_pic_io_hook();

    if ( hvm_apic_support(d) )
    {
        spin_lock_init(&d->arch.hvm_domain.round_robin_lock);
        hvm_vioapic_init(d);
    }

    spin_lock_init(&d->arch.hvm_domain.buffered_io_lock);

    init_timer(&platform->pl_time.periodic_tm.timer,
               pt_timer_fn, v, v->processor);
    pit_init(v, cpu_khz);
}

void pic_irq_request(void *data, int level)
{
    int *interrupt_request = data;
    *interrupt_request = level;
}

void hvm_pic_assist(struct vcpu *v)
{
    global_iodata_t *spg;
    u16   *virq_line, irqs;
    struct hvm_virpic *pic = &v->domain->arch.hvm_domain.vpic;

    spg = &get_sp(v->domain)->sp_global;
    virq_line  = &spg->pic_clear_irr;
    if ( *virq_line ) {
        do {
            irqs = *(volatile u16*)virq_line;
        } while ( (u16)cmpxchg(virq_line,irqs, 0) != irqs );
        do_pic_irqs_clear(pic, irqs);
    }
    virq_line  = &spg->pic_irr;
    if ( *virq_line ) {
        do {
            irqs = *(volatile u16*)virq_line;
        } while ( (u16)cmpxchg(virq_line,irqs, 0) != irqs );
        do_pic_irqs(pic, irqs);
    }
}

u64 hvm_get_guest_time(struct vcpu *v)
{
    u64    host_tsc;
    
    rdtscll(host_tsc);
    return host_tsc + v->arch.hvm_vcpu.cache_tsc_offset;
}

int cpu_get_interrupt(struct vcpu *v, int *type)
{
    int intno;
    struct hvm_virpic *s = &v->domain->arch.hvm_domain.vpic;
    unsigned long flags;

    if ( (intno = cpu_get_apic_interrupt(v, type)) != -1 ) {
        /* set irq request if a PIC irq is still pending */
        /* XXX: improve that */
        spin_lock_irqsave(&s->lock, flags);
        pic_update_irq(s);
        spin_unlock_irqrestore(&s->lock, flags);
        return intno;
    }
    /* read the irq from the PIC */
    if ( v->vcpu_id == 0 && (intno = cpu_get_pic_interrupt(v, type)) != -1 )
        return intno;

    return -1;
}

void hvm_hlt(unsigned long rflags)
{
    struct vcpu *v = current;
    struct periodic_time *pt = &v->domain->arch.hvm_domain.pl_time.periodic_tm;
    s_time_t next_pit = -1, next_wakeup;

    /*
     * Detect machine shutdown.  Only do this for vcpu 0, to avoid potentially 
     * shutting down the domain early. If we halt with interrupts disabled, 
     * that's a pretty sure sign that we want to shut down.  In a real 
     * processor, NMIs are the only way to break out of this.
     */
    if ( (v->vcpu_id == 0) && !(rflags & X86_EFLAGS_IF) )
    {
        printk("D%d: HLT with interrupts enabled -- shutting down.\n",
               current->domain->domain_id);
        domain_shutdown(current->domain, SHUTDOWN_poweroff);
        return;
    }

    if ( !v->vcpu_id )
        next_pit = get_scheduled(v, pt->irq, pt);
    next_wakeup = get_apictime_scheduled(v);
    if ( (next_pit != -1 && next_pit < next_wakeup) || next_wakeup == -1 )
        next_wakeup = next_pit;
    if ( next_wakeup != - 1 ) 
        set_timer(&current->arch.hvm_vcpu.hlt_timer, next_wakeup);
    do_sched_op_compat(SCHEDOP_block, 0);
}

/*
 * Copy from/to guest virtual.
 */
int hvm_copy(void *buf, unsigned long vaddr, int size, int dir)
{
    struct vcpu *v = current;
    unsigned long gfn;
    unsigned long mfn;
    char *addr;
    int count;

    while (size > 0) {
        count = PAGE_SIZE - (vaddr & ~PAGE_MASK);
        if (count > size)
            count = size;

        gfn = shadow2_gva_to_gfn(v, vaddr);
        mfn = mfn_x(sh2_vcpu_gfn_to_mfn(v, gfn));

        if (mfn == INVALID_MFN)
            return 0;

        addr = (char *)map_domain_page(mfn) + (vaddr & ~PAGE_MASK);

        if (dir == HVM_COPY_IN)
            memcpy(buf, addr, count);
        else
            memcpy(addr, buf, count);

        unmap_domain_page(addr);

        vaddr += count;
        buf += count;
        size -= count;
    }

    return 1;
}

/*
 * HVM specific printbuf. Mostly used for hvmloader chit-chat.
 */
void hvm_print_line(struct vcpu *v, const char c)
{
    int *index = &v->domain->arch.hvm_domain.pbuf_index;
    char *pbuf = v->domain->arch.hvm_domain.pbuf;

    if (*index == HVM_PBUF_SIZE-2 || c == '\n') {
        if (*index == HVM_PBUF_SIZE-2)
	    pbuf[(*index)++] = c;
        pbuf[*index] = '\0';
        printk("(GUEST: %u) %s\n", v->domain->domain_id, pbuf);
	*index = 0;
    } else
	pbuf[(*index)++] = c;
}

typedef unsigned long hvm_hypercall_t(
    unsigned long, unsigned long, unsigned long, unsigned long, unsigned long);

#define HYPERCALL(x)                                        \
    [ __HYPERVISOR_ ## x ] = (hvm_hypercall_t *) do_ ## x
#define HYPERCALL_COMPAT32(x)                               \
    [ __HYPERVISOR_ ## x ] = (hvm_hypercall_t *) do_ ## x ## _compat32

#if defined(__i386__)

static hvm_hypercall_t *hvm_hypercall_table[] = {
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
        DPRINTK("HVM vcpu %d:%d did a bad hypercall %d.\n",
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
        DPRINTK("memory_op %d.\n", cmd);
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
        DPRINTK("HVM vcpu %d:%d did a bad hypercall %ld.\n",
                current->domain->domain_id, current->vcpu_id,
                pregs->rax);
        pregs->rax = -ENOSYS;
        return;
    }

    if ( current->arch.shadow2->guest_levels == 4 )
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

    /* current must be HVM domain BSP */
    if ( !(hvm_guest(bsp) && bsp->vcpu_id == 0) ) {
        printk("Not calling hvm_bringup_ap from BSP context.\n");
        domain_crash_synchronous();
    }

    if ( (v = d->vcpu[vcpuid]) == NULL )
        return -ENOENT;

    if ( (ctxt = xmalloc(struct vcpu_guest_context)) == NULL ) {
        printk("Failed to allocate memory in hvm_bringup_ap.\n");
        return -ENOMEM;
    }

    hvm_init_ap_context(ctxt, vcpuid, trampoline_vector);

    LOCK_BIGLOCK(d);
    rc = -EEXIST;
    if ( !test_bit(_VCPUF_initialised, &v->vcpu_flags) )
        rc = boot_vcpu(d, vcpuid, ctxt);
    UNLOCK_BIGLOCK(d);

    if ( rc != 0 )
        printk("AP %d bringup failed in boot_vcpu %x.\n", vcpuid, rc);
    else {
        if ( test_and_clear_bit(_VCPUF_down, &d->vcpu[vcpuid]->vcpu_flags) )
            vcpu_wake(d->vcpu[vcpuid]);
        printk("AP %d bringup suceeded.\n", vcpuid);
    }

    xfree(ctxt);

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

        if ( op == HVMOP_set_param )
        {
            d->arch.hvm_domain.params[a.index] = a.value;
            rc = 0;
        }
        else
        {
            a.value = d->arch.hvm_domain.params[a.index];
            rc = copy_to_guest(arg, &a, 1) ? -EFAULT : 0;
        }

        put_domain(d);
        break;
    }

    default:
    {
        DPRINTK("Bad HVM op %ld.\n", op);
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

