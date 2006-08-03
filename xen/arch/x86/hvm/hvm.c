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
#include <asm/current.h>
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
#include <asm/shadow.h>
#if CONFIG_PAGING_LEVELS >= 3
#include <asm/shadow_64.h>
#endif
#include <public/sched.h>
#include <public/hvm/ioreq.h>
#include <public/hvm/hvm_info_table.h>
#include <xen/guest_access.h>

int hvm_enabled = 0;

unsigned int opt_hvm_debug_level = 0;
integer_param("hvm_debug", opt_hvm_debug_level);

struct hvm_function_table hvm_funcs;

static void hvm_zap_mmio_range(
    struct domain *d, unsigned long pfn, unsigned long nr_pfn)
{
    unsigned long i, val = INVALID_MFN;

    for ( i = 0; i < nr_pfn; i++ )
    {
        if ( pfn + i >= 0xfffff )
            break;

        __copy_to_user(&phys_to_machine_mapping[pfn + i], &val, sizeof (val));
    }
}

static void hvm_map_io_shared_page(struct domain *d)
{
    int i;
    unsigned char e820_map_nr;
    struct e820entry *e820entry;
    unsigned char *p;
    unsigned long mfn;
    unsigned long gpfn = 0;

    local_flush_tlb_pge();

    mfn = get_mfn_from_gpfn(E820_MAP_PAGE >> PAGE_SHIFT);
    if (mfn == INVALID_MFN) {
        printk("Can not find E820 memory map page for HVM domain.\n");
        domain_crash_synchronous();
    }

    p = map_domain_page(mfn);
    if (p == NULL) {
        printk("Can not map E820 memory map page for HVM domain.\n");
        domain_crash_synchronous();
    }

    e820_map_nr = *(p + E820_MAP_NR_OFFSET);
    e820entry = (struct e820entry *)(p + E820_MAP_OFFSET);

    for ( i = 0; i < e820_map_nr; i++ )
    {
        if ( e820entry[i].type == E820_SHARED_PAGE )
            gpfn = (e820entry[i].addr >> PAGE_SHIFT);
        if ( e820entry[i].type == E820_IO )
            hvm_zap_mmio_range(
                d, 
                e820entry[i].addr >> PAGE_SHIFT,
                e820entry[i].size >> PAGE_SHIFT);
    }

    if ( gpfn == 0 ) {
        printk("Can not get io request shared page"
               " from E820 memory map for HVM domain.\n");
        unmap_domain_page(p);
        domain_crash_synchronous();
    }
    unmap_domain_page(p);

    /* Initialise shared page */
    mfn = get_mfn_from_gpfn(gpfn);
    if (mfn == INVALID_MFN) {
        printk("Can not find io request shared page for HVM domain.\n");
        domain_crash_synchronous();
    }

    p = map_domain_page_global(mfn);
    if (p == NULL) {
        printk("Can not map io request shared page for HVM domain.\n");
        domain_crash_synchronous();
    }
    d->arch.hvm_domain.shared_page_va = (unsigned long)p;
}

void hvm_setup_platform(struct domain* d)
{
    struct hvm_domain *platform;
    struct vcpu *v=current;

    if ( !hvm_guest(v) || (v->vcpu_id != 0) )
        return;

    if ( shadow_direct_map_init(d) == 0 )
    {
        printk("Can not allocate shadow direct map for HVM domain.\n");
        domain_crash_synchronous();
    }

    hvm_map_io_shared_page(d);

    platform = &d->arch.hvm_domain;
    pic_init(&platform->vpic, pic_irq_request, &platform->interrupt_request);
    register_pic_io_hook();

    if ( hvm_apic_support(d) )
    {
        spin_lock_init(&d->arch.hvm_domain.round_robin_lock);
        hvm_vioapic_init(d);
    }

    init_timer(&platform->pl_time.periodic_tm.timer, pt_timer_fn, v, v->processor);
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

/*
 * Copy from/to guest virtual.
 */
int
hvm_copy(void *buf, unsigned long vaddr, int size, int dir)
{
    unsigned long gpa, mfn;
    char *addr;
    int count;

    while (size > 0) {
        count = PAGE_SIZE - (vaddr & ~PAGE_MASK);
        if (count > size)
            count = size;

        if (hvm_paging_enabled(current)) {
            gpa = gva_to_gpa(vaddr);
            mfn = get_mfn_from_gpfn(gpa >> PAGE_SHIFT);
        } else
            mfn = get_mfn_from_gpfn(vaddr >> PAGE_SHIFT);
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

#if defined(__i386__)

typedef unsigned long hvm_hypercall_t(
    unsigned long, unsigned long, unsigned long, unsigned long, unsigned long);
#define HYPERCALL(x) [ __HYPERVISOR_ ## x ] = (hvm_hypercall_t *) do_ ## x
static hvm_hypercall_t *hvm_hypercall_table[] = {
    HYPERCALL(mmu_update),
    HYPERCALL(memory_op),
    HYPERCALL(multicall),
    HYPERCALL(update_va_mapping),
    HYPERCALL(event_channel_op_compat),
    HYPERCALL(xen_version),
    HYPERCALL(grant_table_op),
    HYPERCALL(event_channel_op),
    HYPERCALL(hvm_op)
};
#undef HYPERCALL

void hvm_do_hypercall(struct cpu_user_regs *pregs)
{
    if ( ring_3(pregs) )
    {
        pregs->eax = -EPERM;
        return;
    }

    if ( pregs->eax > ARRAY_SIZE(hvm_hypercall_table) ||
         !hvm_hypercall_table[pregs->eax] )
    {
        DPRINTK("HVM vcpu %d:%d did a bad hypercall %d.\n",
                current->domain->domain_id, current->vcpu_id,
                pregs->eax);
        pregs->eax = -ENOSYS;
    }
    else
    {
        pregs->eax = hvm_hypercall_table[pregs->eax](
            pregs->ebx, pregs->ecx, pregs->edx, pregs->esi, pregs->edi);
    }
}

#else /* __x86_64__ */

void hvm_do_hypercall(struct cpu_user_regs *pregs)
{
    printk("not supported yet!\n");
}

#endif

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
            if ( !d )
                return -ESRCH;
        }
        else
        {
            return -EPERM;
        }

        if ( op == HVMOP_set_param )
        {
            rc = 0;
            d->arch.hvm_domain.params[a.index] = a.value;
        }
        else
        {
            rc = d->arch.hvm_domain.params[a.index];
        }

        put_domain(d);
        return rc;
    }

    default:
    {
        DPRINTK("Bad HVM op %ld.\n", op);
        rc = -ENOSYS;
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

