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
#include <asm/current.h>
#include <asm/e820.h>
#include <asm/io.h>
#include <asm/paging.h>
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

int hvm_enabled __read_mostly;

unsigned int opt_hvm_debug_level __read_mostly;
integer_param("hvm_debug", opt_hvm_debug_level);

struct hvm_function_table hvm_funcs __read_mostly;

/* I/O permission bitmap is globally shared by all HVM guests. */
char __attribute__ ((__section__ (".bss.page_aligned")))
    hvm_io_bitmap[3*PAGE_SIZE];

void hvm_enable(struct hvm_function_table *fns)
{
    BUG_ON(hvm_enabled);
    printk("HVM: %s enabled\n", fns->name);

    /*
     * Allow direct access to the PC debug port (it is often used for I/O
     * delays, but the vmexits simply slow things down).
     */
    memset(hvm_io_bitmap, ~0, sizeof(hvm_io_bitmap));
    clear_bit(0x80, hvm_io_bitmap);

    hvm_funcs   = *fns;
    hvm_enabled = 1;
}

void hvm_disable(void)
{
    if ( hvm_enabled )
        hvm_funcs.disable();
}

void hvm_stts(struct vcpu *v)
{
    /* FPU state already dirty? Then no need to setup_fpu() lazily. */
    if ( !v->fpu_dirtied )
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
    u64 host_tsc;

    rdtscll(host_tsc);
    return host_tsc + v->arch.hvm_vcpu.cache_tsc_offset;
}

void hvm_migrate_timers(struct vcpu *v)
{
    pit_migrate_timers(v);
    rtc_migrate_timers(v);
    hpet_migrate_timers(v);
    if ( vcpu_vlapic(v)->pt.enabled )
        migrate_timer(&vcpu_vlapic(v)->pt.timer, v->processor);
}

void hvm_do_resume(struct vcpu *v)
{
    ioreq_t *p;

    hvm_stts(v);

    pt_thaw_time(v);

    /* NB. Optimised for common case (p->state == STATE_IOREQ_NONE). */
    p = &get_ioreq(v)->vp_ioreq;
    while ( p->state != STATE_IOREQ_NONE )
    {
        switch ( p->state )
        {
        case STATE_IORESP_READY: /* IORESP_READY -> NONE */
            hvm_io_assist();
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

static void hvm_init_ioreq_page(
    struct domain *d, struct hvm_ioreq_page *iorp)
{
    memset(iorp, 0, sizeof(*iorp));
    spin_lock_init(&iorp->lock);
    domain_pause(d);
}

static void hvm_destroy_ioreq_page(
    struct domain *d, struct hvm_ioreq_page *iorp)
{
    spin_lock(&iorp->lock);

    ASSERT(d->is_dying);

    if ( iorp->va != NULL )
    {
        unmap_domain_page_global(iorp->va);
        put_page_and_type(iorp->page);
        iorp->va = NULL;
    }

    spin_unlock(&iorp->lock);
}

static int hvm_set_ioreq_page(
    struct domain *d, struct hvm_ioreq_page *iorp, unsigned long gmfn)
{
    struct page_info *page;
    unsigned long mfn;
    void *va;

    mfn = gmfn_to_mfn(d, gmfn);
    if ( !mfn_valid(mfn) )
        return -EINVAL;

    page = mfn_to_page(mfn);
    if ( !get_page_and_type(page, d, PGT_writable_page) )
        return -EINVAL;

    va = map_domain_page_global(mfn);
    if ( va == NULL )
    {
        put_page_and_type(page);
        return -ENOMEM;
    }

    spin_lock(&iorp->lock);

    if ( (iorp->va != NULL) || d->is_dying )
    {
        spin_unlock(&iorp->lock);
        unmap_domain_page_global(va);
        put_page_and_type(mfn_to_page(mfn));
        return -EINVAL;
    }

    iorp->va = va;
    iorp->page = page;

    spin_unlock(&iorp->lock);

    domain_unpause(d);

    return 0;
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
    spin_lock_init(&d->arch.hvm_domain.irq_lock);

    rc = paging_enable(d, PG_refcounts|PG_translate|PG_external);
    if ( rc != 0 )
        return rc;

    vpic_init(d);
    vioapic_init(d);

    hvm_init_ioreq_page(d, &d->arch.hvm_domain.ioreq);
    hvm_init_ioreq_page(d, &d->arch.hvm_domain.buf_ioreq);

    return 0;
}

void hvm_domain_relinquish_resources(struct domain *d)
{
    hvm_destroy_ioreq_page(d, &d->arch.hvm_domain.ioreq);
    hvm_destroy_ioreq_page(d, &d->arch.hvm_domain.buf_ioreq);
}

void hvm_domain_destroy(struct domain *d)
{
    pit_deinit(d);
    rtc_deinit(d);
    pmtimer_deinit(d);
    hpet_deinit(d);
}

static int hvm_save_cpu_ctxt(struct domain *d, hvm_domain_context_t *h)
{
    struct vcpu *v;
    struct hvm_hw_cpu ctxt;
    struct vcpu_guest_context *vc;

    for_each_vcpu(d, v)
    {
        /* We don't need to save state for a vcpu that is down; the restore 
         * code will leave it down if there is nothing saved. */
        if ( test_bit(_VPF_down, &v->pause_flags) ) 
            continue;

        /* Architecture-specific vmcs/vmcb bits */
        hvm_funcs.save_cpu_ctxt(v, &ctxt);

        /* Other vcpu register state */
        vc = &v->arch.guest_context;
        if ( vc->flags & VGCF_i387_valid )
            memcpy(ctxt.fpu_regs, &vc->fpu_ctxt, sizeof(ctxt.fpu_regs));
        else 
            memset(ctxt.fpu_regs, 0, sizeof(ctxt.fpu_regs));
        ctxt.rax = vc->user_regs.eax;
        ctxt.rbx = vc->user_regs.ebx;
        ctxt.rcx = vc->user_regs.ecx;
        ctxt.rdx = vc->user_regs.edx;
        ctxt.rbp = vc->user_regs.ebp;
        ctxt.rsi = vc->user_regs.esi;
        ctxt.rdi = vc->user_regs.edi;
        /* %rsp handled by arch-specific call above */
#ifdef __x86_64__        
        ctxt.r8  = vc->user_regs.r8;
        ctxt.r9  = vc->user_regs.r9;
        ctxt.r10 = vc->user_regs.r10;
        ctxt.r11 = vc->user_regs.r11;
        ctxt.r12 = vc->user_regs.r12;
        ctxt.r13 = vc->user_regs.r13;
        ctxt.r14 = vc->user_regs.r14;
        ctxt.r15 = vc->user_regs.r15;
#endif
        ctxt.dr0 = vc->debugreg[0];
        ctxt.dr1 = vc->debugreg[1];
        ctxt.dr2 = vc->debugreg[2];
        ctxt.dr3 = vc->debugreg[3];
        ctxt.dr6 = vc->debugreg[6];
        ctxt.dr7 = vc->debugreg[7];

        if ( hvm_save_entry(CPU, v->vcpu_id, h, &ctxt) != 0 )
            return 1; 
    }
    return 0;
}

static int hvm_load_cpu_ctxt(struct domain *d, hvm_domain_context_t *h)
{
    int vcpuid, rc;
    struct vcpu *v;
    struct hvm_hw_cpu ctxt;
    struct vcpu_guest_context *vc;

    /* Which vcpu is this? */
    vcpuid = hvm_load_instance(h);
    if ( vcpuid > MAX_VIRT_CPUS || (v = d->vcpu[vcpuid]) == NULL ) 
    {
        gdprintk(XENLOG_ERR, "HVM restore: domain has no vcpu %u\n", vcpuid);
        return -EINVAL;
    }
    vc = &v->arch.guest_context;

    /* Need to init this vcpu before loading its contents */
    LOCK_BIGLOCK(d);
    if ( !v->is_initialised )
        if ( (rc = boot_vcpu(d, vcpuid, vc)) != 0 )
            return rc;
    UNLOCK_BIGLOCK(d);

    if ( hvm_load_entry(CPU, h, &ctxt) != 0 ) 
        return -EINVAL;

    /* Architecture-specific vmcs/vmcb bits */
    if ( hvm_funcs.load_cpu_ctxt(v, &ctxt) < 0 )
        return -EINVAL;

    /* Other vcpu register state */
    memcpy(&vc->fpu_ctxt, ctxt.fpu_regs, sizeof(ctxt.fpu_regs));
    vc->user_regs.eax = ctxt.rax;
    vc->user_regs.ebx = ctxt.rbx;
    vc->user_regs.ecx = ctxt.rcx;
    vc->user_regs.edx = ctxt.rdx;
    vc->user_regs.ebp = ctxt.rbp;
    vc->user_regs.esi = ctxt.rsi;
    vc->user_regs.edi = ctxt.rdi;
    vc->user_regs.esp = ctxt.rsp;
#ifdef __x86_64__
    vc->user_regs.r8  = ctxt.r8; 
    vc->user_regs.r9  = ctxt.r9; 
    vc->user_regs.r10 = ctxt.r10;
    vc->user_regs.r11 = ctxt.r11;
    vc->user_regs.r12 = ctxt.r12;
    vc->user_regs.r13 = ctxt.r13;
    vc->user_regs.r14 = ctxt.r14;
    vc->user_regs.r15 = ctxt.r15;
#endif
    vc->debugreg[0] = ctxt.dr0;
    vc->debugreg[1] = ctxt.dr1;
    vc->debugreg[2] = ctxt.dr2;
    vc->debugreg[3] = ctxt.dr3;
    vc->debugreg[6] = ctxt.dr6;
    vc->debugreg[7] = ctxt.dr7;

    vc->flags = VGCF_i387_valid | VGCF_online;
    v->fpu_initialised = 1;

    /* Auxiliary processors should be woken immediately. */
    if ( test_and_clear_bit(_VPF_down, &v->pause_flags) )
        vcpu_wake(v);

    return 0;
}

HVM_REGISTER_SAVE_RESTORE(CPU, hvm_save_cpu_ctxt, hvm_load_cpu_ctxt,
                          1, HVMSR_PER_VCPU);

int hvm_vcpu_initialise(struct vcpu *v)
{
    int rc;

    if ( (rc = vlapic_init(v)) != 0 )
        return rc;

    if ( (rc = hvm_funcs.vcpu_initialise(v)) != 0 )
    {
        vlapic_destroy(v);
        return rc;
    }

    /* Create ioreq event channel. */
    rc = alloc_unbound_xen_event_channel(v, 0);
    if ( rc < 0 )
    {
        hvm_funcs.vcpu_destroy(v);
        vlapic_destroy(v);
        return rc;
    }

    /* Register ioreq event channel. */
    v->arch.hvm_vcpu.xen_port = rc;
    spin_lock(&v->domain->arch.hvm_domain.ioreq.lock);
    if ( v->domain->arch.hvm_domain.ioreq.va != NULL )
        get_ioreq(v)->vp_eport = v->arch.hvm_vcpu.xen_port;
    spin_unlock(&v->domain->arch.hvm_domain.ioreq.lock);

    INIT_LIST_HEAD(&v->arch.hvm_vcpu.tm_list);

    if ( v->vcpu_id != 0 )
        return 0;

    pit_init(v, cpu_khz);
    rtc_init(v, RTC_PORT(0));
    pmtimer_init(v);
    hpet_init(v);
 
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


void hvm_vcpu_reset(struct vcpu *v)
{
    vcpu_pause(v);

    vlapic_reset(vcpu_vlapic(v));

    hvm_funcs.vcpu_initialise(v);

    set_bit(_VPF_down, &v->pause_flags);
    clear_bit(_VPF_blocked, &v->pause_flags);
    v->fpu_initialised = 0;
    v->fpu_dirtied     = 0;
    v->is_initialised  = 0;

    vcpu_unpause(v);
}

static void hvm_vcpu_down(void)
{
    struct vcpu *v = current;
    struct domain *d = v->domain;
    int online_count = 0;

    gdprintk(XENLOG_INFO, "DOM%d/VCPU%d: going offline.\n",
           d->domain_id, v->vcpu_id);

    /* Doesn't halt us immediately, but we'll never return to guest context. */
    set_bit(_VPF_down, &v->pause_flags);
    vcpu_sleep_nosync(v);

    /* Any other VCPUs online? ... */
    LOCK_BIGLOCK(d);
    for_each_vcpu ( d, v )
        if ( !test_bit(_VPF_down, &v->pause_flags) )
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

    if ( unlikely(!vcpu_start_shutdown_deferral(v)) )
        return; /* implicitly bins the i/o operation */

    p = &get_ioreq(v)->vp_ioreq;
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

void hvm_triple_fault(void)
{
    struct vcpu *v = current;
    gdprintk(XENLOG_INFO, "Triple fault on VCPU%d - "
             "invoking HVM system reset.\n", v->vcpu_id);
    domain_shutdown(v->domain, SHUTDOWN_reboot);
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
    unsigned long gfn, mfn;
    char *p;
    int count, todo;

    todo = size;
    while ( todo > 0 )
    {
        count = min_t(int, PAGE_SIZE - (addr & ~PAGE_MASK), todo);

        if ( virt )
            gfn = paging_gva_to_gfn(current, addr);
        else
            gfn = addr >> PAGE_SHIFT;
        
        mfn = get_mfn_from_gpfn(gfn);

        if ( mfn == INVALID_MFN )
            return todo;

        p = (char *)map_domain_page(mfn) + (addr & ~PAGE_MASK);

        if ( dir )
        {
            memcpy(p, buf, count); /* dir == TRUE:  *to* guest */
            mark_dirty(current->domain, mfn);
        }
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

void hvm_cpuid(unsigned int input, unsigned int *eax, unsigned int *ebx,
                                   unsigned int *ecx, unsigned int *edx)
{
    if ( !cpuid_hypervisor_leaves(input, eax, ebx, ecx, edx) )
    {
        cpuid(input, eax, ebx, ecx, edx);

        if ( input == 0x00000001 )
        {
            struct vcpu *v = current;

            clear_bit(X86_FEATURE_MWAIT & 31, ecx);

            if ( vlapic_hw_disabled(vcpu_vlapic(v)) )
                clear_bit(X86_FEATURE_APIC & 31, edx);

#if CONFIG_PAGING_LEVELS >= 3
            if ( !v->domain->arch.hvm_domain.params[HVM_PARAM_PAE_ENABLED] )
#endif
                clear_bit(X86_FEATURE_PAE & 31, edx);
            clear_bit(X86_FEATURE_PSE36 & 31, edx);
        }
        else if ( input == 0x80000001 )
        {
#if CONFIG_PAGING_LEVELS >= 3
            struct vcpu *v = current;
            if ( !v->domain->arch.hvm_domain.params[HVM_PARAM_PAE_ENABLED] )
#endif
                clear_bit(X86_FEATURE_NX & 31, edx);
#ifdef __i386__
            /* Mask feature for Intel ia32e or AMD long mode. */
            clear_bit(X86_FEATURE_LAHF_LM & 31, ecx);

            clear_bit(X86_FEATURE_LM & 31, edx);
            clear_bit(X86_FEATURE_SYSCALL & 31, edx);
#endif
        }
    }
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
    HYPERCALL(sched_op),
    HYPERCALL(hvm_op)
};

static void __hvm_do_hypercall(struct cpu_user_regs *pregs)
{
    if ( (pregs->eax >= NR_hypercalls) || !hvm_hypercall_table[pregs->eax] )
    {
        if ( pregs->eax != __HYPERVISOR_grant_table_op )
            gdprintk(XENLOG_WARNING, "HVM vcpu %d:%d bad hypercall %d.\n",
                     current->domain->domain_id, current->vcpu_id, pregs->eax);
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

static void __hvm_do_hypercall(struct cpu_user_regs *pregs)
{
    pregs->rax = (uint32_t)pregs->eax; /* mask in case compat32 caller */
    if ( (pregs->rax >= NR_hypercalls) || !hvm_hypercall64_table[pregs->rax] )
    {
        if ( pregs->rax != __HYPERVISOR_grant_table_op )
            gdprintk(XENLOG_WARNING, "HVM vcpu %d:%d bad hypercall %ld.\n",
                     current->domain->domain_id, current->vcpu_id, pregs->rax);
        pregs->rax = -ENOSYS;
        return;
    }

    if ( current->arch.paging.mode->guest_levels == 4 )
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

int hvm_do_hypercall(struct cpu_user_regs *pregs)
{
    int flush, preempted;
    unsigned long old_eip;

    if ( unlikely(ring_3(pregs)) )
    {
        pregs->eax = -EPERM;
        return 0;
    }

    /*
     * NB. In future flush only on decrease_reservation.
     * For now we also need to flush when pages are added, as qemu-dm is not
     * yet capable of faulting pages into an existing valid mapcache bucket.
     */
    flush = ((uint32_t)pregs->eax == __HYPERVISOR_memory_op);

    /* Check for preemption: RIP will be modified from this dummy value. */
    old_eip = pregs->eip;
    pregs->eip = 0xF0F0F0FF;

    __hvm_do_hypercall(pregs);

    preempted = (pregs->eip != 0xF0F0F0FF);
    pregs->eip = old_eip;

    return (preempted ? HVM_HCALL_preempted :
            flush ? HVM_HCALL_invalidate : HVM_HCALL_completed);
}

void hvm_update_guest_cr3(struct vcpu *v, unsigned long guest_cr3)
{
    v->arch.hvm_vcpu.hw_cr3 = guest_cr3;
    hvm_funcs.update_guest_cr3(v);
}

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
    struct vcpu *v;
    struct domain *d = current->domain;
    struct vcpu_guest_context *ctxt;
    int rc = 0;

    BUG_ON(!is_hvm_domain(d));

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
    if ( !v->is_initialised )
        rc = boot_vcpu(d, vcpuid, ctxt);
    UNLOCK_BIGLOCK(d);

    if ( rc != 0 )
    {
        gdprintk(XENLOG_ERR,
               "AP %d bringup failed in boot_vcpu %x.\n", vcpuid, rc);
        goto out;
    }

    if ( test_and_clear_bit(_VPF_down, &v->pause_flags) )
        vcpu_wake(v);
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

    d = rcu_lock_domain_by_id(op.domid);
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
    rcu_unlock_domain(d);
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

    d = rcu_lock_domain_by_id(op.domid);
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
    rcu_unlock_domain(d);
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

    d = rcu_lock_domain_by_id(op.domid);
    if ( d == NULL )
        return -ESRCH;

    rc = -EINVAL;
    if ( !is_hvm_domain(d) )
        goto out;

    rc = 0;
    hvm_set_pci_link_route(d, op.link, op.isa_irq);

 out:
    rcu_unlock_domain(d);
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
        struct hvm_ioreq_page *iorp;
        struct domain *d;
        struct vcpu *v;

        if ( copy_from_guest(&a, arg, 1) )
            return -EFAULT;

        if ( a.index >= HVM_NR_PARAMS )
            return -EINVAL;

        if ( a.domid == DOMID_SELF )
            d = rcu_lock_current_domain();
        else if ( IS_PRIV(current->domain) )
            d = rcu_lock_domain_by_id(a.domid);
        else
            return -EPERM;

        if ( d == NULL )
            return -ESRCH;

        rc = -EINVAL;
        if ( !is_hvm_domain(d) )
            goto param_fail;

        if ( op == HVMOP_set_param )
        {
            switch ( a.index )
            {
            case HVM_PARAM_IOREQ_PFN:
                iorp = &d->arch.hvm_domain.ioreq;
                rc = hvm_set_ioreq_page(d, iorp, a.value);
                spin_lock(&iorp->lock);
                if ( (rc == 0) && (iorp->va != NULL) )
                    /* Initialise evtchn port info if VCPUs already created. */
                    for_each_vcpu ( d, v )
                        get_ioreq(v)->vp_eport = v->arch.hvm_vcpu.xen_port;
                spin_unlock(&iorp->lock);
                break;
            case HVM_PARAM_BUFIOREQ_PFN: 
                iorp = &d->arch.hvm_domain.buf_ioreq;
                rc = hvm_set_ioreq_page(d, iorp, a.value);
                break;
            case HVM_PARAM_CALLBACK_IRQ:
                hvm_set_callback_via(d, a.value);
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
        rcu_unlock_domain(d);
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

