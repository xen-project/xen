/*
 * hvm.c: Common hardware virtual machine abstractions.
 *
 * Copyright (c) 2004, Intel Corporation.
 * Copyright (c) 2005, International Business Machines Corporation.
 * Copyright (c) 2008, Citrix Systems, Inc.
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
 * this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/config.h>
#include <xen/ctype.h>
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
#include <xen/cpu.h>
#include <xen/wait.h>
#include <xen/mem_access.h>
#include <xen/rangeset.h>
#include <xen/vm_event.h>
#include <xen/monitor.h>
#include <xen/warning.h>
#include <asm/shadow.h>
#include <asm/hap.h>
#include <asm/current.h>
#include <asm/e820.h>
#include <asm/io.h>
#include <asm/regs.h>
#include <asm/cpufeature.h>
#include <asm/processor.h>
#include <asm/types.h>
#include <asm/msr.h>
#include <asm/i387.h>
#include <asm/xstate.h>
#include <asm/traps.h>
#include <asm/mc146818rtc.h>
#include <asm/mce.h>
#include <asm/monitor.h>
#include <asm/hvm/hvm.h>
#include <asm/hvm/vpt.h>
#include <asm/hvm/support.h>
#include <asm/hvm/cacheattr.h>
#include <asm/hvm/trace.h>
#include <asm/hvm/nestedhvm.h>
#include <asm/hvm/monitor.h>
#include <asm/hvm/ioreq.h>
#include <asm/altp2m.h>
#include <asm/mtrr.h>
#include <asm/apic.h>
#include <asm/vm_event.h>
#include <public/sched.h>
#include <public/hvm/ioreq.h>
#include <public/version.h>
#include <public/memory.h>
#include <public/vm_event.h>
#include <public/arch-x86/cpuid.h>
#include <asm/cpuid.h>

bool_t __read_mostly hvm_enabled;

#ifdef DBG_LEVEL_0
unsigned int opt_hvm_debug_level __read_mostly;
integer_param("hvm_debug", opt_hvm_debug_level);
#endif

struct hvm_function_table hvm_funcs __read_mostly;

/*
 * The I/O permission bitmap is globally shared by all HVM guests except
 * the hardware domain which needs a more permissive one.
 */
#define HVM_IOBITMAP_SIZE (3 * PAGE_SIZE)
unsigned long __section(".bss.page_aligned") __aligned(PAGE_SIZE)
    hvm_io_bitmap[HVM_IOBITMAP_SIZE / BYTES_PER_LONG];

/* Xen command-line option to enable HAP */
static bool_t __initdata opt_hap_enabled = 1;
boolean_param("hap", opt_hap_enabled);

#ifndef opt_hvm_fep
/* Permit use of the Forced Emulation Prefix in HVM guests */
bool_t __read_mostly opt_hvm_fep;
boolean_param("hvm_fep", opt_hvm_fep);
#endif
static const char __initconst warning_hvm_fep[] =
    "WARNING: HVM FORCED EMULATION PREFIX IS AVAILABLE\n"
    "This option is *ONLY* intended to aid testing of Xen.\n"
    "It has implications on the security of the system.\n"
    "Please *DO NOT* use this in production.\n";

/* Xen command-line option to enable altp2m */
static bool_t __initdata opt_altp2m_enabled = 0;
boolean_param("altp2m", opt_altp2m_enabled);

static int cpu_callback(
    struct notifier_block *nfb, unsigned long action, void *hcpu)
{
    unsigned int cpu = (unsigned long)hcpu;
    int rc = 0;

    switch ( action )
    {
    case CPU_UP_PREPARE:
        rc = hvm_funcs.cpu_up_prepare(cpu);
        break;
    case CPU_DYING:
        hvm_cpu_down();
        break;
    case CPU_UP_CANCELED:
    case CPU_DEAD:
        hvm_funcs.cpu_dead(cpu);
        break;
    default:
        break;
    }

    return !rc ? NOTIFY_DONE : notifier_from_errno(rc);
}

static struct notifier_block cpu_nfb = {
    .notifier_call = cpu_callback
};

static int __init hvm_enable(void)
{
    const struct hvm_function_table *fns = NULL;

    if ( cpu_has_vmx )
        fns = start_vmx();
    else if ( cpu_has_svm )
        fns = start_svm();

    if ( fns == NULL )
        return 0;

    hvm_funcs = *fns;
    hvm_enabled = 1;

    printk("HVM: %s enabled\n", fns->name);
    if ( !fns->hap_supported )
        printk("HVM: Hardware Assisted Paging (HAP) not detected\n");
    else if ( !opt_hap_enabled )
    {
        hvm_funcs.hap_supported = 0;
        printk("HVM: Hardware Assisted Paging (HAP) detected but disabled\n");
    }
    else
    {
        printk("HVM: Hardware Assisted Paging (HAP) detected\n");
        printk("HVM: HAP page sizes: 4kB");
        if ( fns->hap_capabilities & HVM_HAP_SUPERPAGE_2MB )
        {
            printk(", 2MB%s", opt_hap_2mb ? "" : " [disabled]");
            if ( !opt_hap_2mb )
                hvm_funcs.hap_capabilities &= ~HVM_HAP_SUPERPAGE_2MB;
        }
        if ( fns->hap_capabilities & HVM_HAP_SUPERPAGE_1GB )
        {
            printk(", 1GB%s", opt_hap_1gb ? "" : " [disabled]");
            if ( !opt_hap_1gb )
                hvm_funcs.hap_capabilities &= ~HVM_HAP_SUPERPAGE_1GB;
        }
        printk("\n");
    }

    if ( !fns->pvh_supported )
        printk(XENLOG_INFO "HVM: PVH mode not supported on this platform\n");

    if ( !opt_altp2m_enabled )
        hvm_funcs.altp2m_supported = 0;

    if ( opt_hvm_fep )
        warning_add(warning_hvm_fep);

    /*
     * Allow direct access to the PC debug ports 0x80 and 0xed (they are
     * often used for I/O delays, but the vmexits simply slow things down).
     */
    memset(hvm_io_bitmap, ~0, sizeof(hvm_io_bitmap));
    if ( hvm_port80_allowed )
        __clear_bit(0x80, hvm_io_bitmap);
    __clear_bit(0xed, hvm_io_bitmap);

    register_cpu_notifier(&cpu_nfb);

    return 0;
}
presmp_initcall(hvm_enable);

/*
 * Need to re-inject a given event? We avoid re-injecting software exceptions
 * and interrupts because the faulting/trapping instruction can simply be
 * re-executed (neither VMX nor SVM update RIP when they VMEXIT during
 * INT3/INTO/INTn).
 */
int hvm_event_needs_reinjection(uint8_t type, uint8_t vector)
{
    switch ( type )
    {
    case X86_EVENTTYPE_EXT_INTR:
    case X86_EVENTTYPE_NMI:
        return 1;
    case X86_EVENTTYPE_HW_EXCEPTION:
        /*
         * SVM uses type 3 ("HW Exception") for #OF and #BP. We explicitly
         * check for these vectors, as they are really SW Exceptions. SVM has
         * not updated RIP to point after the trapping instruction (INT3/INTO).
         */
        return (vector != 3) && (vector != 4);
    default:
        /* Software exceptions/interrupts can be re-executed (e.g., INT n). */
        break;
    }
    return 0;
}

/*
 * Combine two hardware exceptions: @vec2 was raised during delivery of @vec1.
 * This means we can assume that @vec2 is contributory or a page fault.
 */
uint8_t hvm_combine_hw_exceptions(uint8_t vec1, uint8_t vec2)
{
    const unsigned int contributory_exceptions =
        (1 << TRAP_divide_error) |
        (1 << TRAP_invalid_tss) |
        (1 << TRAP_no_segment) |
        (1 << TRAP_stack_error) |
        (1 << TRAP_gp_fault);
    const unsigned int page_faults =
        (1 << TRAP_page_fault) |
        (1 << TRAP_virtualisation);

    /* Exception during double-fault delivery always causes a triple fault. */
    if ( vec1 == TRAP_double_fault )
    {
        hvm_triple_fault();
        return TRAP_double_fault; /* dummy return */
    }

    /* Exception during page-fault delivery always causes a double fault. */
    if ( (1u << vec1) & page_faults )
        return TRAP_double_fault;

    /* Discard the first exception if it's benign or if we now have a #PF. */
    if ( !((1u << vec1) & contributory_exceptions) ||
         ((1u << vec2) & page_faults) )
        return vec2;

    /* Cannot combine the exceptions: double fault. */
    return TRAP_double_fault;
}

void hvm_set_rdtsc_exiting(struct domain *d, bool_t enable)
{
    struct vcpu *v;

    for_each_vcpu ( d, v )
        hvm_funcs.set_rdtsc_exiting(v, enable);
}

void hvm_get_guest_pat(struct vcpu *v, u64 *guest_pat)
{
    if ( !hvm_funcs.get_guest_pat(v, guest_pat) )
        *guest_pat = v->arch.hvm_vcpu.pat_cr;
}

int hvm_set_guest_pat(struct vcpu *v, u64 guest_pat)
{
    int i;
    uint8_t *value = (uint8_t *)&guest_pat;

    for ( i = 0; i < 8; i++ )
        switch ( value[i] )
        {
        case PAT_TYPE_UC_MINUS:
        case PAT_TYPE_UNCACHABLE:
        case PAT_TYPE_WRBACK:
        case PAT_TYPE_WRCOMB:
        case PAT_TYPE_WRPROT:
        case PAT_TYPE_WRTHROUGH:
            break;
        default:
            HVM_DBG_LOG(DBG_LEVEL_MSR, "invalid guest PAT: %"PRIx64"\n",
                        guest_pat); 
            return 0;
        }

    if ( !hvm_funcs.set_guest_pat(v, guest_pat) )
        v->arch.hvm_vcpu.pat_cr = guest_pat;

    return 1;
}

bool hvm_set_guest_bndcfgs(struct vcpu *v, u64 val)
{
    return hvm_funcs.set_guest_bndcfgs &&
           is_canonical_address(val) &&
           !(val & IA32_BNDCFGS_RESERVED) &&
           hvm_funcs.set_guest_bndcfgs(v, val);
}

/*
 * Get the ratio to scale host TSC frequency to gtsc_khz. zero will be
 * returned if TSC scaling is unavailable or ratio cannot be handled
 * by host CPU. Otherwise, a non-zero ratio will be returned.
 */
u64 hvm_get_tsc_scaling_ratio(u32 gtsc_khz)
{
    u8 ratio_frac_bits = hvm_funcs.tsc_scaling.ratio_frac_bits;
    u64 max_ratio = hvm_funcs.tsc_scaling.max_ratio;
    u64 ratio, dummy;

    if ( !hvm_tsc_scaling_supported )
        return 0;

    /*
     * Return early if the quotient is too large to fit in the integral
     * part of TSC scaling ratio. This also avoids #DE from the following
     * divq when the quotient can not fit in a 64-bit integer.
     */
    if ( gtsc_khz / cpu_khz > (max_ratio >> ratio_frac_bits) )
        return 0;

    /* ratio = (gtsc_khz << hvm_funcs.tsc_scaling.ratio_frac_bits) / cpu_khz */
    asm ( "shldq %[frac],%[gkhz],%[zero] ; "
          "shlq  %[frac],%[gkhz]         ; "
          "divq  %[hkhz]                   "
          : "=d" (dummy), "=a" (ratio)
          : [frac] "c" (ratio_frac_bits),
            [gkhz] "a" ((u64) gtsc_khz),
            [zero] "d" (0ULL),
            [hkhz] "rm" ((u64) cpu_khz) );

    return ratio > max_ratio ? 0 : ratio;
}

u64 hvm_scale_tsc(const struct domain *d, u64 tsc)
{
    u64 ratio = d->arch.hvm_domain.tsc_scaling_ratio;
    u64 dummy;

    if ( ratio == hvm_default_tsc_scaling_ratio )
        return tsc;

    /* tsc = (tsc * ratio) >> hvm_funcs.tsc_scaling.ratio_frac_bits */
    asm ( "mulq %[ratio]; shrdq %[frac],%%rdx,%[tsc]"
          : [tsc] "+a" (tsc), "=&d" (dummy)
          : [frac] "c" (hvm_funcs.tsc_scaling.ratio_frac_bits),
            [ratio] "rm" (ratio) );

    return tsc;
}

void hvm_set_guest_tsc_fixed(struct vcpu *v, u64 guest_tsc, u64 at_tsc)
{
    uint64_t tsc;
    uint64_t delta_tsc;

    if ( v->domain->arch.vtsc )
    {
        tsc = hvm_get_guest_time_fixed(v, at_tsc);
        tsc = gtime_to_gtsc(v->domain, tsc);
    }
    else
    {
        tsc = at_tsc ?: rdtsc();
        if ( hvm_tsc_scaling_supported )
            tsc = hvm_scale_tsc(v->domain, tsc);
    }

    delta_tsc = guest_tsc - tsc;
    v->arch.hvm_vcpu.cache_tsc_offset = delta_tsc;

    hvm_funcs.set_tsc_offset(v, v->arch.hvm_vcpu.cache_tsc_offset, at_tsc);
}

static void hvm_set_guest_tsc_msr(struct vcpu *v, u64 guest_tsc)
{
    uint64_t tsc_offset = v->arch.hvm_vcpu.cache_tsc_offset;

    hvm_set_guest_tsc(v, guest_tsc);
    v->arch.hvm_vcpu.msr_tsc_adjust += v->arch.hvm_vcpu.cache_tsc_offset
                          - tsc_offset;
}

void hvm_set_guest_tsc_adjust(struct vcpu *v, u64 tsc_adjust)
{
    v->arch.hvm_vcpu.cache_tsc_offset += tsc_adjust
                            - v->arch.hvm_vcpu.msr_tsc_adjust;
    hvm_funcs.set_tsc_offset(v, v->arch.hvm_vcpu.cache_tsc_offset, 0);
    v->arch.hvm_vcpu.msr_tsc_adjust = tsc_adjust;
}

u64 hvm_get_guest_tsc_fixed(struct vcpu *v, uint64_t at_tsc)
{
    uint64_t tsc;

    if ( v->domain->arch.vtsc )
    {
        tsc = hvm_get_guest_time_fixed(v, at_tsc);
        tsc = gtime_to_gtsc(v->domain, tsc);
    }
    else
    {
        tsc = at_tsc ?: rdtsc();
        if ( hvm_tsc_scaling_supported )
            tsc = hvm_scale_tsc(v->domain, tsc);
    }

    return tsc + v->arch.hvm_vcpu.cache_tsc_offset;
}

u64 hvm_get_guest_tsc_adjust(struct vcpu *v)
{
    return v->arch.hvm_vcpu.msr_tsc_adjust;
}

void hvm_migrate_timers(struct vcpu *v)
{
    /* PVH doesn't use rtc and emulated timers, it uses pvclock mechanism. */
    if ( is_pvh_vcpu(v) )
        return;

    rtc_migrate_timers(v);
    pt_migrate(v);
}

static int hvm_migrate_pirq(struct domain *d, struct hvm_pirq_dpci *pirq_dpci,
                            void *arg)
{
    struct vcpu *v = arg;

    if ( (pirq_dpci->flags & HVM_IRQ_DPCI_MACH_MSI) &&
         (pirq_dpci->gmsi.dest_vcpu_id == v->vcpu_id) )
    {
        struct irq_desc *desc =
            pirq_spin_lock_irq_desc(dpci_pirq(pirq_dpci), NULL);

        if ( !desc )
            return 0;
        ASSERT(MSI_IRQ(desc - irq_desc));
        irq_set_affinity(desc, cpumask_of(v->processor));
        spin_unlock_irq(&desc->lock);
    }

    return 0;
}

void hvm_migrate_pirqs(struct vcpu *v)
{
    struct domain *d = v->domain;

    if ( !iommu_enabled || !d->arch.hvm_domain.irq.dpci )
       return;

    spin_lock(&d->event_lock);
    pt_pirq_iterate(d, hvm_migrate_pirq, v);
    spin_unlock(&d->event_lock);
}

void hvm_do_resume(struct vcpu *v)
{
    check_wakeup_from_wait();

    if ( is_hvm_domain(v->domain) )
        pt_restore_timer(v);

    if ( !handle_hvm_io_completion(v) )
        return;

    if ( unlikely(v->arch.vm_event) )
    {
        struct monitor_write_data *w = &v->arch.vm_event->write_data;

        if ( unlikely(v->arch.vm_event->emulate_flags) )
        {
            enum emul_kind kind = EMUL_KIND_NORMAL;

            /*
             * Please observ the order here to match the flag descriptions
             * provided in public/vm_event.h
             */
            if ( v->arch.vm_event->emulate_flags &
                 VM_EVENT_FLAG_SET_EMUL_READ_DATA )
                kind = EMUL_KIND_SET_CONTEXT_DATA;
            else if ( v->arch.vm_event->emulate_flags &
                      VM_EVENT_FLAG_EMULATE_NOWRITE )
                kind = EMUL_KIND_NOWRITE;
            else if ( v->arch.vm_event->emulate_flags &
                      VM_EVENT_FLAG_SET_EMUL_INSN_DATA )
                kind = EMUL_KIND_SET_CONTEXT_INSN;

            hvm_emulate_one_vm_event(kind, TRAP_invalid_op,
                                     HVM_DELIVER_NO_ERROR_CODE);

            v->arch.vm_event->emulate_flags = 0;
        }

        if ( w->do_write.msr )
        {
            hvm_msr_write_intercept(w->msr, w->value, 0);
            w->do_write.msr = 0;
        }

        if ( w->do_write.cr0 )
        {
            hvm_set_cr0(w->cr0, 0);
            w->do_write.cr0 = 0;
        }

        if ( w->do_write.cr4 )
        {
            hvm_set_cr4(w->cr4, 0);
            w->do_write.cr4 = 0;
        }

        if ( w->do_write.cr3 )
        {
            hvm_set_cr3(w->cr3, 0);
            w->do_write.cr3 = 0;
        }
    }

    /* Inject pending hw/sw trap */
    if ( v->arch.hvm_vcpu.inject_trap.vector != -1 )
    {
        hvm_inject_trap(&v->arch.hvm_vcpu.inject_trap);
        v->arch.hvm_vcpu.inject_trap.vector = -1;
    }
}

static int hvm_print_line(
    int dir, unsigned int port, unsigned int bytes, uint32_t *val)
{
    struct domain *cd = current->domain;
    char c = *val;

    BUG_ON(bytes != 1);

    /* Accept only printable characters, newline, and horizontal tab. */
    if ( !isprint(c) && (c != '\n') && (c != '\t') )
        return X86EMUL_OKAY;

    spin_lock(&cd->pbuf_lock);
    if ( c != '\n' )
        cd->pbuf[cd->pbuf_idx++] = c;
    if ( (cd->pbuf_idx == (DOMAIN_PBUF_SIZE - 1)) || (c == '\n') )
    {
        cd->pbuf[cd->pbuf_idx] = '\0';
        guest_printk(cd, XENLOG_G_DEBUG "%s\n", cd->pbuf);
        cd->pbuf_idx = 0;
    }
    spin_unlock(&cd->pbuf_lock);

    return X86EMUL_OKAY;
}

static int handle_pvh_io(
    int dir, unsigned int port, unsigned int bytes, uint32_t *val)
{
    struct domain *currd = current->domain;

    if ( dir == IOREQ_WRITE )
        guest_io_write(port, bytes, *val, currd);
    else
        *val = guest_io_read(port, bytes, currd);

    return X86EMUL_OKAY;
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

    if ( is_pvh_domain(d) )
    {
        if ( !hvm_funcs.pvh_supported )
        {
            printk(XENLOG_G_WARNING "Attempt to create a PVH guest "
                   "on a system without necessary hardware support\n");
            return -EINVAL;
        }
        if ( !hap_enabled(d) )
        {
            printk(XENLOG_G_INFO "PVH guest must have HAP on\n");
            return -EINVAL;
        }

    }

    spin_lock_init(&d->arch.hvm_domain.irq_lock);
    spin_lock_init(&d->arch.hvm_domain.uc_lock);
    spin_lock_init(&d->arch.hvm_domain.write_map.lock);
    INIT_LIST_HEAD(&d->arch.hvm_domain.write_map.list);

    hvm_init_cacheattr_region_list(d);

    rc = paging_enable(d, PG_refcounts|PG_translate|PG_external);
    if ( rc != 0 )
        goto fail0;

    d->arch.hvm_domain.pl_time = xzalloc(struct pl_time);
    d->arch.hvm_domain.params = xzalloc_array(uint64_t, HVM_NR_PARAMS);
    d->arch.hvm_domain.io_handler = xzalloc_array(struct hvm_io_handler,
                                                  NR_IO_HANDLERS);
    rc = -ENOMEM;
    if ( !d->arch.hvm_domain.pl_time ||
         !d->arch.hvm_domain.params  || !d->arch.hvm_domain.io_handler )
        goto fail1;

    /* need link to containing domain */
    d->arch.hvm_domain.pl_time->domain = d;

    /* Set the default IO Bitmap. */
    if ( is_hardware_domain(d) )
    {
        d->arch.hvm_domain.io_bitmap = _xmalloc(HVM_IOBITMAP_SIZE, PAGE_SIZE);
        if ( d->arch.hvm_domain.io_bitmap == NULL )
        {
            rc = -ENOMEM;
            goto fail1;
        }
        memset(d->arch.hvm_domain.io_bitmap, ~0, HVM_IOBITMAP_SIZE);
    }
    else
        d->arch.hvm_domain.io_bitmap = hvm_io_bitmap;

    register_dpci_portio_handler(d);

    hvm_ioreq_init(d);

    if ( is_pvh_domain(d) )
    {
        register_portio_handler(d, 0, 0x10003, handle_pvh_io);
        return 0;
    }

    hvm_init_guest_time(d);

    d->arch.hvm_domain.params[HVM_PARAM_TRIPLE_FAULT_REASON] = SHUTDOWN_reboot;

    vpic_init(d);

    rc = vioapic_init(d);
    if ( rc != 0 )
        goto fail1;

    stdvga_init(d);

    rtc_init(d);

    register_portio_handler(d, 0xe9, 1, hvm_print_line);

    if ( hvm_tsc_scaling_supported )
        d->arch.hvm_domain.tsc_scaling_ratio = hvm_default_tsc_scaling_ratio;

    rc = hvm_funcs.domain_initialise(d);
    if ( rc != 0 )
        goto fail2;

    return 0;

 fail2:
    rtc_deinit(d);
    stdvga_deinit(d);
    vioapic_deinit(d);
 fail1:
    if ( is_hardware_domain(d) )
        xfree(d->arch.hvm_domain.io_bitmap);
    xfree(d->arch.hvm_domain.io_handler);
    xfree(d->arch.hvm_domain.params);
    xfree(d->arch.hvm_domain.pl_time);
 fail0:
    hvm_destroy_cacheattr_region_list(d);
    return rc;
}

void hvm_domain_relinquish_resources(struct domain *d)
{
    if ( is_pvh_domain(d) )
        return;

    if ( hvm_funcs.nhvm_domain_relinquish_resources )
        hvm_funcs.nhvm_domain_relinquish_resources(d);

    viridian_domain_deinit(d);

    hvm_destroy_all_ioreq_servers(d);

    msixtbl_pt_cleanup(d);

    /* Stop all asynchronous timer actions. */
    rtc_deinit(d);
    if ( d->vcpu != NULL && d->vcpu[0] != NULL )
    {
        pmtimer_deinit(d);
        hpet_deinit(d);
    }
}

void hvm_domain_destroy(struct domain *d)
{
    xfree(d->arch.hvm_domain.io_handler);
    d->arch.hvm_domain.io_handler = NULL;

    xfree(d->arch.hvm_domain.params);
    d->arch.hvm_domain.params = NULL;

    hvm_destroy_cacheattr_region_list(d);

    if ( is_pvh_domain(d) )
        return;

    hvm_funcs.domain_destroy(d);
    rtc_deinit(d);
    stdvga_deinit(d);
    vioapic_deinit(d);

    xfree(d->arch.hvm_domain.pl_time);
    d->arch.hvm_domain.pl_time = NULL;
}

static int hvm_save_tsc_adjust(struct domain *d, hvm_domain_context_t *h)
{
    struct vcpu *v;
    struct hvm_tsc_adjust ctxt;
    int err = 0;

    for_each_vcpu ( d, v )
    {
        ctxt.tsc_adjust = v->arch.hvm_vcpu.msr_tsc_adjust;
        err = hvm_save_entry(TSC_ADJUST, v->vcpu_id, h, &ctxt);
        if ( err )
            break;
    }

    return err;
}

static int hvm_load_tsc_adjust(struct domain *d, hvm_domain_context_t *h)
{
    unsigned int vcpuid = hvm_load_instance(h);
    struct vcpu *v;
    struct hvm_tsc_adjust ctxt;

    if ( vcpuid >= d->max_vcpus || (v = d->vcpu[vcpuid]) == NULL )
    {
        dprintk(XENLOG_G_ERR, "HVM restore: dom%d has no vcpu%u\n",
                d->domain_id, vcpuid);
        return -EINVAL;
    }

    if ( hvm_load_entry(TSC_ADJUST, h, &ctxt) != 0 )
        return -EINVAL;

    v->arch.hvm_vcpu.msr_tsc_adjust = ctxt.tsc_adjust;
    return 0;
}

HVM_REGISTER_SAVE_RESTORE(TSC_ADJUST, hvm_save_tsc_adjust,
                          hvm_load_tsc_adjust, 1, HVMSR_PER_VCPU);

static int hvm_save_cpu_ctxt(struct domain *d, hvm_domain_context_t *h)
{
    struct vcpu *v;
    struct hvm_hw_cpu ctxt;
    struct segment_register seg;

    for_each_vcpu ( d, v )
    {
        /* We don't need to save state for a vcpu that is down; the restore 
         * code will leave it down if there is nothing saved. */
        if ( v->pause_flags & VPF_down )
            continue;

        memset(&ctxt, 0, sizeof(ctxt));

        /* Architecture-specific vmcs/vmcb bits */
        hvm_funcs.save_cpu_ctxt(v, &ctxt);

        ctxt.tsc = hvm_get_guest_tsc_fixed(v, d->arch.hvm_domain.sync_tsc);

        ctxt.msr_tsc_aux = hvm_msr_tsc_aux(v);

        hvm_get_segment_register(v, x86_seg_idtr, &seg);
        ctxt.idtr_limit = seg.limit;
        ctxt.idtr_base = seg.base;

        hvm_get_segment_register(v, x86_seg_gdtr, &seg);
        ctxt.gdtr_limit = seg.limit;
        ctxt.gdtr_base = seg.base;

        hvm_get_segment_register(v, x86_seg_cs, &seg);
        ctxt.cs_sel = seg.sel;
        ctxt.cs_limit = seg.limit;
        ctxt.cs_base = seg.base;
        ctxt.cs_arbytes = seg.attr.bytes;

        hvm_get_segment_register(v, x86_seg_ds, &seg);
        ctxt.ds_sel = seg.sel;
        ctxt.ds_limit = seg.limit;
        ctxt.ds_base = seg.base;
        ctxt.ds_arbytes = seg.attr.bytes;

        hvm_get_segment_register(v, x86_seg_es, &seg);
        ctxt.es_sel = seg.sel;
        ctxt.es_limit = seg.limit;
        ctxt.es_base = seg.base;
        ctxt.es_arbytes = seg.attr.bytes;

        hvm_get_segment_register(v, x86_seg_ss, &seg);
        ctxt.ss_sel = seg.sel;
        ctxt.ss_limit = seg.limit;
        ctxt.ss_base = seg.base;
        ctxt.ss_arbytes = seg.attr.bytes;

        hvm_get_segment_register(v, x86_seg_fs, &seg);
        ctxt.fs_sel = seg.sel;
        ctxt.fs_limit = seg.limit;
        ctxt.fs_base = seg.base;
        ctxt.fs_arbytes = seg.attr.bytes;

        hvm_get_segment_register(v, x86_seg_gs, &seg);
        ctxt.gs_sel = seg.sel;
        ctxt.gs_limit = seg.limit;
        ctxt.gs_base = seg.base;
        ctxt.gs_arbytes = seg.attr.bytes;

        hvm_get_segment_register(v, x86_seg_tr, &seg);
        ctxt.tr_sel = seg.sel;
        ctxt.tr_limit = seg.limit;
        ctxt.tr_base = seg.base;
        ctxt.tr_arbytes = seg.attr.bytes;

        hvm_get_segment_register(v, x86_seg_ldtr, &seg);
        ctxt.ldtr_sel = seg.sel;
        ctxt.ldtr_limit = seg.limit;
        ctxt.ldtr_base = seg.base;
        ctxt.ldtr_arbytes = seg.attr.bytes;

        if ( v->fpu_initialised )
        {
            memcpy(ctxt.fpu_regs, v->arch.fpu_ctxt, sizeof(ctxt.fpu_regs));
            ctxt.flags = XEN_X86_FPU_INITIALISED;
        }

        ctxt.rax = v->arch.user_regs.eax;
        ctxt.rbx = v->arch.user_regs.ebx;
        ctxt.rcx = v->arch.user_regs.ecx;
        ctxt.rdx = v->arch.user_regs.edx;
        ctxt.rbp = v->arch.user_regs.ebp;
        ctxt.rsi = v->arch.user_regs.esi;
        ctxt.rdi = v->arch.user_regs.edi;
        ctxt.rsp = v->arch.user_regs.esp;
        ctxt.rip = v->arch.user_regs.eip;
        ctxt.rflags = v->arch.user_regs.eflags;
        ctxt.r8  = v->arch.user_regs.r8;
        ctxt.r9  = v->arch.user_regs.r9;
        ctxt.r10 = v->arch.user_regs.r10;
        ctxt.r11 = v->arch.user_regs.r11;
        ctxt.r12 = v->arch.user_regs.r12;
        ctxt.r13 = v->arch.user_regs.r13;
        ctxt.r14 = v->arch.user_regs.r14;
        ctxt.r15 = v->arch.user_regs.r15;
        ctxt.dr0 = v->arch.debugreg[0];
        ctxt.dr1 = v->arch.debugreg[1];
        ctxt.dr2 = v->arch.debugreg[2];
        ctxt.dr3 = v->arch.debugreg[3];
        ctxt.dr6 = v->arch.debugreg[6];
        ctxt.dr7 = v->arch.debugreg[7];

        if ( hvm_save_entry(CPU, v->vcpu_id, h, &ctxt) != 0 )
            return 1; 
    }
    return 0;
}

/* Return a string indicating the error, or NULL for valid. */
const char *hvm_efer_valid(const struct vcpu *v, uint64_t value,
                           signed int cr0_pg)
{
    unsigned int ext1_ecx = 0, ext1_edx = 0;

    if ( cr0_pg < 0 && !is_hardware_domain(v->domain) )
    {
        unsigned int level;

        ASSERT(v->domain == current->domain);
        hvm_cpuid(0x80000000, &level, NULL, NULL, NULL);
        if ( (level >> 16) == 0x8000 && level > 0x80000000 )
        {
            unsigned int dummy;

            level = 0x80000001;
            hvm_funcs.cpuid_intercept(&level, &dummy, &ext1_ecx, &ext1_edx);
        }
    }
    else
    {
        ext1_edx = boot_cpu_data.x86_capability[cpufeat_word(X86_FEATURE_LM)];
        ext1_ecx = boot_cpu_data.x86_capability[cpufeat_word(X86_FEATURE_SVM)];
    }

    /*
     * Guests may want to set EFER.SCE and EFER.LME at the same time, so we
     * can't make the check depend on only X86_FEATURE_SYSCALL (which on VMX
     * will be clear without the guest having entered 64-bit mode).
     */
    if ( (value & EFER_SCE) &&
         !(ext1_edx & cpufeat_mask(X86_FEATURE_SYSCALL)) &&
         (cr0_pg >= 0 || !(value & EFER_LME)) )
        return "SCE without feature";

    if ( (value & (EFER_LME | EFER_LMA)) &&
         !(ext1_edx & cpufeat_mask(X86_FEATURE_LM)) )
        return "LME/LMA without feature";

    if ( (value & EFER_LMA) && (!(value & EFER_LME) || !cr0_pg) )
        return "LMA/LME/CR0.PG inconsistency";

    if ( (value & EFER_NX) && !(ext1_edx & cpufeat_mask(X86_FEATURE_NX)) )
        return "NX without feature";

    if ( (value & EFER_SVME) &&
         (!(ext1_ecx & cpufeat_mask(X86_FEATURE_SVM)) ||
          !nestedhvm_enabled(v->domain)) )
        return "SVME without nested virt";

    if ( (value & EFER_LMSLE) && !cpu_has_lmsl )
        return "LMSLE without support";

    if ( (value & EFER_FFXSE) &&
         !(ext1_edx & cpufeat_mask(X86_FEATURE_FFXSR)) )
        return "FFXSE without feature";

    return NULL;
}

/* These reserved bits in lower 32 remain 0 after any load of CR0 */
#define HVM_CR0_GUEST_RESERVED_BITS             \
    (~((unsigned long)                          \
       (X86_CR0_PE | X86_CR0_MP | X86_CR0_EM |  \
        X86_CR0_TS | X86_CR0_ET | X86_CR0_NE |  \
        X86_CR0_WP | X86_CR0_AM | X86_CR0_NW |  \
        X86_CR0_CD | X86_CR0_PG)))

/* These bits in CR4 cannot be set by the guest. */
unsigned long hvm_cr4_guest_reserved_bits(const struct vcpu *v,bool_t restore)
{
    unsigned int leaf1_ecx = 0, leaf1_edx = 0;
    unsigned int leaf7_0_ebx = 0, leaf7_0_ecx = 0;

    if ( !restore && !is_hardware_domain(v->domain) )
    {
        unsigned int level;

        ASSERT(v->domain == current->domain);
        hvm_cpuid(0, &level, NULL, NULL, NULL);
        if ( level >= 1 )
            hvm_cpuid(1, NULL, NULL, &leaf1_ecx, &leaf1_edx);
        if ( level >= 7 )
            hvm_cpuid(7, NULL, &leaf7_0_ebx, &leaf7_0_ecx, NULL);
    }
    else
    {
        leaf1_edx = boot_cpu_data.x86_capability[cpufeat_word(X86_FEATURE_VME)];
        leaf1_ecx = boot_cpu_data.x86_capability[cpufeat_word(X86_FEATURE_PCID)];
        leaf7_0_ebx = boot_cpu_data.x86_capability[cpufeat_word(X86_FEATURE_FSGSBASE)];
        leaf7_0_ecx = boot_cpu_data.x86_capability[cpufeat_word(X86_FEATURE_PKU)];
    }

    return ~(unsigned long)
            ((leaf1_edx & cpufeat_mask(X86_FEATURE_VME) ?
              X86_CR4_VME | X86_CR4_PVI : 0) |
             (leaf1_edx & cpufeat_mask(X86_FEATURE_TSC) ?
              X86_CR4_TSD : 0) |
             (leaf1_edx & cpufeat_mask(X86_FEATURE_DE) ?
              X86_CR4_DE : 0) |
             (leaf1_edx & cpufeat_mask(X86_FEATURE_PSE) ?
              X86_CR4_PSE : 0) |
             (leaf1_edx & cpufeat_mask(X86_FEATURE_PAE) ?
              X86_CR4_PAE : 0) |
             (leaf1_edx & (cpufeat_mask(X86_FEATURE_MCE) |
                           cpufeat_mask(X86_FEATURE_MCA)) ?
              X86_CR4_MCE : 0) |
             (leaf1_edx & cpufeat_mask(X86_FEATURE_PGE) ?
              X86_CR4_PGE : 0) |
             X86_CR4_PCE |
             (leaf1_edx & cpufeat_mask(X86_FEATURE_FXSR) ?
              X86_CR4_OSFXSR : 0) |
             (leaf1_edx & cpufeat_mask(X86_FEATURE_SSE) ?
              X86_CR4_OSXMMEXCPT : 0) |
             ((restore || nestedhvm_enabled(v->domain)) &&
              (leaf1_ecx & cpufeat_mask(X86_FEATURE_VMX)) ?
              X86_CR4_VMXE : 0) |
             (leaf7_0_ebx & cpufeat_mask(X86_FEATURE_FSGSBASE) ?
              X86_CR4_FSGSBASE : 0) |
             (leaf1_ecx & cpufeat_mask(X86_FEATURE_PCID) ?
              X86_CR4_PCIDE : 0) |
             (leaf1_ecx & cpufeat_mask(X86_FEATURE_XSAVE) ?
              X86_CR4_OSXSAVE : 0) |
             (leaf7_0_ebx & cpufeat_mask(X86_FEATURE_SMEP) ?
              X86_CR4_SMEP : 0) |
             (leaf7_0_ebx & cpufeat_mask(X86_FEATURE_SMAP) ?
              X86_CR4_SMAP : 0) |
              (leaf7_0_ecx & cpufeat_mask(X86_FEATURE_PKU) ?
              X86_CR4_PKE : 0));
}

static int hvm_load_cpu_ctxt(struct domain *d, hvm_domain_context_t *h)
{
    int vcpuid;
    struct vcpu *v;
    struct hvm_hw_cpu ctxt;
    struct segment_register seg;
    const char *errstr;
    struct xsave_struct *xsave_area;

    /* Which vcpu is this? */
    vcpuid = hvm_load_instance(h);
    if ( vcpuid >= d->max_vcpus || (v = d->vcpu[vcpuid]) == NULL )
    {
        dprintk(XENLOG_G_ERR, "HVM restore: dom%u has no vcpu%u\n",
                d->domain_id, vcpuid);
        return -EINVAL;
    }

    if ( hvm_load_entry_zeroextend(CPU, h, &ctxt) != 0 )
        return -EINVAL;

    if ( ctxt.pad0 != 0 )
        return -EINVAL;

    /* Sanity check some control registers. */
    if ( (ctxt.cr0 & HVM_CR0_GUEST_RESERVED_BITS) ||
         !(ctxt.cr0 & X86_CR0_ET) ||
         ((ctxt.cr0 & (X86_CR0_PE|X86_CR0_PG)) == X86_CR0_PG) )
    {
        printk(XENLOG_G_ERR "HVM%d restore: bad CR0 %#" PRIx64 "\n",
               d->domain_id, ctxt.cr0);
        return -EINVAL;
    }

    if ( ctxt.cr4 & hvm_cr4_guest_reserved_bits(v, 1) )
    {
        printk(XENLOG_G_ERR "HVM%d restore: bad CR4 %#" PRIx64 "\n",
               d->domain_id, ctxt.cr4);
        return -EINVAL;
    }

    errstr = hvm_efer_valid(v, ctxt.msr_efer, MASK_EXTR(ctxt.cr0, X86_CR0_PG));
    if ( errstr )
    {
        printk(XENLOG_G_ERR "%pv: HVM restore: bad EFER %#" PRIx64 " - %s\n",
               v, ctxt.msr_efer, errstr);
        return -EINVAL;
    }

    if ( (ctxt.flags & ~XEN_X86_FPU_INITIALISED) != 0 )
    {
        gprintk(XENLOG_ERR, "bad flags value in CPU context: %#x\n",
                ctxt.flags);
        return -EINVAL;
    }

    /* Older Xen versions used to save the segment arbytes directly 
     * from the VMCS on Intel hosts.  Detect this and rearrange them
     * into the struct segment_register format. */
#define UNFOLD_ARBYTES(_r)                          \
    if ( (_r & 0xf000) && !(_r & 0x0f00) )          \
        _r = ((_r & 0xff) | ((_r >> 4) & 0xf00))
    UNFOLD_ARBYTES(ctxt.cs_arbytes);
    UNFOLD_ARBYTES(ctxt.ds_arbytes);
    UNFOLD_ARBYTES(ctxt.es_arbytes);
    UNFOLD_ARBYTES(ctxt.fs_arbytes);
    UNFOLD_ARBYTES(ctxt.gs_arbytes);
    UNFOLD_ARBYTES(ctxt.ss_arbytes);
    UNFOLD_ARBYTES(ctxt.tr_arbytes);
    UNFOLD_ARBYTES(ctxt.ldtr_arbytes);
#undef UNFOLD_ARBYTES

    /* Architecture-specific vmcs/vmcb bits */
    if ( hvm_funcs.load_cpu_ctxt(v, &ctxt) < 0 )
        return -EINVAL;

    if ( hvm_funcs.tsc_scaling.setup )
        hvm_funcs.tsc_scaling.setup(v);

    v->arch.hvm_vcpu.msr_tsc_aux = ctxt.msr_tsc_aux;

    hvm_set_guest_tsc_fixed(v, ctxt.tsc, d->arch.hvm_domain.sync_tsc);

    seg.limit = ctxt.idtr_limit;
    seg.base = ctxt.idtr_base;
    hvm_set_segment_register(v, x86_seg_idtr, &seg);

    seg.limit = ctxt.gdtr_limit;
    seg.base = ctxt.gdtr_base;
    hvm_set_segment_register(v, x86_seg_gdtr, &seg);

    seg.sel = ctxt.cs_sel;
    seg.limit = ctxt.cs_limit;
    seg.base = ctxt.cs_base;
    seg.attr.bytes = ctxt.cs_arbytes;
    hvm_set_segment_register(v, x86_seg_cs, &seg);

    seg.sel = ctxt.ds_sel;
    seg.limit = ctxt.ds_limit;
    seg.base = ctxt.ds_base;
    seg.attr.bytes = ctxt.ds_arbytes;
    hvm_set_segment_register(v, x86_seg_ds, &seg);

    seg.sel = ctxt.es_sel;
    seg.limit = ctxt.es_limit;
    seg.base = ctxt.es_base;
    seg.attr.bytes = ctxt.es_arbytes;
    hvm_set_segment_register(v, x86_seg_es, &seg);

    seg.sel = ctxt.ss_sel;
    seg.limit = ctxt.ss_limit;
    seg.base = ctxt.ss_base;
    seg.attr.bytes = ctxt.ss_arbytes;
    hvm_set_segment_register(v, x86_seg_ss, &seg);

    seg.sel = ctxt.fs_sel;
    seg.limit = ctxt.fs_limit;
    seg.base = ctxt.fs_base;
    seg.attr.bytes = ctxt.fs_arbytes;
    hvm_set_segment_register(v, x86_seg_fs, &seg);

    seg.sel = ctxt.gs_sel;
    seg.limit = ctxt.gs_limit;
    seg.base = ctxt.gs_base;
    seg.attr.bytes = ctxt.gs_arbytes;
    hvm_set_segment_register(v, x86_seg_gs, &seg);

    seg.sel = ctxt.tr_sel;
    seg.limit = ctxt.tr_limit;
    seg.base = ctxt.tr_base;
    seg.attr.bytes = ctxt.tr_arbytes;
    hvm_set_segment_register(v, x86_seg_tr, &seg);

    seg.sel = ctxt.ldtr_sel;
    seg.limit = ctxt.ldtr_limit;
    seg.base = ctxt.ldtr_base;
    seg.attr.bytes = ctxt.ldtr_arbytes;
    hvm_set_segment_register(v, x86_seg_ldtr, &seg);

    /* Cover xsave-absent save file restoration on xsave-capable host. */
    xsave_area = xsave_enabled(v) ? NULL : v->arch.xsave_area;

    v->fpu_initialised = !!(ctxt.flags & XEN_X86_FPU_INITIALISED);
    if ( v->fpu_initialised )
    {
        memcpy(v->arch.fpu_ctxt, ctxt.fpu_regs, sizeof(ctxt.fpu_regs));
        if ( xsave_area )
            xsave_area->xsave_hdr.xstate_bv = XSTATE_FP_SSE;
    }
    else if ( xsave_area )
    {
        xsave_area->xsave_hdr.xstate_bv = 0;
        xsave_area->fpu_sse.mxcsr = MXCSR_DEFAULT;
    }
    if ( xsave_area )
        xsave_area->xsave_hdr.xcomp_bv = 0;

    v->arch.user_regs.eax = ctxt.rax;
    v->arch.user_regs.ebx = ctxt.rbx;
    v->arch.user_regs.ecx = ctxt.rcx;
    v->arch.user_regs.edx = ctxt.rdx;
    v->arch.user_regs.ebp = ctxt.rbp;
    v->arch.user_regs.esi = ctxt.rsi;
    v->arch.user_regs.edi = ctxt.rdi;
    v->arch.user_regs.esp = ctxt.rsp;
    v->arch.user_regs.eip = ctxt.rip;
    v->arch.user_regs.eflags = ctxt.rflags | X86_EFLAGS_MBS;
    v->arch.user_regs.r8  = ctxt.r8;
    v->arch.user_regs.r9  = ctxt.r9;
    v->arch.user_regs.r10 = ctxt.r10;
    v->arch.user_regs.r11 = ctxt.r11;
    v->arch.user_regs.r12 = ctxt.r12;
    v->arch.user_regs.r13 = ctxt.r13;
    v->arch.user_regs.r14 = ctxt.r14;
    v->arch.user_regs.r15 = ctxt.r15;
    v->arch.debugreg[0] = ctxt.dr0;
    v->arch.debugreg[1] = ctxt.dr1;
    v->arch.debugreg[2] = ctxt.dr2;
    v->arch.debugreg[3] = ctxt.dr3;
    v->arch.debugreg[6] = ctxt.dr6;
    v->arch.debugreg[7] = ctxt.dr7;

    v->arch.vgc_flags = VGCF_online;

    /* Auxiliary processors should be woken immediately. */
    v->is_initialised = 1;
    clear_bit(_VPF_down, &v->pause_flags);
    vcpu_wake(v);

    return 0;
}

HVM_REGISTER_SAVE_RESTORE(CPU, hvm_save_cpu_ctxt, hvm_load_cpu_ctxt,
                          1, HVMSR_PER_VCPU);

#define HVM_CPU_XSAVE_SIZE(xcr0) (offsetof(struct hvm_hw_cpu_xsave, \
                                           save_area) + \
                                  xstate_ctxt_size(xcr0))

static int hvm_save_cpu_xsave_states(struct domain *d, hvm_domain_context_t *h)
{
    struct vcpu *v;
    struct hvm_hw_cpu_xsave *ctxt;

    if ( !cpu_has_xsave )
        return 0;   /* do nothing */

    for_each_vcpu ( d, v )
    {
        unsigned int size = HVM_CPU_XSAVE_SIZE(v->arch.xcr0_accum);

        if ( !xsave_enabled(v) )
            continue;
        if ( _hvm_init_entry(h, CPU_XSAVE_CODE, v->vcpu_id, size) )
            return 1;
        ctxt = (struct hvm_hw_cpu_xsave *)&h->data[h->cur];
        h->cur += size;

        ctxt->xfeature_mask = xfeature_mask;
        ctxt->xcr0 = v->arch.xcr0;
        ctxt->xcr0_accum = v->arch.xcr0_accum;
        expand_xsave_states(v, &ctxt->save_area,
                            size - offsetof(typeof(*ctxt), save_area));
    }

    return 0;
}

/*
 * Structure layout conformity checks, documenting correctness of the cast in
 * the invocation of validate_xstate() below.
 * Leverage CONFIG_COMPAT machinery to perform this.
 */
#define xen_xsave_hdr xsave_hdr
#define compat_xsave_hdr hvm_hw_cpu_xsave_hdr
CHECK_FIELD_(struct, xsave_hdr, xstate_bv);
CHECK_FIELD_(struct, xsave_hdr, xcomp_bv);
CHECK_FIELD_(struct, xsave_hdr, reserved);
#undef compat_xsave_hdr
#undef xen_xsave_hdr

static int hvm_load_cpu_xsave_states(struct domain *d, hvm_domain_context_t *h)
{
    unsigned int vcpuid, size;
    int err;
    struct vcpu *v;
    struct hvm_hw_cpu_xsave *ctxt;
    const struct hvm_save_descriptor *desc;
    unsigned int i, desc_start, desc_length;

    /* Which vcpu is this? */
    vcpuid = hvm_load_instance(h);
    if ( vcpuid >= d->max_vcpus || (v = d->vcpu[vcpuid]) == NULL )
    {
        dprintk(XENLOG_G_ERR, "HVM restore: dom%d has no vcpu%u\n",
                d->domain_id, vcpuid);
        return -EINVAL;
    }

    /* Fails since we can't restore an img saved on xsave-capable host. */
    if ( !cpu_has_xsave )
        return -EOPNOTSUPP;

    /* Customized checking for entry since our entry is of variable length */
    desc = (struct hvm_save_descriptor *)&h->data[h->cur];
    if ( sizeof (*desc) > h->size - h->cur)
    {
        printk(XENLOG_G_WARNING
               "HVM%d.%d restore: not enough data left to read xsave descriptor\n",
               d->domain_id, vcpuid);
        return -ENODATA;
    }
    if ( desc->length + sizeof (*desc) > h->size - h->cur)
    {
        printk(XENLOG_G_WARNING
               "HVM%d.%d restore: not enough data left to read %u xsave bytes\n",
               d->domain_id, vcpuid, desc->length);
        return -ENODATA;
    }
    if ( desc->length < offsetof(struct hvm_hw_cpu_xsave, save_area) +
                        XSTATE_AREA_MIN_SIZE )
    {
        printk(XENLOG_G_WARNING
               "HVM%d.%d restore mismatch: xsave length %u < %zu\n",
               d->domain_id, vcpuid, desc->length,
               offsetof(struct hvm_hw_cpu_xsave,
                        save_area) + XSTATE_AREA_MIN_SIZE);
        return -EINVAL;
    }
    h->cur += sizeof (*desc);
    desc_start = h->cur;

    ctxt = (struct hvm_hw_cpu_xsave *)&h->data[h->cur];
    h->cur += desc->length;

    err = validate_xstate(ctxt->xcr0, ctxt->xcr0_accum,
                          (const void *)&ctxt->save_area.xsave_hdr);
    if ( err )
    {
        printk(XENLOG_G_WARNING
               "HVM%d.%d restore: inconsistent xsave state (feat=%#"PRIx64
               " accum=%#"PRIx64" xcr0=%#"PRIx64" bv=%#"PRIx64" err=%d)\n",
               d->domain_id, vcpuid, ctxt->xfeature_mask, ctxt->xcr0_accum,
               ctxt->xcr0, ctxt->save_area.xsave_hdr.xstate_bv, err);
        return err;
    }
    size = HVM_CPU_XSAVE_SIZE(ctxt->xcr0_accum);
    desc_length = desc->length;
    if ( desc_length > size )
    {
        /*
         * Xen 4.3.0, 4.2.3 and older used to send longer-than-needed
         * xsave regions.  Permit loading the record if the extra data
         * is all zero.
         */
        for ( i = size; i < desc->length; i++ )
        {
            if ( h->data[desc_start + i] )
            {
                printk(XENLOG_G_WARNING
                       "HVM%d.%u restore mismatch: xsave length %#x > %#x (non-zero data at %#x)\n",
                       d->domain_id, vcpuid, desc->length, size, i);
                return -EOPNOTSUPP;
            }
        }
        printk(XENLOG_G_WARNING
               "HVM%d.%u restore mismatch: xsave length %#x > %#x\n",
               d->domain_id, vcpuid, desc->length, size);
        /* Rewind desc_length to ignore the extraneous zeros. */
        desc_length = size;
    }

    if ( xsave_area_compressed((const void *)&ctxt->save_area) )
    {
        printk(XENLOG_G_WARNING
               "HVM%d.%u restore: compressed xsave state not supported\n",
               d->domain_id, vcpuid);
        return -EOPNOTSUPP;
    }
    else if ( desc_length != size )
    {
        printk(XENLOG_G_WARNING
               "HVM%d.%u restore mismatch: xsave length %#x != %#x\n",
               d->domain_id, vcpuid, desc_length, size);
        return -EINVAL;
    }
    /* Checking finished */

    v->arch.xcr0 = ctxt->xcr0;
    v->arch.xcr0_accum = ctxt->xcr0_accum;
    if ( ctxt->xcr0_accum & XSTATE_NONLAZY )
        v->arch.nonlazy_xstate_used = 1;
    compress_xsave_states(v, &ctxt->save_area,
                          size - offsetof(struct hvm_hw_cpu_xsave, save_area));

    return 0;
}

#define HVM_CPU_MSR_SIZE(cnt) offsetof(struct hvm_msr, msr[cnt])
static unsigned int __read_mostly msr_count_max;

static int hvm_save_cpu_msrs(struct domain *d, hvm_domain_context_t *h)
{
    struct vcpu *v;

    for_each_vcpu ( d, v )
    {
        struct hvm_msr *ctxt;
        unsigned int i;

        if ( _hvm_init_entry(h, CPU_MSR_CODE, v->vcpu_id,
                             HVM_CPU_MSR_SIZE(msr_count_max)) )
            return 1;
        ctxt = (struct hvm_msr *)&h->data[h->cur];
        ctxt->count = 0;

        if ( hvm_funcs.save_msr )
            hvm_funcs.save_msr(v, ctxt);

        ASSERT(ctxt->count <= msr_count_max);

        for ( i = 0; i < ctxt->count; ++i )
            ctxt->msr[i]._rsvd = 0;

        if ( ctxt->count )
            h->cur += HVM_CPU_MSR_SIZE(ctxt->count);
        else
            h->cur -= sizeof(struct hvm_save_descriptor);
    }

    return 0;
}

static int hvm_load_cpu_msrs(struct domain *d, hvm_domain_context_t *h)
{
    unsigned int i, vcpuid = hvm_load_instance(h);
    struct vcpu *v;
    const struct hvm_save_descriptor *desc;
    struct hvm_msr *ctxt;
    int err = 0;

    if ( vcpuid >= d->max_vcpus || (v = d->vcpu[vcpuid]) == NULL )
    {
        dprintk(XENLOG_G_ERR, "HVM restore: dom%d has no vcpu%u\n",
                d->domain_id, vcpuid);
        return -EINVAL;
    }

    /* Customized checking for entry since our entry is of variable length */
    desc = (struct hvm_save_descriptor *)&h->data[h->cur];
    if ( sizeof (*desc) > h->size - h->cur)
    {
        printk(XENLOG_G_WARNING
               "HVM%d.%d restore: not enough data left to read MSR descriptor\n",
               d->domain_id, vcpuid);
        return -ENODATA;
    }
    if ( desc->length + sizeof (*desc) > h->size - h->cur)
    {
        printk(XENLOG_G_WARNING
               "HVM%d.%d restore: not enough data left to read %u MSR bytes\n",
               d->domain_id, vcpuid, desc->length);
        return -ENODATA;
    }
    if ( desc->length < HVM_CPU_MSR_SIZE(1) )
    {
        printk(XENLOG_G_WARNING
               "HVM%d.%d restore mismatch: MSR length %u < %zu\n",
               d->domain_id, vcpuid, desc->length, HVM_CPU_MSR_SIZE(1));
        return -EINVAL;
    }

    h->cur += sizeof(*desc);
    ctxt = (struct hvm_msr *)&h->data[h->cur];
    h->cur += desc->length;

    if ( desc->length != HVM_CPU_MSR_SIZE(ctxt->count) )
    {
        printk(XENLOG_G_WARNING
               "HVM%d.%d restore mismatch: MSR length %u != %zu\n",
               d->domain_id, vcpuid, desc->length,
               HVM_CPU_MSR_SIZE(ctxt->count));
        return -EOPNOTSUPP;
    }

    for ( i = 0; i < ctxt->count; ++i )
        if ( ctxt->msr[i]._rsvd )
            return -EOPNOTSUPP;
    /* Checking finished */

    if ( hvm_funcs.load_msr )
        err = hvm_funcs.load_msr(v, ctxt);

    for ( i = 0; !err && i < ctxt->count; ++i )
    {
        switch ( ctxt->msr[i].index )
        {
        default:
            if ( !ctxt->msr[i]._rsvd )
                err = -ENXIO;
            break;
        }
    }

    return err;
}

/* We need variable length data chunks for XSAVE area and MSRs, hence
 * a custom declaration rather than HVM_REGISTER_SAVE_RESTORE.
 */
static int __init hvm_register_CPU_save_and_restore(void)
{
    hvm_register_savevm(CPU_XSAVE_CODE,
                        "CPU_XSAVE",
                        hvm_save_cpu_xsave_states,
                        hvm_load_cpu_xsave_states,
                        HVM_CPU_XSAVE_SIZE(xfeature_mask) +
                            sizeof(struct hvm_save_descriptor),
                        HVMSR_PER_VCPU);

    if ( hvm_funcs.init_msr )
        msr_count_max += hvm_funcs.init_msr();

    if ( msr_count_max )
        hvm_register_savevm(CPU_MSR_CODE,
                            "CPU_MSR",
                            hvm_save_cpu_msrs,
                            hvm_load_cpu_msrs,
                            HVM_CPU_MSR_SIZE(msr_count_max) +
                                sizeof(struct hvm_save_descriptor),
                            HVMSR_PER_VCPU);

    return 0;
}
__initcall(hvm_register_CPU_save_and_restore);

int hvm_vcpu_initialise(struct vcpu *v)
{
    int rc;
    struct domain *d = v->domain;

    hvm_asid_flush_vcpu(v);

    spin_lock_init(&v->arch.hvm_vcpu.tm_lock);
    INIT_LIST_HEAD(&v->arch.hvm_vcpu.tm_list);

    rc = hvm_vcpu_cacheattr_init(v); /* teardown: vcpu_cacheattr_destroy */
    if ( rc != 0 )
        goto fail1;

    /* NB: vlapic_init must be called before hvm_funcs.vcpu_initialise */
    rc = vlapic_init(v);
    if ( rc != 0 ) /* teardown: vlapic_destroy */
        goto fail2;

    if ( (rc = hvm_funcs.vcpu_initialise(v)) != 0 ) /* teardown: hvm_funcs.vcpu_destroy */
        goto fail3;

    softirq_tasklet_init(
        &v->arch.hvm_vcpu.assert_evtchn_irq_tasklet,
        (void(*)(unsigned long))hvm_assert_evtchn_irq,
        (unsigned long)v);

    v->arch.hvm_vcpu.inject_trap.vector = -1;

    if ( is_pvh_domain(d) )
    {
        /* This is for hvm_long_mode_enabled(v). */
        v->arch.hvm_vcpu.guest_efer = EFER_LMA | EFER_LME;
        return 0;
    }

    rc = setup_compat_arg_xlat(v); /* teardown: free_compat_arg_xlat() */
    if ( rc != 0 )
        goto fail4;

    if ( nestedhvm_enabled(d)
         && (rc = nestedhvm_vcpu_initialise(v)) < 0 ) /* teardown: nestedhvm_vcpu_destroy */
        goto fail5;

    rc = hvm_all_ioreq_servers_add_vcpu(d, v);
    if ( rc != 0 )
        goto fail6;

    if ( v->vcpu_id == 0 )
    {
        /* NB. All these really belong in hvm_domain_initialise(). */
        pmtimer_init(v);
        hpet_init(d);
 
        /* Init guest TSC to start from zero. */
        hvm_set_guest_tsc(v, 0);
    }

    hvm_update_guest_vendor(v);

    return 0;

 fail6:
    nestedhvm_vcpu_destroy(v);
 fail5:
    free_compat_arg_xlat(v);
 fail4:
    hvm_funcs.vcpu_destroy(v);
 fail3:
    vlapic_destroy(v);
 fail2:
    hvm_vcpu_cacheattr_destroy(v);
 fail1:
    return rc;
}

void hvm_vcpu_destroy(struct vcpu *v)
{
    viridian_vcpu_deinit(v);

    hvm_all_ioreq_servers_remove_vcpu(v->domain, v);

    if ( hvm_altp2m_supported() )
        altp2m_vcpu_destroy(v);

    nestedhvm_vcpu_destroy(v);

    free_compat_arg_xlat(v);

    tasklet_kill(&v->arch.hvm_vcpu.assert_evtchn_irq_tasklet);
    hvm_vcpu_cacheattr_destroy(v);

    if ( is_hvm_vcpu(v) )
        vlapic_destroy(v);

    hvm_funcs.vcpu_destroy(v);
}

void hvm_vcpu_down(struct vcpu *v)
{
    struct domain *d = v->domain;
    int online_count = 0;

    /* Doesn't halt us immediately, but we'll never return to guest context. */
    set_bit(_VPF_down, &v->pause_flags);
    vcpu_sleep_nosync(v);

    /* Any other VCPUs online? ... */
    domain_lock(d);
    for_each_vcpu ( d, v )
        if ( !(v->pause_flags & VPF_down) )
            online_count++;
    domain_unlock(d);

    /* ... Shut down the domain if not. */
    if ( online_count == 0 )
    {
        gdprintk(XENLOG_INFO, "All CPUs offline -- powering off.\n");
        domain_shutdown(d, SHUTDOWN_poweroff);
    }
}

void hvm_hlt(unsigned long rflags)
{
    struct vcpu *curr = current;

    if ( hvm_event_pending(curr) )
        return;

    /*
     * If we halt with interrupts disabled, that's a pretty sure sign that we
     * want to shut down. In a real processor, NMIs are the only way to break
     * out of this.
     */
    if ( unlikely(!(rflags & X86_EFLAGS_IF)) )
        return hvm_vcpu_down(curr);

    do_sched_op(SCHEDOP_block, guest_handle_from_ptr(NULL, void));

    HVMTRACE_1D(HLT, /* pending = */ vcpu_runnable(curr));
}

void hvm_triple_fault(void)
{
    struct vcpu *v = current;
    struct domain *d = v->domain;
    u8 reason = d->arch.hvm_domain.params[HVM_PARAM_TRIPLE_FAULT_REASON];

    gprintk(XENLOG_INFO,
            "Triple fault - invoking HVM shutdown action %d\n",
            reason);
    vcpu_show_execution_state(v);
    domain_shutdown(d, reason);
}

void hvm_inject_trap(const struct hvm_trap *trap)
{
    struct vcpu *curr = current;

    if ( nestedhvm_enabled(curr->domain) &&
         !nestedhvm_vmswitch_in_progress(curr) &&
         nestedhvm_vcpu_in_guestmode(curr) &&
         nhvm_vmcx_guest_intercepts_trap(
             curr, trap->vector, trap->error_code) )
    {
        enum nestedhvm_vmexits nsret;

        nsret = nhvm_vcpu_vmexit_trap(curr, trap);

        switch ( nsret )
        {
        case NESTEDHVM_VMEXIT_DONE:
        case NESTEDHVM_VMEXIT_ERROR: /* L1 guest will crash L2 guest */
            return;
        case NESTEDHVM_VMEXIT_HOST:
        case NESTEDHVM_VMEXIT_CONTINUE:
        case NESTEDHVM_VMEXIT_FATALERROR:
        default:
            gdprintk(XENLOG_ERR, "unexpected nestedhvm error %i\n", nsret);
            return;
        }
    }

    hvm_funcs.inject_trap(trap);
}

void hvm_inject_hw_exception(unsigned int trapnr, int errcode)
{
    struct hvm_trap trap = {
        .vector = trapnr,
        .type = X86_EVENTTYPE_HW_EXCEPTION,
        .error_code = errcode };
    hvm_inject_trap(&trap);
}

void hvm_inject_page_fault(int errcode, unsigned long cr2)
{
    struct hvm_trap trap = {
        .vector = TRAP_page_fault,
        .type = X86_EVENTTYPE_HW_EXCEPTION,
        .error_code = errcode,
        .cr2 = cr2 };
    hvm_inject_trap(&trap);
}

int hvm_hap_nested_page_fault(paddr_t gpa, unsigned long gla,
                              struct npfec npfec)
{
    unsigned long gfn = gpa >> PAGE_SHIFT;
    p2m_type_t p2mt;
    p2m_access_t p2ma;
    mfn_t mfn;
    struct vcpu *curr = current;
    struct domain *currd = curr->domain;
    struct p2m_domain *p2m, *hostp2m;
    int rc, fall_through = 0, paged = 0;
    int sharing_enomem = 0;
    vm_event_request_t *req_ptr = NULL;
    bool_t ap2m_active, sync = 0;

    /* On Nested Virtualization, walk the guest page table.
     * If this succeeds, all is fine.
     * If this fails, inject a nested page fault into the guest.
     */
    if ( nestedhvm_enabled(currd)
        && nestedhvm_vcpu_in_guestmode(curr)
        && nestedhvm_paging_mode_hap(curr) )
    {
        int rv;

        /* The vcpu is in guest mode and the l1 guest
         * uses hap. That means 'gpa' is in l2 guest
         * physical address space.
         * Fix the nested p2m or inject nested page fault
         * into l1 guest if not fixable. The algorithm is
         * the same as for shadow paging.
         */

         rv = nestedhvm_hap_nested_page_fault(curr, &gpa,
                                              npfec.read_access,
                                              npfec.write_access,
                                              npfec.insn_fetch);
        switch (rv) {
        case NESTEDHVM_PAGEFAULT_DONE:
        case NESTEDHVM_PAGEFAULT_RETRY:
            return 1;
        case NESTEDHVM_PAGEFAULT_L1_ERROR:
            /* An error occured while translating gpa from
             * l2 guest address to l1 guest address. */
            return 0;
        case NESTEDHVM_PAGEFAULT_INJECT:
            return -1;
        case NESTEDHVM_PAGEFAULT_MMIO:
            if ( !handle_mmio() )
                hvm_inject_hw_exception(TRAP_gp_fault, 0);
            return 1;
        case NESTEDHVM_PAGEFAULT_L0_ERROR:
            /* gpa is now translated to l1 guest address, update gfn. */
            gfn = gpa >> PAGE_SHIFT;
            break;
        }
    }

    /*
     * No need to do the P2M lookup for internally handled MMIO, benefiting
     * - 32-bit WinXP (& older Windows) on AMD CPUs for LAPIC accesses,
     * - newer Windows (like Server 2012) for HPET accesses.
     */
    if ( !nestedhvm_vcpu_in_guestmode(curr)
         && is_hvm_domain(currd)
         && hvm_mmio_internal(gpa) )
    {
        if ( !handle_mmio_with_translation(gla, gpa >> PAGE_SHIFT, npfec) )
            hvm_inject_hw_exception(TRAP_gp_fault, 0);
        rc = 1;
        goto out;
    }

    ap2m_active = altp2m_active(currd);

    /*
     * Take a lock on the host p2m speculatively, to avoid potential
     * locking order problems later and to handle unshare etc.
     */
    hostp2m = p2m_get_hostp2m(currd);
    mfn = get_gfn_type_access(hostp2m, gfn, &p2mt, &p2ma,
                              P2M_ALLOC | (npfec.write_access ? P2M_UNSHARE : 0),
                              NULL);

    if ( ap2m_active )
    {
        if ( p2m_altp2m_lazy_copy(curr, gpa, gla, npfec, &p2m) )
        {
            /* entry was lazily copied from host -- retry */
            __put_gfn(hostp2m, gfn);
            rc = 1;
            goto out;
        }

        mfn = get_gfn_type_access(p2m, gfn, &p2mt, &p2ma, 0, NULL);
    }
    else
        p2m = hostp2m;

    /* Check access permissions first, then handle faults */
    if ( !mfn_eq(mfn, INVALID_MFN) )
    {
        bool_t violation;

        /* If the access is against the permissions, then send to vm_event */
        switch (p2ma)
        {
        case p2m_access_n:
        case p2m_access_n2rwx:
        default:
            violation = npfec.read_access || npfec.write_access || npfec.insn_fetch;
            break;
        case p2m_access_r:
            violation = npfec.write_access || npfec.insn_fetch;
            break;
        case p2m_access_w:
            violation = npfec.read_access || npfec.insn_fetch;
            break;
        case p2m_access_x:
            violation = npfec.read_access || npfec.write_access;
            break;
        case p2m_access_rx:
        case p2m_access_rx2rw:
            violation = npfec.write_access;
            break;
        case p2m_access_wx:
            violation = npfec.read_access;
            break;
        case p2m_access_rw:
            violation = npfec.insn_fetch;
            break;
        case p2m_access_rwx:
            violation = 0;
            break;
        }

        if ( violation )
        {
            /* Should #VE be emulated for this fault? */
            if ( p2m_is_altp2m(p2m) && !cpu_has_vmx_virt_exceptions )
            {
                bool_t sve;

                p2m->get_entry(p2m, gfn, &p2mt, &p2ma, 0, NULL, &sve);

                if ( !sve && altp2m_vcpu_emulate_ve(curr) )
                {
                    rc = 1;
                    goto out_put_gfn;
                }
            }

            sync = p2m_mem_access_check(gpa, gla, npfec, &req_ptr);

            if ( !sync )
                fall_through = 1;
            else
            {
                /* Rights not promoted (aka. sync event), work here is done */
                rc = 1;
                goto out_put_gfn;
            }
        }
    }

    /*
     * If this GFN is emulated MMIO or marked as read-only, pass the fault
     * to the mmio handler.
     */
    if ( (p2mt == p2m_mmio_dm) || 
         (npfec.write_access &&
          (p2m_is_discard_write(p2mt) || (p2mt == p2m_ioreq_server))) )
    {
        __put_gfn(p2m, gfn);
        if ( ap2m_active )
            __put_gfn(hostp2m, gfn);

        rc = 0;
        if ( unlikely(is_pvh_domain(currd)) )
            goto out;

        if ( !handle_mmio_with_translation(gla, gpa >> PAGE_SHIFT, npfec) )
            hvm_inject_hw_exception(TRAP_gp_fault, 0);
        rc = 1;
        goto out;
    }

    /* Check if the page has been paged out */
    if ( p2m_is_paged(p2mt) || (p2mt == p2m_ram_paging_out) )
        paged = 1;

    /* Mem sharing: unshare the page and try again */
    if ( npfec.write_access && (p2mt == p2m_ram_shared) )
    {
        ASSERT(p2m_is_hostp2m(p2m));
        sharing_enomem = 
            (mem_sharing_unshare_page(currd, gfn, 0) < 0);
        rc = 1;
        goto out_put_gfn;
    }
 
    /* Spurious fault? PoD and log-dirty also take this path. */
    if ( p2m_is_ram(p2mt) )
    {
        rc = 1;
        /*
         * Page log dirty is always done with order 0. If this mfn resides in
         * a large page, we do not change other pages type within that large
         * page.
         */
        if ( npfec.write_access )
        {
            paging_mark_dirty(currd, mfn_x(mfn));
            /*
             * If p2m is really an altp2m, unlock here to avoid lock ordering
             * violation when the change below is propagated from host p2m.
             */
            if ( ap2m_active )
                __put_gfn(p2m, gfn);
            p2m_change_type_one(currd, gfn, p2m_ram_logdirty, p2m_ram_rw);
            __put_gfn(ap2m_active ? hostp2m : p2m, gfn);

            goto out;
        }
        goto out_put_gfn;
    }

    if ( (p2mt == p2m_mmio_direct) && is_hardware_domain(currd) &&
         npfec.write_access && npfec.present &&
         (hvm_emulate_one_mmio(mfn_x(mfn), gla) == X86EMUL_OKAY) )
    {
        rc = 1;
        goto out_put_gfn;
    }

    /* If we fell through, the vcpu will retry now that access restrictions have
     * been removed. It may fault again if the p2m entry type still requires so.
     * Otherwise, this is an error condition. */
    rc = fall_through;

 out_put_gfn:
    __put_gfn(p2m, gfn);
    if ( ap2m_active )
        __put_gfn(hostp2m, gfn);
 out:
    /* All of these are delayed until we exit, since we might 
     * sleep on event ring wait queues, and we must not hold
     * locks in such circumstance */
    if ( paged )
        p2m_mem_paging_populate(currd, gfn);
    if ( sharing_enomem )
    {
        int rv;
        if ( (rv = mem_sharing_notify_enomem(currd, gfn, 1)) < 0 )
        {
            gdprintk(XENLOG_ERR, "Domain %hu attempt to unshare "
                     "gfn %lx, ENOMEM and no helper (rc %d)\n",
                     currd->domain_id, gfn, rv);
            /* Crash the domain */
            rc = 0;
        }
    }
    if ( req_ptr )
    {
        if ( monitor_traps(curr, sync, req_ptr) < 0 )
            rc = 0;

        xfree(req_ptr);
    }
    return rc;
}

int hvm_handle_xsetbv(u32 index, u64 new_bv)
{
    int rc;

    hvm_monitor_crX(XCR0, new_bv, current->arch.xcr0);

    rc = handle_xsetbv(index, new_bv);
    if ( rc )
        hvm_inject_hw_exception(TRAP_gp_fault, 0);

    return rc;
}

int hvm_set_efer(uint64_t value)
{
    struct vcpu *v = current;
    const char *errstr;

    value &= ~EFER_LMA;

    errstr = hvm_efer_valid(v, value, -1);
    if ( errstr )
    {
        printk(XENLOG_G_WARNING
               "%pv: Invalid EFER update: %#"PRIx64" -> %#"PRIx64" - %s\n",
               v, v->arch.hvm_vcpu.guest_efer, value, errstr);
        hvm_inject_hw_exception(TRAP_gp_fault, 0);
        return X86EMUL_EXCEPTION;
    }

    if ( ((value ^ v->arch.hvm_vcpu.guest_efer) & EFER_LME) &&
         hvm_paging_enabled(v) )
    {
        gdprintk(XENLOG_WARNING,
                 "Trying to change EFER.LME with paging enabled\n");
        hvm_inject_hw_exception(TRAP_gp_fault, 0);
        return X86EMUL_EXCEPTION;
    }

    if ( (value & EFER_LME) && !(v->arch.hvm_vcpu.guest_efer & EFER_LME) )
    {
        struct segment_register cs;

        hvm_get_segment_register(v, x86_seg_cs, &cs);

        /*
         * %cs may be loaded with both .D and .L set in legacy mode, and both
         * are captured in the VMCS/VMCB.
         *
         * If a guest does this and then tries to transition into long mode,
         * the vmentry from setting LME fails due to invalid guest state,
         * because %cr0.PG is still clear.
         *
         * When LME becomes set, clobber %cs.L to keep the guest firmly in
         * compatibility mode until it reloads %cs itself.
         */
        if ( cs.attr.fields.l )
        {
            cs.attr.fields.l = 0;
            hvm_set_segment_register(v, x86_seg_cs, &cs);
        }
    }

    if ( nestedhvm_enabled(v->domain) && cpu_has_svm &&
       ((value & EFER_SVME) == 0 ) &&
       ((value ^ v->arch.hvm_vcpu.guest_efer) & EFER_SVME) )
    {
        /* Cleared EFER.SVME: Flush all nestedp2m tables */
        p2m_flush_nestedp2m(v->domain);
        nestedhvm_vcpu_reset(v);
    }

    value |= v->arch.hvm_vcpu.guest_efer & EFER_LMA;
    v->arch.hvm_vcpu.guest_efer = value;
    hvm_update_guest_efer(v);

    return X86EMUL_OKAY;
}

/* Exit UC mode only if all VCPUs agree on MTRR/PAT and are not in no_fill. */
static bool_t domain_exit_uc_mode(struct vcpu *v)
{
    struct domain *d = v->domain;
    struct vcpu *vs;

    for_each_vcpu ( d, vs )
    {
        if ( (vs == v) || !vs->is_initialised )
            continue;
        if ( (vs->arch.hvm_vcpu.cache_mode == NO_FILL_CACHE_MODE) ||
             mtrr_pat_not_equal(vs, v) )
            return 0;
    }

    return 1;
}

static void hvm_set_uc_mode(struct vcpu *v, bool_t is_in_uc_mode)
{
    v->domain->arch.hvm_domain.is_in_uc_mode = is_in_uc_mode;
    shadow_blow_tables_per_domain(v->domain);
}

int hvm_mov_to_cr(unsigned int cr, unsigned int gpr)
{
    struct vcpu *curr = current;
    unsigned long val, *reg;

    if ( (reg = decode_register(gpr, guest_cpu_user_regs(), 0)) == NULL )
    {
        gdprintk(XENLOG_ERR, "invalid gpr: %u\n", gpr);
        goto exit_and_crash;
    }

    val = *reg;
    HVMTRACE_LONG_2D(CR_WRITE, cr, TRC_PAR_LONG(val));
    HVM_DBG_LOG(DBG_LEVEL_1, "CR%u, value = %lx", cr, val);

    switch ( cr )
    {
    case 0:
        return hvm_set_cr0(val, 1);

    case 3:
        return hvm_set_cr3(val, 1);

    case 4:
        return hvm_set_cr4(val, 1);

    case 8:
        vlapic_set_reg(vcpu_vlapic(curr), APIC_TASKPRI, ((val & 0x0f) << 4));
        break;

    default:
        gdprintk(XENLOG_ERR, "invalid cr: %d\n", cr);
        goto exit_and_crash;
    }

    return X86EMUL_OKAY;

 exit_and_crash:
    domain_crash(curr->domain);
    return X86EMUL_UNHANDLEABLE;
}

int hvm_mov_from_cr(unsigned int cr, unsigned int gpr)
{
    struct vcpu *curr = current;
    unsigned long val = 0, *reg;

    if ( (reg = decode_register(gpr, guest_cpu_user_regs(), 0)) == NULL )
    {
        gdprintk(XENLOG_ERR, "invalid gpr: %u\n", gpr);
        goto exit_and_crash;
    }

    switch ( cr )
    {
    case 0:
    case 2:
    case 3:
    case 4:
        val = curr->arch.hvm_vcpu.guest_cr[cr];
        break;
    case 8:
        val = (vlapic_get_reg(vcpu_vlapic(curr), APIC_TASKPRI) & 0xf0) >> 4;
        break;
    default:
        gdprintk(XENLOG_ERR, "invalid cr: %u\n", cr);
        goto exit_and_crash;
    }

    *reg = val;
    HVMTRACE_LONG_2D(CR_READ, cr, TRC_PAR_LONG(val));
    HVM_DBG_LOG(DBG_LEVEL_VMMU, "CR%u, value = %lx", cr, val);

    return X86EMUL_OKAY;

 exit_and_crash:
    domain_crash(curr->domain);
    return X86EMUL_UNHANDLEABLE;
}

void hvm_shadow_handle_cd(struct vcpu *v, unsigned long value)
{
    if ( value & X86_CR0_CD )
    {
        /* Entering no fill cache mode. */
        spin_lock(&v->domain->arch.hvm_domain.uc_lock);
        v->arch.hvm_vcpu.cache_mode = NO_FILL_CACHE_MODE;

        if ( !v->domain->arch.hvm_domain.is_in_uc_mode )
        {
            domain_pause_nosync(v->domain);

            /* Flush physical caches. */
            flush_all(FLUSH_CACHE);
            hvm_set_uc_mode(v, 1);

            domain_unpause(v->domain);
        }
        spin_unlock(&v->domain->arch.hvm_domain.uc_lock);
    }
    else if ( !(value & X86_CR0_CD) &&
              (v->arch.hvm_vcpu.cache_mode == NO_FILL_CACHE_MODE) )
    {
        /* Exit from no fill cache mode. */
        spin_lock(&v->domain->arch.hvm_domain.uc_lock);
        v->arch.hvm_vcpu.cache_mode = NORMAL_CACHE_MODE;

        if ( domain_exit_uc_mode(v) )
            hvm_set_uc_mode(v, 0);

        spin_unlock(&v->domain->arch.hvm_domain.uc_lock);
    }
}

static void hvm_update_cr(struct vcpu *v, unsigned int cr, unsigned long value)
{
    v->arch.hvm_vcpu.guest_cr[cr] = value;
    nestedhvm_set_cr(v, cr, value);
    hvm_update_guest_cr(v, cr);
}

int hvm_set_cr0(unsigned long value, bool_t may_defer)
{
    struct vcpu *v = current;
    struct domain *d = v->domain;
    unsigned long gfn, old_value = v->arch.hvm_vcpu.guest_cr[0];
    struct page_info *page;

    HVM_DBG_LOG(DBG_LEVEL_VMMU, "Update CR0 value = %lx", value);

    if ( (u32)value != value )
    {
        HVM_DBG_LOG(DBG_LEVEL_1,
                    "Guest attempts to set upper 32 bits in CR0: %lx",
                    value);
        goto gpf;
    }

    value &= ~HVM_CR0_GUEST_RESERVED_BITS;

    /* ET is reserved and should be always be 1. */
    value |= X86_CR0_ET;

    if ( !nestedhvm_vmswitch_in_progress(v) &&
         (value & (X86_CR0_PE | X86_CR0_PG)) == X86_CR0_PG )
        goto gpf;

    /* A pvh is not expected to change to real mode. */
    if ( is_pvh_domain(d) &&
         (value & (X86_CR0_PE | X86_CR0_PG)) != (X86_CR0_PG | X86_CR0_PE) )
    {
        printk(XENLOG_G_WARNING
               "PVH attempting to turn off PE/PG. CR0:%lx\n", value);
        goto gpf;
    }

    if ( may_defer && unlikely(v->domain->arch.monitor.write_ctrlreg_enabled &
                               monitor_ctrlreg_bitmask(VM_EVENT_X86_CR0)) )
    {
        ASSERT(v->arch.vm_event);

        if ( hvm_monitor_crX(CR0, value, old_value) )
        {
            /* The actual write will occur in hvm_do_resume(), if permitted. */
            v->arch.vm_event->write_data.do_write.cr0 = 1;
            v->arch.vm_event->write_data.cr0 = value;

            return X86EMUL_OKAY;
        }
    }

    if ( (value & X86_CR0_PG) && !(old_value & X86_CR0_PG) )
    {
        if ( v->arch.hvm_vcpu.guest_efer & EFER_LME )
        {
            if ( !(v->arch.hvm_vcpu.guest_cr[4] & X86_CR4_PAE) &&
                 !nestedhvm_vmswitch_in_progress(v) )
            {
                HVM_DBG_LOG(DBG_LEVEL_1, "Enable paging before PAE enable");
                goto gpf;
            }
            HVM_DBG_LOG(DBG_LEVEL_1, "Enabling long mode");
            v->arch.hvm_vcpu.guest_efer |= EFER_LMA;
            hvm_update_guest_efer(v);
        }

        if ( !paging_mode_hap(d) )
        {
            /* The guest CR3 must be pointing to the guest physical. */
            gfn = v->arch.hvm_vcpu.guest_cr[3]>>PAGE_SHIFT;
            page = get_page_from_gfn(d, gfn, NULL, P2M_ALLOC);
            if ( !page )
            {
                gdprintk(XENLOG_ERR, "Invalid CR3 value = %lx\n",
                         v->arch.hvm_vcpu.guest_cr[3]);
                domain_crash(d);
                return X86EMUL_UNHANDLEABLE;
            }

            /* Now arch.guest_table points to machine physical. */
            v->arch.guest_table = pagetable_from_page(page);

            HVM_DBG_LOG(DBG_LEVEL_VMMU, "Update CR3 value = %lx, mfn = %lx",
                        v->arch.hvm_vcpu.guest_cr[3], page_to_mfn(page));
        }
    }
    else if ( !(value & X86_CR0_PG) && (old_value & X86_CR0_PG) )
    {
        if ( hvm_pcid_enabled(v) )
        {
            HVM_DBG_LOG(DBG_LEVEL_1, "Guest attempts to clear CR0.PG "
                        "while CR4.PCIDE=1");
            goto gpf;
        }

        /* When CR0.PG is cleared, LMA is cleared immediately. */
        if ( hvm_long_mode_enabled(v) )
        {
            v->arch.hvm_vcpu.guest_efer &= ~EFER_LMA;
            hvm_update_guest_efer(v);
        }

        if ( !paging_mode_hap(d) )
        {
            put_page(pagetable_get_page(v->arch.guest_table));
            v->arch.guest_table = pagetable_null();
        }
    }

    if ( ((value ^ old_value) & X86_CR0_CD) &&
         iommu_enabled && hvm_funcs.handle_cd &&
         (!rangeset_is_empty(d->iomem_caps) ||
          !rangeset_is_empty(d->arch.ioport_caps) ||
          has_arch_pdevs(d)) )
        hvm_funcs.handle_cd(v, value);

    hvm_update_cr(v, 0, value);

    if ( (value ^ old_value) & X86_CR0_PG ) {
        if ( !nestedhvm_vmswitch_in_progress(v) && nestedhvm_vcpu_in_guestmode(v) )
            paging_update_nestedmode(v);
        else
            paging_update_paging_modes(v);
    }

    return X86EMUL_OKAY;

 gpf:
    hvm_inject_hw_exception(TRAP_gp_fault, 0);
    return X86EMUL_EXCEPTION;
}

int hvm_set_cr3(unsigned long value, bool_t may_defer)
{
    struct vcpu *v = current;
    struct page_info *page;
    unsigned long old = v->arch.hvm_vcpu.guest_cr[3];

    if ( may_defer && unlikely(v->domain->arch.monitor.write_ctrlreg_enabled &
                               monitor_ctrlreg_bitmask(VM_EVENT_X86_CR3)) )
    {
        ASSERT(v->arch.vm_event);

        if ( hvm_monitor_crX(CR3, value, old) )
        {
            /* The actual write will occur in hvm_do_resume(), if permitted. */
            v->arch.vm_event->write_data.do_write.cr3 = 1;
            v->arch.vm_event->write_data.cr3 = value;

            return X86EMUL_OKAY;
        }
    }

    if ( hvm_paging_enabled(v) && !paging_mode_hap(v->domain) &&
         (value != v->arch.hvm_vcpu.guest_cr[3]) )
    {
        /* Shadow-mode CR3 change. Check PDBR and update refcounts. */
        HVM_DBG_LOG(DBG_LEVEL_VMMU, "CR3 value = %lx", value);
        page = get_page_from_gfn(v->domain, value >> PAGE_SHIFT,
                                 NULL, P2M_ALLOC);
        if ( !page )
            goto bad_cr3;

        put_page(pagetable_get_page(v->arch.guest_table));
        v->arch.guest_table = pagetable_from_page(page);

        HVM_DBG_LOG(DBG_LEVEL_VMMU, "Update CR3 value = %lx", value);
    }

    v->arch.hvm_vcpu.guest_cr[3] = value;
    paging_update_cr3(v);
    return X86EMUL_OKAY;

 bad_cr3:
    gdprintk(XENLOG_ERR, "Invalid CR3\n");
    domain_crash(v->domain);
    return X86EMUL_UNHANDLEABLE;
}

int hvm_set_cr4(unsigned long value, bool_t may_defer)
{
    struct vcpu *v = current;
    unsigned long old_cr;

    if ( value & hvm_cr4_guest_reserved_bits(v, 0) )
    {
        HVM_DBG_LOG(DBG_LEVEL_1,
                    "Guest attempts to set reserved bit in CR4: %lx",
                    value);
        goto gpf;
    }

    if ( !(value & X86_CR4_PAE) )
    {
        if ( hvm_long_mode_enabled(v) )
        {
            HVM_DBG_LOG(DBG_LEVEL_1, "Guest cleared CR4.PAE while "
                        "EFER.LMA is set");
            goto gpf;
        }
        if ( is_pvh_vcpu(v) )
        {
            HVM_DBG_LOG(DBG_LEVEL_1, "32-bit PVH guest cleared CR4.PAE");
            goto gpf;
        }
    }

    old_cr = v->arch.hvm_vcpu.guest_cr[4];

    if ( (value & X86_CR4_PCIDE) && !(old_cr & X86_CR4_PCIDE) &&
         (!hvm_long_mode_enabled(v) ||
          (v->arch.hvm_vcpu.guest_cr[3] & 0xfff)) )
    {
        HVM_DBG_LOG(DBG_LEVEL_1, "Guest attempts to change CR4.PCIDE from "
                    "0 to 1 while either EFER.LMA=0 or CR3[11:0]!=000H");
        goto gpf;
    }

    if ( may_defer && unlikely(v->domain->arch.monitor.write_ctrlreg_enabled &
                               monitor_ctrlreg_bitmask(VM_EVENT_X86_CR4)) )
    {
        ASSERT(v->arch.vm_event);

        if ( hvm_monitor_crX(CR4, value, old_cr) )
        {
            /* The actual write will occur in hvm_do_resume(), if permitted. */
            v->arch.vm_event->write_data.do_write.cr4 = 1;
            v->arch.vm_event->write_data.cr4 = value;

            return X86EMUL_OKAY;
        }
    }

    hvm_update_cr(v, 4, value);

    /*
     * Modifying CR4.{PSE,PAE,PGE,SMEP}, or clearing CR4.PCIDE
     * invalidate all TLB entries.
     */
    if ( ((old_cr ^ value) &
          (X86_CR4_PSE | X86_CR4_PGE | X86_CR4_PAE | X86_CR4_SMEP)) ||
         (!(value & X86_CR4_PCIDE) && (old_cr & X86_CR4_PCIDE)) )
    {
        if ( !nestedhvm_vmswitch_in_progress(v) && nestedhvm_vcpu_in_guestmode(v) )
            paging_update_nestedmode(v);
        else
            paging_update_paging_modes(v);
    }

    return X86EMUL_OKAY;

 gpf:
    hvm_inject_hw_exception(TRAP_gp_fault, 0);
    return X86EMUL_EXCEPTION;
}

bool_t hvm_virtual_to_linear_addr(
    enum x86_segment seg,
    const struct segment_register *reg,
    unsigned long offset,
    unsigned int bytes,
    enum hvm_access_type access_type,
    unsigned int addr_size,
    unsigned long *linear_addr)
{
    unsigned long addr = offset, last_byte;
    bool_t okay = 0;

    if ( !(current->arch.hvm_vcpu.guest_cr[0] & X86_CR0_PE) )
    {
        /*
         * REAL MODE: Don't bother with segment access checks.
         * Certain of them are not done in native real mode anyway.
         */
        addr = (uint32_t)(addr + reg->base);
        last_byte = (uint32_t)addr + bytes - !!bytes;
        if ( last_byte < addr )
            goto out;
    }
    else if ( addr_size != 64 )
    {
        /*
         * COMPATIBILITY MODE: Apply segment checks and add base.
         */

        /*
         * Hardware truncates to 32 bits in compatibility mode.
         * It does not truncate to 16 bits in 16-bit address-size mode.
         */
        addr = (uint32_t)(addr + reg->base);

        /* Segment not valid for use (cooked meaning of .p)? */
        if ( !reg->attr.fields.p )
            goto out;

        switch ( access_type )
        {
        case hvm_access_read:
            if ( (reg->attr.fields.type & 0xa) == 0x8 )
                goto out; /* execute-only code segment */
            break;
        case hvm_access_write:
            if ( (reg->attr.fields.type & 0xa) != 0x2 )
                goto out; /* not a writable data segment */
            break;
        default:
            break;
        }

        last_byte = (uint32_t)offset + bytes - !!bytes;

        /* Is this a grows-down data segment? Special limit check if so. */
        if ( (reg->attr.fields.type & 0xc) == 0x4 )
        {
            /* Is upper limit 0xFFFF or 0xFFFFFFFF? */
            if ( !reg->attr.fields.db )
                last_byte = (uint16_t)last_byte;

            /* Check first byte and last byte against respective bounds. */
            if ( (offset <= reg->limit) || (last_byte < offset) )
                goto out;
        }
        else if ( (last_byte > reg->limit) || (last_byte < offset) )
            goto out; /* last byte is beyond limit or wraps 0xFFFFFFFF */
    }
    else
    {
        /*
         * LONG MODE: FS and GS add segment base. Addresses must be canonical.
         */

        if ( (seg == x86_seg_fs) || (seg == x86_seg_gs) )
            addr += reg->base;

        last_byte = addr + bytes - !!bytes;
        if ( !is_canonical_address(addr) || last_byte < addr ||
             !is_canonical_address(last_byte) )
            goto out;
    }

    /* All checks ok. */
    okay = 1;

 out:
    /*
     * Always return the correct linear address, even if a permission check
     * failed.  The permissions failure is not relevant to some callers.
     */
    *linear_addr = addr;
    return okay;
}

struct hvm_write_map {
    struct list_head list;
    struct page_info *page;
};

/* On non-NULL return, we leave this function holding an additional 
 * ref on the underlying mfn, if any */
static void *_hvm_map_guest_frame(unsigned long gfn, bool_t permanent,
                                  bool_t *writable)
{
    void *map;
    p2m_type_t p2mt;
    struct page_info *page;
    struct domain *d = current->domain;

    page = get_page_from_gfn(d, gfn, &p2mt,
                             writable ? P2M_UNSHARE : P2M_ALLOC);
    if ( (p2m_is_shared(p2mt) && writable) || !page )
    {
        if ( page )
            put_page(page);
        return NULL;
    }
    if ( p2m_is_paging(p2mt) )
    {
        put_page(page);
        p2m_mem_paging_populate(d, gfn);
        return NULL;
    }

    if ( writable )
    {
        if ( unlikely(p2m_is_discard_write(p2mt)) )
            *writable = 0;
        else if ( !permanent )
            paging_mark_dirty(d, page_to_mfn(page));
    }

    if ( !permanent )
        return __map_domain_page(page);

    if ( writable && *writable )
    {
        struct hvm_write_map *track = xmalloc(struct hvm_write_map);

        if ( !track )
        {
            put_page(page);
            return NULL;
        }
        track->page = page;
        spin_lock(&d->arch.hvm_domain.write_map.lock);
        list_add_tail(&track->list, &d->arch.hvm_domain.write_map.list);
        spin_unlock(&d->arch.hvm_domain.write_map.lock);
    }

    map = __map_domain_page_global(page);
    if ( !map )
        put_page(page);

    return map;
}

void *hvm_map_guest_frame_rw(unsigned long gfn, bool_t permanent,
                             bool_t *writable)
{
    *writable = 1;
    return _hvm_map_guest_frame(gfn, permanent, writable);
}

void *hvm_map_guest_frame_ro(unsigned long gfn, bool_t permanent)
{
    return _hvm_map_guest_frame(gfn, permanent, NULL);
}

void hvm_unmap_guest_frame(void *p, bool_t permanent)
{
    unsigned long mfn;
    struct page_info *page;

    if ( !p )
        return;

    mfn = domain_page_map_to_mfn(p);
    page = mfn_to_page(mfn);

    if ( !permanent )
        unmap_domain_page(p);
    else
    {
        struct domain *d = page_get_owner(page);
        struct hvm_write_map *track;

        unmap_domain_page_global(p);
        spin_lock(&d->arch.hvm_domain.write_map.lock);
        list_for_each_entry(track, &d->arch.hvm_domain.write_map.list, list)
            if ( track->page == page )
            {
                paging_mark_dirty(d, mfn);
                list_del(&track->list);
                xfree(track);
                break;
            }
        spin_unlock(&d->arch.hvm_domain.write_map.lock);
    }

    put_page(page);
}

void hvm_mapped_guest_frames_mark_dirty(struct domain *d)
{
    struct hvm_write_map *track;

    spin_lock(&d->arch.hvm_domain.write_map.lock);
    list_for_each_entry(track, &d->arch.hvm_domain.write_map.list, list)
        paging_mark_dirty(d, page_to_mfn(track->page));
    spin_unlock(&d->arch.hvm_domain.write_map.lock);
}

static void *hvm_map_entry(unsigned long va, bool_t *writable)
{
    unsigned long gfn;
    uint32_t pfec;
    char *v;

    if ( ((va & ~PAGE_MASK) + 8) > PAGE_SIZE )
    {
        gdprintk(XENLOG_ERR, "Descriptor table entry "
                 "straddles page boundary\n");
        goto fail;
    }

    /*
     * We're mapping on behalf of the segment-load logic, which might write
     * the accessed flags in the descriptors (in 32-bit mode), but we still
     * treat it as a kernel-mode read (i.e. no access checks).
     */
    pfec = PFEC_page_present;
    gfn = paging_gva_to_gfn(current, va, &pfec);
    if ( pfec & (PFEC_page_paged | PFEC_page_shared) )
        goto fail;

    v = hvm_map_guest_frame_rw(gfn, 0, writable);
    if ( v == NULL )
        goto fail;

    return v + (va & ~PAGE_MASK);

 fail:
    domain_crash(current->domain);
    return NULL;
}

static void hvm_unmap_entry(void *p)
{
    hvm_unmap_guest_frame(p, 0);
}

static int hvm_load_segment_selector(
    enum x86_segment seg, uint16_t sel, unsigned int eflags)
{
    struct segment_register desctab, cs, segr;
    struct desc_struct *pdesc, desc;
    u8 dpl, rpl, cpl;
    bool_t writable;
    int fault_type = TRAP_invalid_tss;
    struct vcpu *v = current;

    if ( eflags & X86_EFLAGS_VM )
    {
        segr.sel = sel;
        segr.base = (uint32_t)sel << 4;
        segr.limit = 0xffffu;
        segr.attr.bytes = 0xf3;
        hvm_set_segment_register(v, seg, &segr);
        return 0;
    }

    /* NULL selector? */
    if ( (sel & 0xfffc) == 0 )
    {
        if ( (seg == x86_seg_cs) || (seg == x86_seg_ss) )
            goto fail;
        memset(&segr, 0, sizeof(segr));
        segr.sel = sel;
        hvm_set_segment_register(v, seg, &segr);
        return 0;
    }

    /* LDT descriptor must be in the GDT. */
    if ( (seg == x86_seg_ldtr) && (sel & 4) )
        goto fail;

    hvm_get_segment_register(v, x86_seg_cs, &cs);
    hvm_get_segment_register(
        v, (sel & 4) ? x86_seg_ldtr : x86_seg_gdtr, &desctab);

    /* Segment not valid for use (cooked meaning of .p)? */
    if ( !desctab.attr.fields.p )
        goto fail;

    /* Check against descriptor table limit. */
    if ( ((sel & 0xfff8) + 7) > desctab.limit )
        goto fail;

    pdesc = hvm_map_entry(desctab.base + (sel & 0xfff8), &writable);
    if ( pdesc == NULL )
        goto hvm_map_fail;

    do {
        desc = *pdesc;

        /* LDT descriptor is a system segment. All others are code/data. */
        if ( (desc.b & (1u<<12)) == ((seg == x86_seg_ldtr) << 12) )
            goto unmap_and_fail;

        dpl = (desc.b >> 13) & 3;
        rpl = sel & 3;
        cpl = cs.sel & 3;

        switch ( seg )
        {
        case x86_seg_cs:
            /* Code segment? */
            if ( !(desc.b & _SEGMENT_CODE) )
                goto unmap_and_fail;
            /* Non-conforming segment: check DPL against RPL. */
            if ( !(desc.b & _SEGMENT_EC) && (dpl != rpl) )
                goto unmap_and_fail;
            break;
        case x86_seg_ss:
            /* Writable data segment? */
            if ( (desc.b & (_SEGMENT_CODE|_SEGMENT_WR)) != _SEGMENT_WR )
                goto unmap_and_fail;
            if ( (dpl != cpl) || (dpl != rpl) )
                goto unmap_and_fail;
            break;
        case x86_seg_ldtr:
            /* LDT system segment? */
            if ( (desc.b & _SEGMENT_TYPE) != (2u<<8) )
                goto unmap_and_fail;
            goto skip_accessed_flag;
        default:
            /* Readable code or data segment? */
            if ( (desc.b & (_SEGMENT_CODE|_SEGMENT_WR)) == _SEGMENT_CODE )
                goto unmap_and_fail;
            /*
             * Data or non-conforming code segment:
             * check DPL against RPL and CPL.
             */
            if ( ((desc.b & (_SEGMENT_EC|_SEGMENT_CODE)) !=
                  (_SEGMENT_EC|_SEGMENT_CODE))
                 && ((dpl < cpl) || (dpl < rpl)) )
                goto unmap_and_fail;
            break;
        }

        /* Segment present in memory? */
        if ( !(desc.b & _SEGMENT_P) )
        {
            fault_type = (seg != x86_seg_ss) ? TRAP_no_segment
                                             : TRAP_stack_error;
            goto unmap_and_fail;
        }
    } while ( !(desc.b & 0x100) && /* Ensure Accessed flag is set */
              writable && /* except if we are to discard writes */
              (cmpxchg(&pdesc->b, desc.b, desc.b | 0x100) != desc.b) );

    /* Force the Accessed flag in our local copy. */
    desc.b |= 0x100;

 skip_accessed_flag:
    hvm_unmap_entry(pdesc);

    segr.base = (((desc.b <<  0) & 0xff000000u) |
                 ((desc.b << 16) & 0x00ff0000u) |
                 ((desc.a >> 16) & 0x0000ffffu));
    segr.attr.bytes = (((desc.b >>  8) & 0x00ffu) |
                       ((desc.b >> 12) & 0x0f00u));
    segr.limit = (desc.b & 0x000f0000u) | (desc.a & 0x0000ffffu);
    if ( segr.attr.fields.g )
        segr.limit = (segr.limit << 12) | 0xfffu;
    segr.sel = sel;
    hvm_set_segment_register(v, seg, &segr);

    return 0;

 unmap_and_fail:
    hvm_unmap_entry(pdesc);
 fail:
    hvm_inject_hw_exception(fault_type, sel & 0xfffc);
 hvm_map_fail:
    return 1;
}

void hvm_task_switch(
    uint16_t tss_sel, enum hvm_task_switch_reason taskswitch_reason,
    int32_t errcode)
{
    struct vcpu *v = current;
    struct cpu_user_regs *regs = guest_cpu_user_regs();
    struct segment_register gdt, tr, prev_tr, segr;
    struct desc_struct *optss_desc = NULL, *nptss_desc = NULL, tss_desc;
    bool_t otd_writable, ntd_writable;
    unsigned long eflags;
    int exn_raised, rc;
    struct {
        u16 back_link,__blh;
        u32 esp0;
        u16 ss0, _0;
        u32 esp1;
        u16 ss1, _1;
        u32 esp2;
        u16 ss2, _2;
        u32 cr3, eip, eflags, eax, ecx, edx, ebx, esp, ebp, esi, edi;
        u16 es, _3, cs, _4, ss, _5, ds, _6, fs, _7, gs, _8, ldt, _9;
        u16 trace, iomap;
    } tss;

    hvm_get_segment_register(v, x86_seg_gdtr, &gdt);
    hvm_get_segment_register(v, x86_seg_tr, &prev_tr);

    if ( ((tss_sel & 0xfff8) + 7) > gdt.limit )
    {
        hvm_inject_hw_exception((taskswitch_reason == TSW_iret) ?
                             TRAP_invalid_tss : TRAP_gp_fault,
                             tss_sel & 0xfff8);
        goto out;
    }

    optss_desc = hvm_map_entry(gdt.base + (prev_tr.sel & 0xfff8),
                               &otd_writable);
    if ( optss_desc == NULL )
        goto out;

    nptss_desc = hvm_map_entry(gdt.base + (tss_sel & 0xfff8), &ntd_writable);
    if ( nptss_desc == NULL )
        goto out;

    tss_desc = *nptss_desc;
    tr.sel = tss_sel;
    tr.base = (((tss_desc.b <<  0) & 0xff000000u) |
               ((tss_desc.b << 16) & 0x00ff0000u) |
               ((tss_desc.a >> 16) & 0x0000ffffu));
    tr.attr.bytes = (((tss_desc.b >>  8) & 0x00ffu) |
                     ((tss_desc.b >> 12) & 0x0f00u));
    tr.limit = (tss_desc.b & 0x000f0000u) | (tss_desc.a & 0x0000ffffu);
    if ( tr.attr.fields.g )
        tr.limit = (tr.limit << 12) | 0xfffu;

    if ( tr.attr.fields.type != ((taskswitch_reason == TSW_iret) ? 0xb : 0x9) )
    {
        hvm_inject_hw_exception(
            (taskswitch_reason == TSW_iret) ? TRAP_invalid_tss : TRAP_gp_fault,
            tss_sel & 0xfff8);
        goto out;
    }

    if ( !tr.attr.fields.p )
    {
        hvm_inject_hw_exception(TRAP_no_segment, tss_sel & 0xfff8);
        goto out;
    }

    if ( tr.limit < (sizeof(tss)-1) )
    {
        hvm_inject_hw_exception(TRAP_invalid_tss, tss_sel & 0xfff8);
        goto out;
    }

    rc = hvm_copy_from_guest_virt(
        &tss, prev_tr.base, sizeof(tss), PFEC_page_present);
    if ( rc != HVMCOPY_okay )
        goto out;

    eflags = regs->eflags;
    if ( taskswitch_reason == TSW_iret )
        eflags &= ~X86_EFLAGS_NT;

    tss.eip    = regs->eip;
    tss.eflags = eflags;
    tss.eax    = regs->eax;
    tss.ecx    = regs->ecx;
    tss.edx    = regs->edx;
    tss.ebx    = regs->ebx;
    tss.esp    = regs->esp;
    tss.ebp    = regs->ebp;
    tss.esi    = regs->esi;
    tss.edi    = regs->edi;

    hvm_get_segment_register(v, x86_seg_es, &segr);
    tss.es = segr.sel;
    hvm_get_segment_register(v, x86_seg_cs, &segr);
    tss.cs = segr.sel;
    hvm_get_segment_register(v, x86_seg_ss, &segr);
    tss.ss = segr.sel;
    hvm_get_segment_register(v, x86_seg_ds, &segr);
    tss.ds = segr.sel;
    hvm_get_segment_register(v, x86_seg_fs, &segr);
    tss.fs = segr.sel;
    hvm_get_segment_register(v, x86_seg_gs, &segr);
    tss.gs = segr.sel;
    hvm_get_segment_register(v, x86_seg_ldtr, &segr);
    tss.ldt = segr.sel;

    rc = hvm_copy_to_guest_virt(prev_tr.base + offsetof(typeof(tss), eip),
                                &tss.eip,
                                offsetof(typeof(tss), trace) -
                                offsetof(typeof(tss), eip),
                                PFEC_page_present);
    if ( rc != HVMCOPY_okay )
        goto out;

    rc = hvm_copy_from_guest_virt(
        &tss, tr.base, sizeof(tss), PFEC_page_present);
    /*
     * Note: The HVMCOPY_gfn_shared case could be optimised, if the callee
     * functions knew we want RO access.
     */
    if ( rc != HVMCOPY_okay )
        goto out;

    if ( hvm_load_segment_selector(x86_seg_ldtr, tss.ldt, 0) )
        goto out;

    if ( hvm_set_cr3(tss.cr3, 1) )
        goto out;

    regs->eip    = tss.eip;
    regs->eflags = tss.eflags | 2;
    regs->eax    = tss.eax;
    regs->ecx    = tss.ecx;
    regs->edx    = tss.edx;
    regs->ebx    = tss.ebx;
    regs->esp    = tss.esp;
    regs->ebp    = tss.ebp;
    regs->esi    = tss.esi;
    regs->edi    = tss.edi;

    exn_raised = 0;
    if ( hvm_load_segment_selector(x86_seg_es, tss.es, tss.eflags) ||
         hvm_load_segment_selector(x86_seg_cs, tss.cs, tss.eflags) ||
         hvm_load_segment_selector(x86_seg_ss, tss.ss, tss.eflags) ||
         hvm_load_segment_selector(x86_seg_ds, tss.ds, tss.eflags) ||
         hvm_load_segment_selector(x86_seg_fs, tss.fs, tss.eflags) ||
         hvm_load_segment_selector(x86_seg_gs, tss.gs, tss.eflags) )
        exn_raised = 1;

    if ( taskswitch_reason == TSW_call_or_int )
    {
        regs->eflags |= X86_EFLAGS_NT;
        tss.back_link = prev_tr.sel;

        rc = hvm_copy_to_guest_virt(tr.base + offsetof(typeof(tss), back_link),
                                    &tss.back_link, sizeof(tss.back_link), 0);
        if ( rc == HVMCOPY_bad_gva_to_gfn )
            exn_raised = 1;
        else if ( rc != HVMCOPY_okay )
            goto out;
    }

    tr.attr.fields.type = 0xb; /* busy 32-bit tss */
    hvm_set_segment_register(v, x86_seg_tr, &tr);

    v->arch.hvm_vcpu.guest_cr[0] |= X86_CR0_TS;
    hvm_update_guest_cr(v, 0);

    if ( (taskswitch_reason == TSW_iret ||
          taskswitch_reason == TSW_jmp) && otd_writable )
        clear_bit(41, optss_desc); /* clear B flag of old task */

    if ( taskswitch_reason != TSW_iret && ntd_writable )
        set_bit(41, nptss_desc); /* set B flag of new task */

    if ( errcode >= 0 )
    {
        unsigned long linear_addr;
        unsigned int opsz, sp;

        hvm_get_segment_register(v, x86_seg_cs, &segr);
        opsz = segr.attr.fields.db ? 4 : 2;
        hvm_get_segment_register(v, x86_seg_ss, &segr);
        if ( segr.attr.fields.db )
            sp = regs->_esp -= opsz;
        else
            sp = *(uint16_t *)&regs->esp -= opsz;
        if ( hvm_virtual_to_linear_addr(x86_seg_ss, &segr, sp, opsz,
                                        hvm_access_write,
                                        16 << segr.attr.fields.db,
                                        &linear_addr) )
        {
            rc = hvm_copy_to_guest_virt(linear_addr, &errcode, opsz, 0);
            if ( rc == HVMCOPY_bad_gva_to_gfn )
                exn_raised = 1;
            else if ( rc != HVMCOPY_okay )
                goto out;
        }
    }

    if ( (tss.trace & 1) && !exn_raised )
        hvm_inject_hw_exception(TRAP_debug, HVM_DELIVER_NO_ERROR_CODE);

 out:
    hvm_unmap_entry(optss_desc);
    hvm_unmap_entry(nptss_desc);
}

#define HVMCOPY_from_guest (0u<<0)
#define HVMCOPY_to_guest   (1u<<0)
#define HVMCOPY_no_fault   (0u<<1)
#define HVMCOPY_fault      (1u<<1)
#define HVMCOPY_phys       (0u<<2)
#define HVMCOPY_virt       (1u<<2)
static enum hvm_copy_result __hvm_copy(
    void *buf, paddr_t addr, int size, unsigned int flags, uint32_t pfec)
{
    struct vcpu *curr = current;
    unsigned long gfn;
    struct page_info *page;
    p2m_type_t p2mt;
    char *p;
    int count, todo = size;

    /*
     * XXX Disable for 4.1.0: PV-on-HVM drivers will do grant-table ops
     * such as query_size. Grant-table code currently does copy_to/from_guest
     * accesses under the big per-domain lock, which this test would disallow.
     * The test is not needed until we implement sleeping-on-waitqueue when
     * we access a paged-out frame, and that's post 4.1.0 now.
     */
#if 0
    /*
     * If the required guest memory is paged out, this function may sleep.
     * Hence we bail immediately if called from atomic context.
     */
    if ( in_atomic() )
        return HVMCOPY_unhandleable;
#endif

    while ( todo > 0 )
    {
        paddr_t gpa = addr & ~PAGE_MASK;

        count = min_t(int, PAGE_SIZE - gpa, todo);

        if ( flags & HVMCOPY_virt )
        {
            gfn = paging_gva_to_gfn(curr, addr, &pfec);
            if ( gfn == gfn_x(INVALID_GFN) )
            {
                if ( pfec & PFEC_page_paged )
                    return HVMCOPY_gfn_paged_out;
                if ( pfec & PFEC_page_shared )
                    return HVMCOPY_gfn_shared;
                if ( flags & HVMCOPY_fault )
                    hvm_inject_page_fault(pfec, addr);
                return HVMCOPY_bad_gva_to_gfn;
            }
            gpa |= (paddr_t)gfn << PAGE_SHIFT;
        }
        else
        {
            gfn = addr >> PAGE_SHIFT;
            gpa = addr;
        }

        /*
         * No need to do the P2M lookup for internally handled MMIO, benefiting
         * - 32-bit WinXP (& older Windows) on AMD CPUs for LAPIC accesses,
         * - newer Windows (like Server 2012) for HPET accesses.
         */
        if ( !nestedhvm_vcpu_in_guestmode(curr)
             && is_hvm_vcpu(curr)
             && hvm_mmio_internal(gpa) )
            return HVMCOPY_bad_gfn_to_mfn;

        page = get_page_from_gfn(curr->domain, gfn, &p2mt, P2M_UNSHARE);

        if ( !page )
            return HVMCOPY_bad_gfn_to_mfn;

        if ( p2m_is_paging(p2mt) )
        {
            put_page(page);
            p2m_mem_paging_populate(curr->domain, gfn);
            return HVMCOPY_gfn_paged_out;
        }
        if ( p2m_is_shared(p2mt) )
        {
            put_page(page);
            return HVMCOPY_gfn_shared;
        }
        if ( p2m_is_grant(p2mt) )
        {
            put_page(page);
            return HVMCOPY_unhandleable;
        }

        p = (char *)__map_domain_page(page) + (addr & ~PAGE_MASK);

        if ( flags & HVMCOPY_to_guest )
        {
            if ( p2m_is_discard_write(p2mt) )
            {
                static unsigned long lastpage;
                if ( xchg(&lastpage, gfn) != gfn )
                    gdprintk(XENLOG_DEBUG, "guest attempted write to read-only"
                             " memory page. gfn=%#lx, mfn=%#lx\n",
                             gfn, page_to_mfn(page));
            }
            else
            {
                memcpy(p, buf, count);
                paging_mark_dirty(curr->domain, page_to_mfn(page));
            }
        }
        else
        {
            memcpy(buf, p, count);
        }

        unmap_domain_page(p);

        addr += count;
        buf  += count;
        todo -= count;
        put_page(page);
    }

    return HVMCOPY_okay;
}

static enum hvm_copy_result __hvm_clear(paddr_t addr, int size)
{
    struct vcpu *curr = current;
    unsigned long gfn;
    struct page_info *page;
    p2m_type_t p2mt;
    char *p;
    int count, todo = size;
    uint32_t pfec = PFEC_page_present | PFEC_write_access;

    /*
     * XXX Disable for 4.1.0: PV-on-HVM drivers will do grant-table ops
     * such as query_size. Grant-table code currently does copy_to/from_guest
     * accesses under the big per-domain lock, which this test would disallow.
     * The test is not needed until we implement sleeping-on-waitqueue when
     * we access a paged-out frame, and that's post 4.1.0 now.
     */
#if 0
    /*
     * If the required guest memory is paged out, this function may sleep.
     * Hence we bail immediately if called from atomic context.
     */
    if ( in_atomic() )
        return HVMCOPY_unhandleable;
#endif

    while ( todo > 0 )
    {
        count = min_t(int, PAGE_SIZE - (addr & ~PAGE_MASK), todo);

        gfn = paging_gva_to_gfn(curr, addr, &pfec);
        if ( gfn == gfn_x(INVALID_GFN) )
        {
            if ( pfec & PFEC_page_paged )
                return HVMCOPY_gfn_paged_out;
            if ( pfec & PFEC_page_shared )
                return HVMCOPY_gfn_shared;
            return HVMCOPY_bad_gva_to_gfn;
        }

        page = get_page_from_gfn(curr->domain, gfn, &p2mt, P2M_UNSHARE);

        if ( !page )
            return HVMCOPY_bad_gfn_to_mfn;

        if ( p2m_is_paging(p2mt) )
        {
            put_page(page);
            p2m_mem_paging_populate(curr->domain, gfn);
            return HVMCOPY_gfn_paged_out;
        }
        if ( p2m_is_shared(p2mt) )
        {
            put_page(page);
            return HVMCOPY_gfn_shared;
        }
        if ( p2m_is_grant(p2mt) )
        {
            put_page(page);
            return HVMCOPY_unhandleable;
        }

        p = (char *)__map_domain_page(page) + (addr & ~PAGE_MASK);

        if ( p2m_is_discard_write(p2mt) )
        {
            static unsigned long lastpage;
            if ( xchg(&lastpage, gfn) != gfn )
                gdprintk(XENLOG_DEBUG, "guest attempted write to read-only"
                        " memory page. gfn=%#lx, mfn=%#lx\n",
                         gfn, page_to_mfn(page));
        }
        else
        {
            memset(p, 0x00, count);
            paging_mark_dirty(curr->domain, page_to_mfn(page));
        }

        unmap_domain_page(p);

        addr += count;
        todo -= count;
        put_page(page);
    }

    return HVMCOPY_okay;
}

enum hvm_copy_result hvm_copy_to_guest_phys(
    paddr_t paddr, void *buf, int size)
{
    return __hvm_copy(buf, paddr, size,
                      HVMCOPY_to_guest | HVMCOPY_fault | HVMCOPY_phys,
                      0);
}

enum hvm_copy_result hvm_copy_from_guest_phys(
    void *buf, paddr_t paddr, int size)
{
    return __hvm_copy(buf, paddr, size,
                      HVMCOPY_from_guest | HVMCOPY_fault | HVMCOPY_phys,
                      0);
}

enum hvm_copy_result hvm_copy_to_guest_virt(
    unsigned long vaddr, void *buf, int size, uint32_t pfec)
{
    return __hvm_copy(buf, vaddr, size,
                      HVMCOPY_to_guest | HVMCOPY_fault | HVMCOPY_virt,
                      PFEC_page_present | PFEC_write_access | pfec);
}

enum hvm_copy_result hvm_copy_from_guest_virt(
    void *buf, unsigned long vaddr, int size, uint32_t pfec)
{
    return __hvm_copy(buf, vaddr, size,
                      HVMCOPY_from_guest | HVMCOPY_fault | HVMCOPY_virt,
                      PFEC_page_present | pfec);
}

enum hvm_copy_result hvm_fetch_from_guest_virt(
    void *buf, unsigned long vaddr, int size, uint32_t pfec)
{
    return __hvm_copy(buf, vaddr, size,
                      HVMCOPY_from_guest | HVMCOPY_fault | HVMCOPY_virt,
                      PFEC_page_present | PFEC_insn_fetch | pfec);
}

enum hvm_copy_result hvm_copy_to_guest_virt_nofault(
    unsigned long vaddr, void *buf, int size, uint32_t pfec)
{
    return __hvm_copy(buf, vaddr, size,
                      HVMCOPY_to_guest | HVMCOPY_no_fault | HVMCOPY_virt,
                      PFEC_page_present | PFEC_write_access | pfec);
}

enum hvm_copy_result hvm_copy_from_guest_virt_nofault(
    void *buf, unsigned long vaddr, int size, uint32_t pfec)
{
    return __hvm_copy(buf, vaddr, size,
                      HVMCOPY_from_guest | HVMCOPY_no_fault | HVMCOPY_virt,
                      PFEC_page_present | pfec);
}

enum hvm_copy_result hvm_fetch_from_guest_virt_nofault(
    void *buf, unsigned long vaddr, int size, uint32_t pfec)
{
    return __hvm_copy(buf, vaddr, size,
                      HVMCOPY_from_guest | HVMCOPY_no_fault | HVMCOPY_virt,
                      PFEC_page_present | PFEC_insn_fetch | pfec);
}

unsigned long copy_to_user_hvm(void *to, const void *from, unsigned int len)
{
    int rc;

    if ( !current->arch.hvm_vcpu.hcall_64bit &&
         is_compat_arg_xlat_range(to, len) )
    {
        memcpy(to, from, len);
        return 0;
    }

    rc = hvm_copy_to_guest_virt_nofault((unsigned long)to, (void *)from,
                                        len, 0);
    return rc ? len : 0; /* fake a copy_to_user() return code */
}

unsigned long clear_user_hvm(void *to, unsigned int len)
{
    int rc;

    if ( !current->arch.hvm_vcpu.hcall_64bit &&
         is_compat_arg_xlat_range(to, len) )
    {
        memset(to, 0x00, len);
        return 0;
    }

    rc = __hvm_clear((unsigned long)to, len);
    return rc ? len : 0; /* fake a copy_to_user() return code */
}

unsigned long copy_from_user_hvm(void *to, const void *from, unsigned len)
{
    int rc;

    if ( !current->arch.hvm_vcpu.hcall_64bit &&
         is_compat_arg_xlat_range(from, len) )
    {
        memcpy(to, from, len);
        return 0;
    }

    rc = hvm_copy_from_guest_virt_nofault(to, (unsigned long)from, len, 0);
    return rc ? len : 0; /* fake a copy_from_user() return code */
}

void hvm_hypervisor_cpuid_leaf(uint32_t sub_idx,
                               uint32_t *eax, uint32_t *ebx,
                               uint32_t *ecx, uint32_t *edx)
{
    *eax = *ebx = *ecx = *edx = 0;
    if ( hvm_funcs.hypervisor_cpuid_leaf )
        hvm_funcs.hypervisor_cpuid_leaf(sub_idx, eax, ebx, ecx, edx);

    if ( sub_idx == 0 )
    {
        /*
         * Indicate that memory mapped from other domains (either grants or
         * foreign pages) has valid IOMMU entries.
         */
        *eax |= XEN_HVM_CPUID_IOMMU_MAPPINGS;

        /* Indicate presence of vcpu id and set it in ebx */
        *eax |= XEN_HVM_CPUID_VCPU_ID_PRESENT;
        *ebx = current->vcpu_id;
    }
}

void hvm_cpuid(unsigned int input, unsigned int *eax, unsigned int *ebx,
                                   unsigned int *ecx, unsigned int *edx)
{
    struct vcpu *v = current;
    struct domain *d = v->domain;
    unsigned int count, dummy = 0;

    if ( !eax )
        eax = &dummy;
    if ( !ebx )
        ebx = &dummy;
    if ( !ecx )
        ecx = &dummy;
    count = *ecx;
    if ( !edx )
        edx = &dummy;

    if ( cpuid_viridian_leaves(input, eax, ebx, ecx, edx) )
        return;

    if ( cpuid_hypervisor_leaves(input, count, eax, ebx, ecx, edx) )
        return;

    if ( input & 0x7fffffff )
    {
        /*
         * Requests outside the supported leaf ranges return zero on AMD
         * and the highest basic leaf output on Intel. Uniformly follow
         * the AMD model as the more sane one.
         */
        unsigned int limit;

        domain_cpuid(d, (input >> 16) != 0x8000 ? 0 : 0x80000000, 0,
                     &limit, &dummy, &dummy, &dummy);
        if ( input > limit )
        {
            *eax = 0;
            *ebx = 0;
            *ecx = 0;
            *edx = 0;
            return;
        }
    }

    domain_cpuid(d, input, count, eax, ebx, ecx, edx);

    switch ( input )
    {
        unsigned int _ebx, _ecx, _edx;

    case 0x1:
        /* Fix up VLAPIC details. */
        *ebx &= 0x00FFFFFFu;
        *ebx |= (v->vcpu_id * 2) << 24;

        *ecx &= hvm_featureset[FEATURESET_1c];
        *edx &= hvm_featureset[FEATURESET_1d];

        /* APIC exposed to guests, but Fast-forward MSR_APIC_BASE.EN back in. */
        if ( vlapic_hw_disabled(vcpu_vlapic(v)) )
            *edx &= ~cpufeat_bit(X86_FEATURE_APIC);

        /* OSXSAVE cleared by hvm_featureset.  Fast-forward CR4 back in. */
        if ( v->arch.hvm_vcpu.guest_cr[4] & X86_CR4_OSXSAVE )
            *ecx |= cpufeat_mask(X86_FEATURE_OSXSAVE);

        /* Don't expose HAP-only features to non-hap guests. */
        if ( !hap_enabled(d) )
        {
            *ecx &= ~cpufeat_mask(X86_FEATURE_PCID);

            /*
             * PSE36 is not supported in shadow mode.  This bit should be
             * unilaterally cleared.
             *
             * However, an unspecified version of Hyper-V from 2011 refuses
             * to start as the "cpu does not provide required hw features" if
             * it can't see PSE36.
             *
             * As a workaround, leak the toolstack-provided PSE36 value into a
             * shadow guest if the guest is already using PAE paging (and
             * won't care about reverting back to PSE paging).  Otherwise,
             * knoble it, so a 32bit guest doesn't get the impression that it
             * could try to use PSE36 paging.
             */
            if ( !(hvm_pae_enabled(v) || hvm_long_mode_enabled(v)) )
                *edx &= ~cpufeat_mask(X86_FEATURE_PSE36);
        }
        break;

    case 0x7:
        if ( count == 0 )
        {
            /* Fold host's FDP_EXCP_ONLY and NO_FPU_SEL into guest's view. */
            *ebx &= (hvm_featureset[FEATURESET_7b0] &
                     ~special_features[FEATURESET_7b0]);
            *ebx |= (host_featureset[FEATURESET_7b0] &
                     special_features[FEATURESET_7b0]);

            *ecx &= hvm_featureset[FEATURESET_7c0];

            /* Don't expose HAP-only features to non-hap guests. */
            if ( !hap_enabled(d) )
            {
                 *ebx &= ~cpufeat_mask(X86_FEATURE_INVPCID);
                 *ecx &= ~cpufeat_mask(X86_FEATURE_PKU);
            }

            /* OSPKE cleared by hvm_featureset.  Fast-forward CR4 back in. */
            if ( v->arch.hvm_vcpu.guest_cr[4] & X86_CR4_PKE )
                *ecx |= cpufeat_mask(X86_FEATURE_OSPKE);
        }
        break;

    case 0xb:
        /* Fix the x2APIC identifier. */
        *edx = v->vcpu_id * 2;
        break;

    case XSTATE_CPUID:
        hvm_cpuid(1, NULL, NULL, &_ecx, NULL);
        if ( !(_ecx & cpufeat_mask(X86_FEATURE_XSAVE)) || count >= 63 )
        {
            *eax = *ebx = *ecx = *edx = 0;
            break;
        }
        switch ( count )
        {
        case 0:
        {
            uint64_t xfeature_mask = XSTATE_FP_SSE;
            uint32_t xstate_size = XSTATE_AREA_MIN_SIZE;

            if ( _ecx & cpufeat_mask(X86_FEATURE_AVX) )
            {
                xfeature_mask |= XSTATE_YMM;
                xstate_size = max(xstate_size,
                                  xstate_offsets[_XSTATE_YMM] +
                                  xstate_sizes[_XSTATE_YMM]);
            }

            _ecx = 0;
            hvm_cpuid(7, NULL, &_ebx, &_ecx, NULL);

            if ( _ebx & cpufeat_mask(X86_FEATURE_MPX) )
            {
                xfeature_mask |= XSTATE_BNDREGS | XSTATE_BNDCSR;
                xstate_size = max(xstate_size,
                                  xstate_offsets[_XSTATE_BNDCSR] +
                                  xstate_sizes[_XSTATE_BNDCSR]);
            }

            if ( _ebx & cpufeat_mask(X86_FEATURE_AVX512F) )
            {
                xfeature_mask |= XSTATE_OPMASK | XSTATE_ZMM | XSTATE_HI_ZMM;
                xstate_size = max(xstate_size,
                                  xstate_offsets[_XSTATE_OPMASK] +
                                  xstate_sizes[_XSTATE_OPMASK]);
                xstate_size = max(xstate_size,
                                  xstate_offsets[_XSTATE_ZMM] +
                                  xstate_sizes[_XSTATE_ZMM]);
                xstate_size = max(xstate_size,
                                  xstate_offsets[_XSTATE_HI_ZMM] +
                                  xstate_sizes[_XSTATE_HI_ZMM]);
            }

            if ( _ecx & cpufeat_mask(X86_FEATURE_PKU) )
            {
                xfeature_mask |= XSTATE_PKRU;
                xstate_size = max(xstate_size,
                                  xstate_offsets[_XSTATE_PKRU] +
                                  xstate_sizes[_XSTATE_PKRU]);
            }

            hvm_cpuid(0x80000001, NULL, NULL, &_ecx, NULL);

            if ( _ecx & cpufeat_mask(X86_FEATURE_LWP) )
            {
                xfeature_mask |= XSTATE_LWP;
                xstate_size = max(xstate_size,
                                  xstate_offsets[_XSTATE_LWP] +
                                  xstate_sizes[_XSTATE_LWP]);
            }

            *eax = (uint32_t)xfeature_mask;
            *edx = (uint32_t)(xfeature_mask >> 32);
            *ecx = xstate_size;

            /*
             * Always read CPUID[0xD,0].EBX from hardware, rather than domain
             * policy.  It varies with enabled xstate, and the correct xcr0 is
             * in context.
             */
            cpuid_count(input, count, &dummy, ebx, &dummy, &dummy);
            break;
        }

        case 1:
            *eax &= hvm_featureset[FEATURESET_Da1];

            if ( *eax & cpufeat_mask(X86_FEATURE_XSAVES) )
            {
                /*
                 * Always read CPUID[0xD,1].EBX from hardware, rather than
                 * domain policy.  It varies with enabled xstate, and the
                 * correct xcr0/xss are in context.
                 */
                cpuid_count(input, count, &dummy, ebx, &dummy, &dummy);
            }
            else
                *ebx = 0;

            *ecx = *edx = 0;
            break;
        }
        break;

    case 0x80000001:
        *ecx &= hvm_featureset[FEATURESET_e1c];
        *edx &= hvm_featureset[FEATURESET_e1d];

        /* If not emulating AMD, clear the duplicated features in e1d. */
        if ( d->arch.x86_vendor != X86_VENDOR_AMD )
            *edx &= ~CPUID_COMMON_1D_FEATURES;
        /* fast-forward MSR_APIC_BASE.EN if it hasn't already been clobbered. */
        else if ( vlapic_hw_disabled(vcpu_vlapic(v)) )
            *edx &= ~cpufeat_bit(X86_FEATURE_APIC);

        /* Don't expose HAP-only features to non-hap guests. */
        if ( !hap_enabled(d) )
        {
            *edx &= ~cpufeat_mask(X86_FEATURE_PAGE1GB);

            /*
             * PSE36 is not supported in shadow mode.  This bit should be
             * unilaterally cleared.
             *
             * However, an unspecified version of Hyper-V from 2011 refuses
             * to start as the "cpu does not provide required hw features" if
             * it can't see PSE36.
             *
             * As a workaround, leak the toolstack-provided PSE36 value into a
             * shadow guest if the guest is already using PAE paging (and
             * won't care about reverting back to PSE paging).  Otherwise,
             * knoble it, so a 32bit guest doesn't get the impression that it
             * could try to use PSE36 paging.
             */
            if ( !(hvm_pae_enabled(v) || hvm_long_mode_enabled(v)) )
                *edx &= ~cpufeat_mask(X86_FEATURE_PSE36);
        }
        break;

    case 0x80000007:
        *edx &= (hvm_featureset[FEATURESET_e7d] |
                 (host_featureset[FEATURESET_e7d] & cpufeat_mask(X86_FEATURE_ITSC)));
        break;

    case 0x80000008:
        *eax &= 0xff;
        count = d->arch.paging.gfn_bits + PAGE_SHIFT;
        if ( *eax > count )
            *eax = count;

        hvm_cpuid(1, NULL, NULL, NULL, &_edx);
        count = _edx & (cpufeat_mask(X86_FEATURE_PAE) |
                        cpufeat_mask(X86_FEATURE_PSE36)) ? 36 : 32;
        if ( *eax < count )
            *eax = count;

        hvm_cpuid(0x80000001, NULL, NULL, NULL, &_edx);
        *eax |= (_edx & cpufeat_mask(X86_FEATURE_LM) ? vaddr_bits : 32) << 8;

        *ebx &= hvm_featureset[FEATURESET_e8b];
        break;
    }
}

bool hvm_check_cpuid_faulting(struct vcpu *v)
{
    struct segment_register sreg;

    if ( !v->arch.cpuid_faulting )
        return false;

    hvm_get_segment_register(v, x86_seg_ss, &sreg);
    if ( sreg.attr.fields.dpl == 0 )
        return false;

    return true;
}

static uint64_t _hvm_rdtsc_intercept(void)
{
    struct vcpu *curr = current;
#if !defined(NDEBUG) || defined(CONFIG_PERF_COUNTERS)
    struct domain *currd = curr->domain;

    if ( currd->arch.vtsc )
        switch ( hvm_guest_x86_mode(curr) )
        {
            struct segment_register sreg;

        case 8:
        case 4:
        case 2:
            hvm_get_segment_register(curr, x86_seg_ss, &sreg);
            if ( unlikely(sreg.attr.fields.dpl) )
            {
        case 1:
                currd->arch.vtsc_usercount++;
                break;
            }
            /* fall through */
        case 0:
            currd->arch.vtsc_kerncount++;
            break;
        }
#endif

    return hvm_get_guest_tsc(curr);
}

void hvm_rdtsc_intercept(struct cpu_user_regs *regs)
{
    uint64_t tsc = _hvm_rdtsc_intercept();

    regs->eax = (uint32_t)tsc;
    regs->edx = (uint32_t)(tsc >> 32);

    HVMTRACE_2D(RDTSC, regs->eax, regs->edx);
}

int hvm_msr_read_intercept(unsigned int msr, uint64_t *msr_content)
{
    struct vcpu *v = current;
    uint64_t *var_range_base, *fixed_range_base;
    bool mtrr = false;
    int ret = X86EMUL_OKAY;

    var_range_base = (uint64_t *)v->arch.hvm_vcpu.mtrr.var_ranges;
    fixed_range_base = (uint64_t *)v->arch.hvm_vcpu.mtrr.fixed_ranges;

    if ( msr == MSR_MTRRcap ||
         (msr >= MSR_IA32_MTRR_PHYSBASE(0) && msr <= MSR_MTRRdefType) )
    {
        unsigned int edx;

        hvm_cpuid(1, NULL, NULL, NULL, &edx);
        if ( edx & cpufeat_mask(X86_FEATURE_MTRR) )
            mtrr = true;
    }

    switch ( msr )
    {
        unsigned int eax, ebx, ecx, index;

    case MSR_EFER:
        *msr_content = v->arch.hvm_vcpu.guest_efer;
        break;

    case MSR_IA32_TSC:
        *msr_content = _hvm_rdtsc_intercept();
        break;

    case MSR_IA32_TSC_ADJUST:
        *msr_content = hvm_get_guest_tsc_adjust(v);
        break;

    case MSR_TSC_AUX:
        *msr_content = hvm_msr_tsc_aux(v);
        break;

    case MSR_IA32_APICBASE:
        *msr_content = vcpu_vlapic(v)->hw.apic_base_msr;
        break;

    case MSR_IA32_APICBASE_MSR ... MSR_IA32_APICBASE_MSR + 0x3ff:
        if ( hvm_x2apic_msr_read(v, msr, msr_content) )
            goto gp_fault;
        break;

    case MSR_IA32_TSC_DEADLINE:
        *msr_content = vlapic_tdt_msr_get(vcpu_vlapic(v));
        break;

    case MSR_IA32_CR_PAT:
        hvm_get_guest_pat(v, msr_content);
        break;

    case MSR_MTRRcap:
        if ( !mtrr )
            goto gp_fault;
        *msr_content = v->arch.hvm_vcpu.mtrr.mtrr_cap;
        break;
    case MSR_MTRRdefType:
        if ( !mtrr )
            goto gp_fault;
        *msr_content = v->arch.hvm_vcpu.mtrr.def_type
                        | (v->arch.hvm_vcpu.mtrr.enabled << 10);
        break;
    case MSR_MTRRfix64K_00000:
        if ( !mtrr )
            goto gp_fault;
        *msr_content = fixed_range_base[0];
        break;
    case MSR_MTRRfix16K_80000:
    case MSR_MTRRfix16K_A0000:
        if ( !mtrr )
            goto gp_fault;
        index = msr - MSR_MTRRfix16K_80000;
        *msr_content = fixed_range_base[index + 1];
        break;
    case MSR_MTRRfix4K_C0000...MSR_MTRRfix4K_F8000:
        if ( !mtrr )
            goto gp_fault;
        index = msr - MSR_MTRRfix4K_C0000;
        *msr_content = fixed_range_base[index + 3];
        break;
    case MSR_IA32_MTRR_PHYSBASE(0)...MSR_IA32_MTRR_PHYSMASK(MTRR_VCNT-1):
        if ( !mtrr )
            goto gp_fault;
        index = msr - MSR_IA32_MTRR_PHYSBASE(0);
        *msr_content = var_range_base[index];
        break;

    case MSR_IA32_XSS:
        ecx = 1;
        hvm_cpuid(XSTATE_CPUID, &eax, NULL, &ecx, NULL);
        if ( !(eax & cpufeat_mask(X86_FEATURE_XSAVES)) )
            goto gp_fault;
        *msr_content = v->arch.hvm_vcpu.msr_xss;
        break;

    case MSR_IA32_BNDCFGS:
        ecx = 0;
        hvm_cpuid(7, NULL, &ebx, &ecx, NULL);
        if ( !(ebx & cpufeat_mask(X86_FEATURE_MPX)) ||
             !hvm_get_guest_bndcfgs(v, msr_content) )
            goto gp_fault;
        break;

    case MSR_K8_ENABLE_C1E:
    case MSR_AMD64_NB_CFG:
         /*
          * These AMD-only registers may be accessed if this HVM guest
          * has been migrated to an Intel host. This fixes a guest crash
          * in this case.
          */
         *msr_content = 0;
         break;

    default:
        if ( (ret = vmce_rdmsr(msr, msr_content)) < 0 )
            goto gp_fault;
        /* If ret == 0 then this is not an MCE MSR, see other MSRs. */
        ret = ((ret == 0)
               ? hvm_funcs.msr_read_intercept(msr, msr_content)
               : X86EMUL_OKAY);
        break;
    }

 out:
    HVMTRACE_3D(MSR_READ, msr,
                (uint32_t)*msr_content, (uint32_t)(*msr_content >> 32));
    return ret;

 gp_fault:
    hvm_inject_hw_exception(TRAP_gp_fault, 0);
    ret = X86EMUL_EXCEPTION;
    *msr_content = -1ull;
    goto out;
}

int hvm_msr_write_intercept(unsigned int msr, uint64_t msr_content,
                            bool_t may_defer)
{
    struct vcpu *v = current;
    bool mtrr = false;
    int ret = X86EMUL_OKAY;

    HVMTRACE_3D(MSR_WRITE, msr,
               (uint32_t)msr_content, (uint32_t)(msr_content >> 32));

    if ( msr >= MSR_IA32_MTRR_PHYSBASE(0) && msr <= MSR_MTRRdefType )
    {
        unsigned int edx;

        hvm_cpuid(1, NULL, NULL, NULL, &edx);
        if ( edx & cpufeat_mask(X86_FEATURE_MTRR) )
            mtrr = true;
    }

    if ( may_defer && unlikely(monitored_msr(v->domain, msr)) )
    {
        ASSERT(v->arch.vm_event);

        /* The actual write will occur in hvm_do_resume() (if permitted). */
        v->arch.vm_event->write_data.do_write.msr = 1;
        v->arch.vm_event->write_data.msr = msr;
        v->arch.vm_event->write_data.value = msr_content;

        hvm_monitor_msr(msr, msr_content);
        return X86EMUL_OKAY;
    }

    switch ( msr )
    {
        unsigned int eax, ebx, ecx, index;

    case MSR_EFER:
        if ( hvm_set_efer(msr_content) )
           return X86EMUL_EXCEPTION;
        break;

    case MSR_IA32_TSC:
        hvm_set_guest_tsc_msr(v, msr_content);
        break;

    case MSR_IA32_TSC_ADJUST:
        hvm_set_guest_tsc_adjust(v, msr_content);
        break;

    case MSR_TSC_AUX:
        v->arch.hvm_vcpu.msr_tsc_aux = (uint32_t)msr_content;
        if ( cpu_has_rdtscp
             && (v->domain->arch.tsc_mode != TSC_MODE_PVRDTSCP) )
            wrmsrl(MSR_TSC_AUX, (uint32_t)msr_content);
        break;

    case MSR_IA32_APICBASE:
        if ( unlikely(is_pvh_vcpu(v)) ||
             !vlapic_msr_set(vcpu_vlapic(v), msr_content) )
            goto gp_fault;
        break;

    case MSR_IA32_TSC_DEADLINE:
        vlapic_tdt_msr_set(vcpu_vlapic(v), msr_content);
        break;

    case MSR_IA32_APICBASE_MSR ... MSR_IA32_APICBASE_MSR + 0x3ff:
        if ( hvm_x2apic_msr_write(v, msr, msr_content) )
            goto gp_fault;
        break;

    case MSR_IA32_CR_PAT:
        if ( !hvm_set_guest_pat(v, msr_content) )
           goto gp_fault;
        break;

    case MSR_MTRRcap:
        goto gp_fault;

    case MSR_MTRRdefType:
        if ( !mtrr )
            goto gp_fault;
        if ( !mtrr_def_type_msr_set(v->domain, &v->arch.hvm_vcpu.mtrr,
                                    msr_content) )
           goto gp_fault;
        break;
    case MSR_MTRRfix64K_00000:
        if ( !mtrr )
            goto gp_fault;
        if ( !mtrr_fix_range_msr_set(v->domain, &v->arch.hvm_vcpu.mtrr, 0,
                                     msr_content) )
            goto gp_fault;
        break;
    case MSR_MTRRfix16K_80000:
    case MSR_MTRRfix16K_A0000:
        if ( !mtrr )
            goto gp_fault;
        index = msr - MSR_MTRRfix16K_80000 + 1;
        if ( !mtrr_fix_range_msr_set(v->domain, &v->arch.hvm_vcpu.mtrr,
                                     index, msr_content) )
            goto gp_fault;
        break;
    case MSR_MTRRfix4K_C0000...MSR_MTRRfix4K_F8000:
        if ( !mtrr )
            goto gp_fault;
        index = msr - MSR_MTRRfix4K_C0000 + 3;
        if ( !mtrr_fix_range_msr_set(v->domain, &v->arch.hvm_vcpu.mtrr,
                                     index, msr_content) )
            goto gp_fault;
        break;
    case MSR_IA32_MTRR_PHYSBASE(0)...MSR_IA32_MTRR_PHYSMASK(MTRR_VCNT-1):
        if ( !mtrr )
            goto gp_fault;
        if ( !mtrr_var_range_msr_set(v->domain, &v->arch.hvm_vcpu.mtrr,
                                     msr, msr_content) )
            goto gp_fault;
        break;

    case MSR_IA32_XSS:
        ecx = 1;
        hvm_cpuid(XSTATE_CPUID, &eax, NULL, &ecx, NULL);
        /* No XSS features currently supported for guests. */
        if ( !(eax & cpufeat_mask(X86_FEATURE_XSAVES)) || msr_content != 0 )
            goto gp_fault;
        v->arch.hvm_vcpu.msr_xss = msr_content;
        break;

    case MSR_IA32_BNDCFGS:
        ecx = 0;
        hvm_cpuid(7, NULL, &ebx, &ecx, NULL);
        if ( !(ebx & cpufeat_mask(X86_FEATURE_MPX)) ||
             !hvm_set_guest_bndcfgs(v, msr_content) )
            goto gp_fault;
        break;

    case MSR_AMD64_NB_CFG:
        /* ignore the write */
        break;

    default:
        if ( (ret = vmce_wrmsr(msr, msr_content)) < 0 )
            goto gp_fault;
        /* If ret == 0 then this is not an MCE MSR, see other MSRs. */
        ret = ((ret == 0)
               ? hvm_funcs.msr_write_intercept(msr, msr_content)
               : X86EMUL_OKAY);
        break;
    }

    return ret;

gp_fault:
    hvm_inject_hw_exception(TRAP_gp_fault, 0);
    return X86EMUL_EXCEPTION;
}

void hvm_ud_intercept(struct cpu_user_regs *regs)
{
    struct hvm_emulate_ctxt ctxt;

    hvm_emulate_init_once(&ctxt, regs);

    if ( opt_hvm_fep )
    {
        struct vcpu *cur = current;
        const struct segment_register *cs = &ctxt.seg_reg[x86_seg_cs];
        uint32_t walk = (ctxt.seg_reg[x86_seg_ss].attr.fields.dpl == 3)
            ? PFEC_user_mode : 0;
        unsigned long addr;
        char sig[5]; /* ud2; .ascii "xen" */

        if ( hvm_virtual_to_linear_addr(x86_seg_cs, cs, regs->eip,
                                        sizeof(sig), hvm_access_insn_fetch,
                                        (hvm_long_mode_enabled(cur) &&
                                         cs->attr.fields.l) ? 64 :
                                        cs->attr.fields.db ? 32 : 16, &addr) &&
             (hvm_fetch_from_guest_virt_nofault(sig, addr, sizeof(sig),
                                                walk) == HVMCOPY_okay) &&
             (memcmp(sig, "\xf\xbxen", sizeof(sig)) == 0) )
        {
            regs->eip += sizeof(sig);
            regs->eflags &= ~X86_EFLAGS_RF;

            /* Zero the upper 32 bits of %rip if not in 64bit mode. */
            if ( !(hvm_long_mode_enabled(cur) && cs->attr.fields.l) )
                regs->eip = regs->_eip;

            add_taint(TAINT_HVM_FEP);
        }
    }

    switch ( hvm_emulate_one(&ctxt) )
    {
    case X86EMUL_UNHANDLEABLE:
        hvm_inject_hw_exception(TRAP_invalid_op, HVM_DELIVER_NO_ERROR_CODE);
        break;
    case X86EMUL_EXCEPTION:
        if ( ctxt.exn_pending )
            hvm_inject_trap(&ctxt.trap);
        /* fall through */
    default:
        hvm_emulate_writeback(&ctxt);
        break;
    }
}

enum hvm_intblk hvm_interrupt_blocked(struct vcpu *v, struct hvm_intack intack)
{
    unsigned long intr_shadow;

    ASSERT(v == current);

    if ( nestedhvm_enabled(v->domain) ) {
        enum hvm_intblk intr;

        intr = nhvm_interrupt_blocked(v);
        if ( intr != hvm_intblk_none )
            return intr;
    }

    if ( (intack.source != hvm_intsrc_nmi) &&
         !(guest_cpu_user_regs()->eflags & X86_EFLAGS_IF) )
        return hvm_intblk_rflags_ie;

    intr_shadow = hvm_funcs.get_interrupt_shadow(v);

    if ( intr_shadow & (HVM_INTR_SHADOW_STI|HVM_INTR_SHADOW_MOV_SS) )
        return hvm_intblk_shadow;

    if ( intack.source == hvm_intsrc_nmi )
        return ((intr_shadow & HVM_INTR_SHADOW_NMI) ?
                hvm_intblk_nmi_iret : hvm_intblk_none);

    if ( intack.source == hvm_intsrc_lapic )
    {
        uint32_t tpr = vlapic_get_reg(vcpu_vlapic(v), APIC_TASKPRI) & 0xF0;
        if ( (tpr >> 4) >= (intack.vector >> 4) )
            return hvm_intblk_tpr;
    }

    return hvm_intblk_none;
}

static int grant_table_op_is_allowed(unsigned int cmd)
{
    switch (cmd) {
    case GNTTABOP_query_size:
    case GNTTABOP_setup_table:
    case GNTTABOP_set_version:
    case GNTTABOP_get_version:
    case GNTTABOP_copy:
    case GNTTABOP_map_grant_ref:
    case GNTTABOP_unmap_grant_ref:
    case GNTTABOP_swap_grant_ref:
        return 1;
    default:
        /* all other commands need auditing */
        return 0;
    }
}

static long hvm_grant_table_op(
    unsigned int cmd, XEN_GUEST_HANDLE_PARAM(void) uop, unsigned int count)
{
    if ( !grant_table_op_is_allowed(cmd) )
        return -ENOSYS; /* all other commands need auditing */
    return do_grant_table_op(cmd, uop, count);
}

static long hvm_memory_op(int cmd, XEN_GUEST_HANDLE_PARAM(void) arg)
{
    long rc;

    switch ( cmd & MEMOP_CMD_MASK )
    {
    case XENMEM_machine_memory_map:
    case XENMEM_machphys_mapping:
        return -ENOSYS;
    case XENMEM_decrease_reservation:
        rc = do_memory_op(cmd, arg);
        current->domain->arch.hvm_domain.qemu_mapcache_invalidate = 1;
        return rc;
    }
    return do_memory_op(cmd, arg);
}

static long hvm_physdev_op(int cmd, XEN_GUEST_HANDLE_PARAM(void) arg)
{
    switch ( cmd )
    {
    default:
        if ( !is_pvh_vcpu(current) || !is_hardware_domain(current->domain) )
            return -ENOSYS;
        /* fall through */
    case PHYSDEVOP_map_pirq:
    case PHYSDEVOP_unmap_pirq:
    case PHYSDEVOP_eoi:
    case PHYSDEVOP_irq_status_query:
    case PHYSDEVOP_get_free_pirq:
        return do_physdev_op(cmd, arg);
    }
}

static long hvm_grant_table_op_compat32(unsigned int cmd,
                                        XEN_GUEST_HANDLE_PARAM(void) uop,
                                        unsigned int count)
{
    if ( !grant_table_op_is_allowed(cmd) )
        return -ENOSYS;
    return compat_grant_table_op(cmd, uop, count);
}

static long hvm_memory_op_compat32(int cmd, XEN_GUEST_HANDLE_PARAM(void) arg)
{
    int rc;

    switch ( cmd & MEMOP_CMD_MASK )
    {
    case XENMEM_machine_memory_map:
    case XENMEM_machphys_mapping:
        return -ENOSYS;
    case XENMEM_decrease_reservation:
        rc = compat_memory_op(cmd, arg);
        current->domain->arch.hvm_domain.qemu_mapcache_invalidate = 1;
        return rc;
    }
    return compat_memory_op(cmd, arg);
}

static long hvm_physdev_op_compat32(
    int cmd, XEN_GUEST_HANDLE_PARAM(void) arg)
{
    switch ( cmd )
    {
        case PHYSDEVOP_map_pirq:
        case PHYSDEVOP_unmap_pirq:
        case PHYSDEVOP_eoi:
        case PHYSDEVOP_irq_status_query:
        case PHYSDEVOP_get_free_pirq:
            return compat_physdev_op(cmd, arg);
        break;
    default:
            return -ENOSYS;
        break;
    }
}

#define HYPERCALL(x)                                         \
    [ __HYPERVISOR_ ## x ] = { (hypercall_fn_t *) do_ ## x,  \
                               (hypercall_fn_t *) do_ ## x }

#define COMPAT_CALL(x)                                       \
    [ __HYPERVISOR_ ## x ] = { (hypercall_fn_t *) do_ ## x,  \
                               (hypercall_fn_t *) compat_ ## x }

#define do_memory_op          hvm_memory_op
#define compat_memory_op      hvm_memory_op_compat32
#define do_physdev_op         hvm_physdev_op
#define compat_physdev_op     hvm_physdev_op_compat32
#define do_grant_table_op     hvm_grant_table_op
#define compat_grant_table_op hvm_grant_table_op_compat32
#define do_arch_1             paging_domctl_continuation

static const hypercall_table_t hvm_hypercall_table[] = {
    COMPAT_CALL(memory_op),
    COMPAT_CALL(grant_table_op),
    COMPAT_CALL(vcpu_op),
    COMPAT_CALL(physdev_op),
    COMPAT_CALL(xen_version),
    HYPERCALL(console_io),
    HYPERCALL(event_channel_op),
    COMPAT_CALL(sched_op),
    COMPAT_CALL(set_timer_op),
    HYPERCALL(xsm_op),
    HYPERCALL(hvm_op),
    HYPERCALL(sysctl),
    HYPERCALL(domctl),
#ifdef CONFIG_TMEM
    HYPERCALL(tmem_op),
#endif
    COMPAT_CALL(platform_op),
    COMPAT_CALL(mmuext_op),
    HYPERCALL(xenpmu_op),
    HYPERCALL(arch_1)
};

#undef do_memory_op
#undef compat_memory_op
#undef do_physdev_op
#undef compat_physdev_op
#undef do_grant_table_op
#undef compat_grant_table_op
#undef do_arch_1

#undef HYPERCALL
#undef COMPAT_CALL

int hvm_do_hypercall(struct cpu_user_regs *regs)
{
    struct vcpu *curr = current;
    struct domain *currd = curr->domain;
    struct segment_register sreg;
    int mode = hvm_guest_x86_mode(curr);
    unsigned long eax = regs->_eax;

    switch ( mode )
    {
    case 8:
        eax = regs->rax;
        /* Fallthrough to permission check. */
    case 4:
    case 2:
        hvm_get_segment_register(curr, x86_seg_ss, &sreg);
        if ( unlikely(sreg.attr.fields.dpl) )
        {
    default:
            regs->eax = -EPERM;
            return HVM_HCALL_completed;
        }
    case 0:
        break;
    }

    if ( (eax & 0x80000000) && is_viridian_domain(currd) )
        return viridian_hypercall(regs);

    BUILD_BUG_ON(ARRAY_SIZE(hvm_hypercall_table) >
                 ARRAY_SIZE(hypercall_args_table));

    if ( (eax >= ARRAY_SIZE(hvm_hypercall_table)) ||
         !hvm_hypercall_table[eax].native )
    {
        regs->eax = -ENOSYS;
        return HVM_HCALL_completed;
    }

    curr->arch.hvm_vcpu.hcall_preempted = 0;

    if ( mode == 8 )
    {
        unsigned long rdi = regs->rdi;
        unsigned long rsi = regs->rsi;
        unsigned long rdx = regs->rdx;
        unsigned long r10 = regs->r10;
        unsigned long r8 = regs->r8;
        unsigned long r9 = regs->r9;

        HVM_DBG_LOG(DBG_LEVEL_HCALL, "hcall%lu(%lx, %lx, %lx, %lx, %lx, %lx)",
                    eax, rdi, rsi, rdx, r10, r8, r9);

#ifndef NDEBUG
        /* Deliberately corrupt parameter regs not used by this hypercall. */
        switch ( hypercall_args_table[eax].native )
        {
        case 0: rdi = 0xdeadbeefdeadf00dUL;
        case 1: rsi = 0xdeadbeefdeadf00dUL;
        case 2: rdx = 0xdeadbeefdeadf00dUL;
        case 3: r10 = 0xdeadbeefdeadf00dUL;
        case 4: r8 = 0xdeadbeefdeadf00dUL;
        case 5: r9 = 0xdeadbeefdeadf00dUL;
        }
#endif

        curr->arch.hvm_vcpu.hcall_64bit = 1;
        regs->rax = hvm_hypercall_table[eax].native(rdi, rsi, rdx, r10, r8,
                                                    r9);

        curr->arch.hvm_vcpu.hcall_64bit = 0;

#ifndef NDEBUG
        if ( !curr->arch.hvm_vcpu.hcall_preempted )
        {
            /* Deliberately corrupt parameter regs used by this hypercall. */
            switch ( hypercall_args_table[eax].native )
            {
            case 6: regs->r9  = 0xdeadbeefdeadf00dUL;
            case 5: regs->r8  = 0xdeadbeefdeadf00dUL;
            case 4: regs->r10 = 0xdeadbeefdeadf00dUL;
            case 3: regs->edx = 0xdeadbeefdeadf00dUL;
            case 2: regs->esi = 0xdeadbeefdeadf00dUL;
            case 1: regs->edi = 0xdeadbeefdeadf00dUL;
            }
        }
#endif
    }
    else
    {
        unsigned int ebx = regs->_ebx;
        unsigned int ecx = regs->_ecx;
        unsigned int edx = regs->_edx;
        unsigned int esi = regs->_esi;
        unsigned int edi = regs->_edi;
        unsigned int ebp = regs->_ebp;

        HVM_DBG_LOG(DBG_LEVEL_HCALL, "hcall%lu(%x, %x, %x, %x, %x, %x)", eax,
                    ebx, ecx, edx, esi, edi, ebp);

#ifndef NDEBUG
        /* Deliberately corrupt parameter regs not used by this hypercall. */
        switch ( hypercall_args_table[eax].compat )
        {
        case 0: ebx = 0xdeadf00d;
        case 1: ecx = 0xdeadf00d;
        case 2: edx = 0xdeadf00d;
        case 3: esi = 0xdeadf00d;
        case 4: edi = 0xdeadf00d;
        case 5: ebp = 0xdeadf00d;
        }
#endif

        regs->_eax = hvm_hypercall_table[eax].compat(ebx, ecx, edx, esi, edi,
                                                     ebp);

#ifndef NDEBUG
        if ( !curr->arch.hvm_vcpu.hcall_preempted )
        {
            /* Deliberately corrupt parameter regs used by this hypercall. */
            switch ( hypercall_args_table[eax].compat )
            {
            case 6: regs->ebp = 0xdeadf00d;
            case 5: regs->edi = 0xdeadf00d;
            case 4: regs->esi = 0xdeadf00d;
            case 3: regs->edx = 0xdeadf00d;
            case 2: regs->ecx = 0xdeadf00d;
            case 1: regs->ebx = 0xdeadf00d;
            }
        }
#endif
    }

    HVM_DBG_LOG(DBG_LEVEL_HCALL, "hcall%lu -> %lx",
                eax, (unsigned long)regs->eax);

    if ( curr->arch.hvm_vcpu.hcall_preempted )
        return HVM_HCALL_preempted;

    if ( unlikely(currd->arch.hvm_domain.qemu_mapcache_invalidate) &&
         test_and_clear_bool(currd->arch.hvm_domain.
                             qemu_mapcache_invalidate) )
        return HVM_HCALL_invalidate;

    return HVM_HCALL_completed;
}

static void hvm_latch_shinfo_size(struct domain *d)
{
    /*
     * Called from operations which are among the very first executed by
     * PV drivers on initialisation or after save/restore. These are sensible
     * points at which to sample the execution mode of the guest and latch
     * 32- or 64-bit format for shared state.
     */
    if ( current->domain == d )
    {
        d->arch.has_32bit_shinfo = (hvm_guest_x86_mode(current) != 8);
        /*
         * Make sure that the timebase in the shared info structure is correct.
         *
         * If the bit-ness changed we should arguably try to convert the other
         * fields as well, but that's much more problematic (e.g. what do you
         * do if you're going from 64 bit to 32 bit and there's an event
         * channel pending which doesn't exist in the 32 bit version?).  Just
         * setting the wallclock time seems to be sufficient for everything
         * we do, even if it is a bit of a hack.
         */
        update_domain_wallclock_time(d);
    }
}

/* Initialise a hypercall transfer page for a VMX domain using
   paravirtualised drivers. */
void hvm_hypercall_page_initialise(struct domain *d,
                                   void *hypercall_page)
{
    hvm_latch_shinfo_size(d);
    hvm_funcs.init_hypercall_page(d, hypercall_page);
}

static int hvmop_set_pci_intx_level(
    XEN_GUEST_HANDLE_PARAM(xen_hvm_set_pci_intx_level_t) uop)
{
    struct xen_hvm_set_pci_intx_level op;
    struct domain *d;
    int rc;

    if ( copy_from_guest(&op, uop, 1) )
        return -EFAULT;

    if ( (op.domain > 0) || (op.bus > 0) || (op.device > 31) || (op.intx > 3) )
        return -EINVAL;

    rc = rcu_lock_remote_domain_by_id(op.domid, &d);
    if ( rc != 0 )
        return rc;

    rc = -EINVAL;
    if ( !is_hvm_domain(d) )
        goto out;

    rc = xsm_hvm_set_pci_intx_level(XSM_DM_PRIV, d);
    if ( rc )
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

void hvm_vcpu_reset_state(struct vcpu *v, uint16_t cs, uint16_t ip)
{
    struct domain *d = v->domain;
    struct segment_register reg;
    typeof(v->arch.xsave_area->fpu_sse) *fpu_ctxt = v->arch.fpu_ctxt;

    domain_lock(d);

    if ( v->is_initialised )
        goto out;

    if ( !paging_mode_hap(d) )
    {
        if ( v->arch.hvm_vcpu.guest_cr[0] & X86_CR0_PG )
            put_page(pagetable_get_page(v->arch.guest_table));
        v->arch.guest_table = pagetable_null();
    }

    memset(fpu_ctxt, 0, sizeof(*fpu_ctxt));
    fpu_ctxt->fcw = FCW_RESET;
    fpu_ctxt->mxcsr = MXCSR_DEFAULT;
    if ( v->arch.xsave_area )
    {
        v->arch.xsave_area->xsave_hdr.xstate_bv = XSTATE_FP;
        v->arch.xsave_area->xsave_hdr.xcomp_bv = 0;
    }

    v->arch.vgc_flags = VGCF_online;
    memset(&v->arch.user_regs, 0, sizeof(v->arch.user_regs));
    v->arch.user_regs.eflags = X86_EFLAGS_MBS;
    v->arch.user_regs.edx = 0x00000f00;
    v->arch.user_regs.eip = ip;
    memset(&v->arch.debugreg, 0, sizeof(v->arch.debugreg));

    v->arch.hvm_vcpu.guest_cr[0] = X86_CR0_ET;
    hvm_update_guest_cr(v, 0);

    v->arch.hvm_vcpu.guest_cr[2] = 0;
    hvm_update_guest_cr(v, 2);

    v->arch.hvm_vcpu.guest_cr[3] = 0;
    hvm_update_guest_cr(v, 3);

    v->arch.hvm_vcpu.guest_cr[4] = 0;
    hvm_update_guest_cr(v, 4);

    v->arch.hvm_vcpu.guest_efer = 0;
    hvm_update_guest_efer(v);

    reg.sel = cs;
    reg.base = (uint32_t)reg.sel << 4;
    reg.limit = 0xffff;
    reg.attr.bytes = 0x09b;
    hvm_set_segment_register(v, x86_seg_cs, &reg);

    reg.sel = reg.base = 0;
    reg.limit = 0xffff;
    reg.attr.bytes = 0x093;
    hvm_set_segment_register(v, x86_seg_ds, &reg);
    hvm_set_segment_register(v, x86_seg_es, &reg);
    hvm_set_segment_register(v, x86_seg_fs, &reg);
    hvm_set_segment_register(v, x86_seg_gs, &reg);
    hvm_set_segment_register(v, x86_seg_ss, &reg);

    reg.attr.bytes = 0x82; /* LDT */
    hvm_set_segment_register(v, x86_seg_ldtr, &reg);

    reg.attr.bytes = 0x8b; /* 32-bit TSS (busy) */
    hvm_set_segment_register(v, x86_seg_tr, &reg);

    reg.attr.bytes = 0;
    hvm_set_segment_register(v, x86_seg_gdtr, &reg);
    hvm_set_segment_register(v, x86_seg_idtr, &reg);

    if ( hvm_funcs.tsc_scaling.setup )
        hvm_funcs.tsc_scaling.setup(v);

    /* Sync AP's TSC with BSP's. */
    v->arch.hvm_vcpu.cache_tsc_offset =
        v->domain->vcpu[0]->arch.hvm_vcpu.cache_tsc_offset;
    hvm_funcs.set_tsc_offset(v, v->arch.hvm_vcpu.cache_tsc_offset,
                             d->arch.hvm_domain.sync_tsc);

    v->arch.hvm_vcpu.msr_tsc_adjust = 0;

    paging_update_paging_modes(v);

    v->arch.flags |= TF_kernel_mode;
    v->is_initialised = 1;
    clear_bit(_VPF_down, &v->pause_flags);

 out:
    domain_unlock(d);
}

static void hvm_s3_suspend(struct domain *d)
{
    struct vcpu *v;

    domain_pause(d);
    domain_lock(d);

    if ( d->is_dying || (d->vcpu == NULL) || (d->vcpu[0] == NULL) ||
         test_and_set_bool(d->arch.hvm_domain.is_s3_suspended) )
    {
        domain_unlock(d);
        domain_unpause(d);
        return;
    }

    for_each_vcpu ( d, v )
    {
        int rc;

        vlapic_reset(vcpu_vlapic(v));
        rc = vcpu_reset(v);
        ASSERT(!rc);
    }

    vpic_reset(d);
    vioapic_reset(d);
    pit_reset(d);
    rtc_reset(d);
    pmtimer_reset(d);
    hpet_reset(d);

    hvm_vcpu_reset_state(d->vcpu[0], 0xf000, 0xfff0);

    domain_unlock(d);
}

static void hvm_s3_resume(struct domain *d)
{
    if ( test_and_clear_bool(d->arch.hvm_domain.is_s3_suspended) )
    {
        struct vcpu *v;

        for_each_vcpu( d, v )
            hvm_set_guest_tsc(v, 0);
        domain_unpause(d);
    }
}

static int hvmop_set_isa_irq_level(
    XEN_GUEST_HANDLE_PARAM(xen_hvm_set_isa_irq_level_t) uop)
{
    struct xen_hvm_set_isa_irq_level op;
    struct domain *d;
    int rc;

    if ( copy_from_guest(&op, uop, 1) )
        return -EFAULT;

    if ( op.isa_irq > 15 )
        return -EINVAL;

    rc = rcu_lock_remote_domain_by_id(op.domid, &d);
    if ( rc != 0 )
        return rc;

    rc = -EINVAL;
    if ( !is_hvm_domain(d) )
        goto out;

    rc = xsm_hvm_set_isa_irq_level(XSM_DM_PRIV, d);
    if ( rc )
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
    XEN_GUEST_HANDLE_PARAM(xen_hvm_set_pci_link_route_t) uop)
{
    struct xen_hvm_set_pci_link_route op;
    struct domain *d;
    int rc;

    if ( copy_from_guest(&op, uop, 1) )
        return -EFAULT;

    if ( (op.link > 3) || (op.isa_irq > 15) )
        return -EINVAL;

    rc = rcu_lock_remote_domain_by_id(op.domid, &d);
    if ( rc != 0 )
        return rc;

    rc = -EINVAL;
    if ( !is_hvm_domain(d) )
        goto out;

    rc = xsm_hvm_set_pci_link_route(XSM_DM_PRIV, d);
    if ( rc )
        goto out;

    rc = 0;
    hvm_set_pci_link_route(d, op.link, op.isa_irq);

 out:
    rcu_unlock_domain(d);
    return rc;
}

static int hvmop_inject_msi(
    XEN_GUEST_HANDLE_PARAM(xen_hvm_inject_msi_t) uop)
{
    struct xen_hvm_inject_msi op;
    struct domain *d;
    int rc;

    if ( copy_from_guest(&op, uop, 1) )
        return -EFAULT;

    rc = rcu_lock_remote_domain_by_id(op.domid, &d);
    if ( rc != 0 )
        return rc;

    rc = -EINVAL;
    if ( !is_hvm_domain(d) )
        goto out;

    rc = xsm_hvm_inject_msi(XSM_DM_PRIV, d);
    if ( rc )
        goto out;

    rc = hvm_inject_msi(d, op.addr, op.data);

 out:
    rcu_unlock_domain(d);
    return rc;
}

static int hvmop_flush_tlb_all(void)
{
    struct domain *d = current->domain;
    struct vcpu *v;

    if ( !is_hvm_domain(d) )
        return -EINVAL;

    /* Avoid deadlock if more than one vcpu tries this at the same time. */
    if ( !spin_trylock(&d->hypercall_deadlock_mutex) )
        return -ERESTART;

    /* Pause all other vcpus. */
    for_each_vcpu ( d, v )
        if ( v != current )
            vcpu_pause_nosync(v);

    /* Now that all VCPUs are signalled to deschedule, we wait... */
    for_each_vcpu ( d, v )
        if ( v != current )
            while ( !vcpu_runnable(v) && v->is_running )
                cpu_relax();

    /* All other vcpus are paused, safe to unlock now. */
    spin_unlock(&d->hypercall_deadlock_mutex);

    /* Flush paging-mode soft state (e.g., va->gfn cache; PAE PDPE cache). */
    for_each_vcpu ( d, v )
        paging_update_cr3(v);

    /* Flush all dirty TLBs. */
    flush_tlb_mask(d->domain_dirty_cpumask);

    /* Done. */
    for_each_vcpu ( d, v )
        if ( v != current )
            vcpu_unpause(v);

    return 0;
}

static int hvmop_create_ioreq_server(
    XEN_GUEST_HANDLE_PARAM(xen_hvm_create_ioreq_server_t) uop)
{
    struct domain *curr_d = current->domain;
    xen_hvm_create_ioreq_server_t op;
    struct domain *d;
    int rc;

    if ( copy_from_guest(&op, uop, 1) )
        return -EFAULT;

    rc = rcu_lock_remote_domain_by_id(op.domid, &d);
    if ( rc != 0 )
        return rc;

    rc = -EINVAL;
    if ( !is_hvm_domain(d) )
        goto out;

    rc = xsm_hvm_ioreq_server(XSM_DM_PRIV, d, HVMOP_create_ioreq_server);
    if ( rc != 0 )
        goto out;

    rc = hvm_create_ioreq_server(d, curr_d->domain_id, 0,
                                 op.handle_bufioreq, &op.id);
    if ( rc != 0 )
        goto out;

    rc = copy_to_guest(uop, &op, 1) ? -EFAULT : 0;
    
 out:
    rcu_unlock_domain(d);
    return rc;
}

static int hvmop_get_ioreq_server_info(
    XEN_GUEST_HANDLE_PARAM(xen_hvm_get_ioreq_server_info_t) uop)
{
    xen_hvm_get_ioreq_server_info_t op;
    struct domain *d;
    int rc;

    if ( copy_from_guest(&op, uop, 1) )
        return -EFAULT;

    rc = rcu_lock_remote_domain_by_id(op.domid, &d);
    if ( rc != 0 )
        return rc;

    rc = -EINVAL;
    if ( !is_hvm_domain(d) )
        goto out;

    rc = xsm_hvm_ioreq_server(XSM_DM_PRIV, d, HVMOP_get_ioreq_server_info);
    if ( rc != 0 )
        goto out;

    rc = hvm_get_ioreq_server_info(d, op.id,
                                   &op.ioreq_pfn,
                                   &op.bufioreq_pfn, 
                                   &op.bufioreq_port);
    if ( rc != 0 )
        goto out;

    rc = copy_to_guest(uop, &op, 1) ? -EFAULT : 0;
    
 out:
    rcu_unlock_domain(d);
    return rc;
}

static int hvmop_map_io_range_to_ioreq_server(
    XEN_GUEST_HANDLE_PARAM(xen_hvm_io_range_t) uop)
{
    xen_hvm_io_range_t op;
    struct domain *d;
    int rc;

    if ( copy_from_guest(&op, uop, 1) )
        return -EFAULT;

    rc = rcu_lock_remote_domain_by_id(op.domid, &d);
    if ( rc != 0 )
        return rc;

    rc = -EINVAL;
    if ( !is_hvm_domain(d) )
        goto out;

    rc = xsm_hvm_ioreq_server(XSM_DM_PRIV, d, HVMOP_map_io_range_to_ioreq_server);
    if ( rc != 0 )
        goto out;

    rc = hvm_map_io_range_to_ioreq_server(d, op.id, op.type,
                                          op.start, op.end);

 out:
    rcu_unlock_domain(d);
    return rc;
}

static int hvmop_unmap_io_range_from_ioreq_server(
    XEN_GUEST_HANDLE_PARAM(xen_hvm_io_range_t) uop)
{
    xen_hvm_io_range_t op;
    struct domain *d;
    int rc;

    if ( copy_from_guest(&op, uop, 1) )
        return -EFAULT;

    rc = rcu_lock_remote_domain_by_id(op.domid, &d);
    if ( rc != 0 )
        return rc;

    rc = -EINVAL;
    if ( !is_hvm_domain(d) )
        goto out;

    rc = xsm_hvm_ioreq_server(XSM_DM_PRIV, d, HVMOP_unmap_io_range_from_ioreq_server);
    if ( rc != 0 )
        goto out;

    rc = hvm_unmap_io_range_from_ioreq_server(d, op.id, op.type,
                                              op.start, op.end);
    
 out:
    rcu_unlock_domain(d);
    return rc;
}

static int hvmop_set_ioreq_server_state(
    XEN_GUEST_HANDLE_PARAM(xen_hvm_set_ioreq_server_state_t) uop)
{
    xen_hvm_set_ioreq_server_state_t op;
    struct domain *d;
    int rc;

    if ( copy_from_guest(&op, uop, 1) )
        return -EFAULT;

    rc = rcu_lock_remote_domain_by_id(op.domid, &d);
    if ( rc != 0 )
        return rc;

    rc = -EINVAL;
    if ( !is_hvm_domain(d) )
        goto out;

    rc = xsm_hvm_ioreq_server(XSM_DM_PRIV, d, HVMOP_set_ioreq_server_state);
    if ( rc != 0 )
        goto out;

    rc = hvm_set_ioreq_server_state(d, op.id, !!op.enabled);

 out:
    rcu_unlock_domain(d);
    return rc;
}

static int hvmop_destroy_ioreq_server(
    XEN_GUEST_HANDLE_PARAM(xen_hvm_destroy_ioreq_server_t) uop)
{
    xen_hvm_destroy_ioreq_server_t op;
    struct domain *d;
    int rc;

    if ( copy_from_guest(&op, uop, 1) )
        return -EFAULT;

    rc = rcu_lock_remote_domain_by_id(op.domid, &d);
    if ( rc != 0 )
        return rc;

    rc = -EINVAL;
    if ( !is_hvm_domain(d) )
        goto out;

    rc = xsm_hvm_ioreq_server(XSM_DM_PRIV, d, HVMOP_destroy_ioreq_server);
    if ( rc != 0 )
        goto out;

    rc = hvm_destroy_ioreq_server(d, op.id);

 out:
    rcu_unlock_domain(d);
    return rc;
}

static int hvmop_set_evtchn_upcall_vector(
    XEN_GUEST_HANDLE_PARAM(xen_hvm_evtchn_upcall_vector_t) uop)
{
    xen_hvm_evtchn_upcall_vector_t op;
    struct domain *d = current->domain;
    struct vcpu *v;

    if ( copy_from_guest(&op, uop, 1) )
        return -EFAULT;

    if ( !is_hvm_domain(d) )
        return -EINVAL;

    if ( op.vector < 0x10 )
        return -EINVAL;

    if ( op.vcpu >= d->max_vcpus || (v = d->vcpu[op.vcpu]) == NULL )
        return -ENOENT;

    printk(XENLOG_G_INFO "%pv: upcall vector %02x\n", v, op.vector);

    v->arch.hvm_vcpu.evtchn_upcall_vector = op.vector;
    return 0;
}

static int hvm_allow_set_param(struct domain *d,
                               const struct xen_hvm_param *a)
{
    uint64_t value = d->arch.hvm_domain.params[a->index];
    int rc;

    rc = xsm_hvm_param(XSM_TARGET, d, HVMOP_set_param);
    if ( rc )
        return rc;

    switch ( a->index )
    {
    /* The following parameters can be set by the guest. */
    case HVM_PARAM_CALLBACK_IRQ:
    case HVM_PARAM_VM86_TSS:
    case HVM_PARAM_ACPI_IOPORTS_LOCATION:
    case HVM_PARAM_VM_GENERATION_ID_ADDR:
    case HVM_PARAM_STORE_EVTCHN:
    case HVM_PARAM_CONSOLE_EVTCHN:
    case HVM_PARAM_X87_FIP_WIDTH:
        break;
    /*
     * The following parameters must not be set by the guest
     * since the domain may need to be paused.
     */
    case HVM_PARAM_IDENT_PT:
    case HVM_PARAM_DM_DOMAIN:
    case HVM_PARAM_ACPI_S_STATE:
    /* The remaining parameters should not be set by the guest. */
    default:
        if ( d == current->domain )
            rc = -EPERM;
        break;
    }

    if ( rc )
        return rc;

    switch ( a->index )
    {
    /* The following parameters should only be changed once. */
    case HVM_PARAM_VIRIDIAN:
    case HVM_PARAM_IOREQ_SERVER_PFN:
    case HVM_PARAM_NR_IOREQ_SERVER_PAGES:
    case HVM_PARAM_ALTP2M:
        if ( value != 0 && a->value != value )
            rc = -EEXIST;
        break;
    default:
        break;
    }

    return rc;
}

static int hvmop_set_param(
    XEN_GUEST_HANDLE_PARAM(xen_hvm_param_t) arg)
{
    struct domain *curr_d = current->domain;
    struct xen_hvm_param a;
    struct domain *d;
    struct vcpu *v;
    int rc;

    if ( copy_from_guest(&a, arg, 1) )
        return -EFAULT;

    if ( a.index >= HVM_NR_PARAMS )
        return -EINVAL;

    d = rcu_lock_domain_by_any_id(a.domid);
    if ( d == NULL )
        return -ESRCH;

    rc = -EINVAL;
    if ( !has_hvm_container_domain(d) ||
         (is_pvh_domain(d) && (a.index != HVM_PARAM_CALLBACK_IRQ)) )
        goto out;

    rc = hvm_allow_set_param(d, &a);
    if ( rc )
        goto out;

    switch ( a.index )
    {
    case HVM_PARAM_CALLBACK_IRQ:
        hvm_set_callback_via(d, a.value);
        hvm_latch_shinfo_size(d);
        break;
    case HVM_PARAM_TIMER_MODE:
        if ( a.value > HVMPTM_one_missed_tick_pending )
            rc = -EINVAL;
        break;
    case HVM_PARAM_VIRIDIAN:
        if ( (a.value & ~HVMPV_feature_mask) ||
             !(a.value & HVMPV_base_freq) )
            rc = -EINVAL;
        break;
    case HVM_PARAM_IDENT_PT:
        /*
         * Only actually required for VT-x lacking unrestricted_guest
         * capabilities.  Short circuit the pause if possible.
         */
        if ( !paging_mode_hap(d) || !cpu_has_vmx )
        {
            d->arch.hvm_domain.params[a.index] = a.value;
            break;
        }

        /*
         * Update GUEST_CR3 in each VMCS to point at identity map.
         * All foreign updates to guest state must synchronise on
         * the domctl_lock.
         */
        rc = -ERESTART;
        if ( !domctl_lock_acquire() )
            break;

        rc = 0;
        domain_pause(d);
        d->arch.hvm_domain.params[a.index] = a.value;
        for_each_vcpu ( d, v )
            paging_update_cr3(v);
        domain_unpause(d);

        domctl_lock_release();
        break;
    case HVM_PARAM_DM_DOMAIN:
        if ( a.value == DOMID_SELF )
            a.value = curr_d->domain_id;

        rc = hvm_set_dm_domain(d, a.value);
        break;
    case HVM_PARAM_ACPI_S_STATE:
        rc = 0;
        if ( a.value == 3 )
            hvm_s3_suspend(d);
        else if ( a.value == 0 )
            hvm_s3_resume(d);
        else
            rc = -EINVAL;

        break;
    case HVM_PARAM_ACPI_IOPORTS_LOCATION:
        rc = pmtimer_change_ioport(d, a.value);
        break;
    case HVM_PARAM_MEMORY_EVENT_CR0:
    case HVM_PARAM_MEMORY_EVENT_CR3:
    case HVM_PARAM_MEMORY_EVENT_CR4:
    case HVM_PARAM_MEMORY_EVENT_INT3:
    case HVM_PARAM_MEMORY_EVENT_SINGLE_STEP:
    case HVM_PARAM_MEMORY_EVENT_MSR:
        /* Deprecated */
        rc = -EOPNOTSUPP;
        break;
    case HVM_PARAM_NESTEDHVM:
        rc = xsm_hvm_param_nested(XSM_PRIV, d);
        if ( rc )
            break;
        if ( a.value > 1 )
            rc = -EINVAL;
        /*
         * Remove the check below once we have
         * shadow-on-shadow.
         */
        if ( cpu_has_svm && !paging_mode_hap(d) && a.value )
            rc = -EINVAL;
        if ( a.value &&
             d->arch.hvm_domain.params[HVM_PARAM_ALTP2M] )
            rc = -EINVAL;
        /* Set up NHVM state for any vcpus that are already up. */
        if ( a.value &&
             !d->arch.hvm_domain.params[HVM_PARAM_NESTEDHVM] )
            for_each_vcpu(d, v)
                if ( rc == 0 )
                    rc = nestedhvm_vcpu_initialise(v);
        if ( !a.value || rc )
            for_each_vcpu(d, v)
                nestedhvm_vcpu_destroy(v);
        break;
    case HVM_PARAM_ALTP2M:
        rc = xsm_hvm_param_altp2mhvm(XSM_PRIV, d);
        if ( rc )
            break;
        if ( a.value > 1 )
            rc = -EINVAL;
        if ( a.value &&
             d->arch.hvm_domain.params[HVM_PARAM_NESTEDHVM] )
            rc = -EINVAL;
        break;
    case HVM_PARAM_BUFIOREQ_EVTCHN:
        rc = -EINVAL;
        break;
    case HVM_PARAM_TRIPLE_FAULT_REASON:
        if ( a.value > SHUTDOWN_MAX )
            rc = -EINVAL;
        break;
    case HVM_PARAM_IOREQ_SERVER_PFN:
        d->arch.hvm_domain.ioreq_gmfn.base = a.value;
        break;
    case HVM_PARAM_NR_IOREQ_SERVER_PAGES:
    {
        unsigned int i;

        if ( a.value == 0 ||
             a.value > sizeof(d->arch.hvm_domain.ioreq_gmfn.mask) * 8 )
        {
            rc = -EINVAL;
            break;
        }
        for ( i = 0; i < a.value; i++ )
            set_bit(i, &d->arch.hvm_domain.ioreq_gmfn.mask);

        break;
    }
    case HVM_PARAM_X87_FIP_WIDTH:
        if ( a.value != 0 && a.value != 4 && a.value != 8 )
        {
            rc = -EINVAL;
            break;
        }
        d->arch.x87_fip_width = a.value;
        break;
    }

    if ( rc != 0 )
        goto out;

    d->arch.hvm_domain.params[a.index] = a.value;

    HVM_DBG_LOG(DBG_LEVEL_HCALL, "set param %u = %"PRIx64,
                a.index, a.value);

 out:
    rcu_unlock_domain(d);
    return rc;
}

static int hvm_allow_get_param(struct domain *d,
                               const struct xen_hvm_param *a)
{
    int rc;

    rc = xsm_hvm_param(XSM_TARGET, d, HVMOP_get_param);
    if ( rc )
        return rc;

    switch ( a->index )
    {
    /* The following parameters can be read by the guest. */
    case HVM_PARAM_CALLBACK_IRQ:
    case HVM_PARAM_VM86_TSS:
    case HVM_PARAM_ACPI_IOPORTS_LOCATION:
    case HVM_PARAM_VM_GENERATION_ID_ADDR:
    case HVM_PARAM_STORE_PFN:
    case HVM_PARAM_STORE_EVTCHN:
    case HVM_PARAM_CONSOLE_PFN:
    case HVM_PARAM_CONSOLE_EVTCHN:
    case HVM_PARAM_ALTP2M:
    case HVM_PARAM_X87_FIP_WIDTH:
        break;
    /*
     * The following parameters must not be read by the guest
     * since the domain may need to be paused.
     */
    case HVM_PARAM_IOREQ_PFN:
    case HVM_PARAM_BUFIOREQ_PFN:
    case HVM_PARAM_BUFIOREQ_EVTCHN:
    /* The remaining parameters should not be read by the guest. */
    default:
        if ( d == current->domain )
            rc = -EPERM;
        break;
    }

    return rc;
}

static int hvmop_get_param(
    XEN_GUEST_HANDLE_PARAM(xen_hvm_param_t) arg)
{
    struct xen_hvm_param a;
    struct domain *d;
    int rc;

    if ( copy_from_guest(&a, arg, 1) )
        return -EFAULT;

    if ( a.index >= HVM_NR_PARAMS )
        return -EINVAL;

    d = rcu_lock_domain_by_any_id(a.domid);
    if ( d == NULL )
        return -ESRCH;

    rc = -EINVAL;
    if ( !has_hvm_container_domain(d) ||
         (is_pvh_domain(d) && (a.index != HVM_PARAM_CALLBACK_IRQ)) )
        goto out;

    rc = hvm_allow_get_param(d, &a);
    if ( rc )
        goto out;

    switch ( a.index )
    {
    case HVM_PARAM_ACPI_S_STATE:
        a.value = d->arch.hvm_domain.is_s3_suspended ? 3 : 0;
        break;
    case HVM_PARAM_X87_FIP_WIDTH:
        a.value = d->arch.x87_fip_width;
        break;
    case HVM_PARAM_IOREQ_PFN:
    case HVM_PARAM_BUFIOREQ_PFN:
    case HVM_PARAM_BUFIOREQ_EVTCHN:
        /*
         * It may be necessary to create a default ioreq server here,
         * because legacy versions of QEMU are not aware of the new API for
         * explicit ioreq server creation. However, if the domain is not
         * under construction then it will not be QEMU querying the
         * parameters and thus the query should not have that side-effect.
         */
        if ( !d->creation_finished )
        {
            domid_t domid = d->arch.hvm_domain.params[HVM_PARAM_DM_DOMAIN];

            rc = hvm_create_ioreq_server(d, domid, 1,
                                         HVM_IOREQSRV_BUFIOREQ_LEGACY, NULL);
            if ( rc != 0 && rc != -EEXIST )
                goto out;
        }

    /*FALLTHRU*/
    default:
        a.value = d->arch.hvm_domain.params[a.index];
        break;
    }

    rc = __copy_to_guest(arg, &a, 1) ? -EFAULT : 0;

    HVM_DBG_LOG(DBG_LEVEL_HCALL, "get param %u = %"PRIx64,
                a.index, a.value);

 out:
    rcu_unlock_domain(d);
    return rc;
}

static int do_altp2m_op(
    XEN_GUEST_HANDLE_PARAM(void) arg)
{
    struct xen_hvm_altp2m_op a;
    struct domain *d = NULL;
    int rc = 0;

    if ( !hvm_altp2m_supported() )
        return -EOPNOTSUPP;

    if ( copy_from_guest(&a, arg, 1) )
        return -EFAULT;

    if ( a.pad1 || a.pad2 ||
         (a.version != HVMOP_ALTP2M_INTERFACE_VERSION) )
        return -EINVAL;

    switch ( a.cmd )
    {
    case HVMOP_altp2m_get_domain_state:
    case HVMOP_altp2m_set_domain_state:
    case HVMOP_altp2m_vcpu_enable_notify:
    case HVMOP_altp2m_create_p2m:
    case HVMOP_altp2m_destroy_p2m:
    case HVMOP_altp2m_switch_p2m:
    case HVMOP_altp2m_set_mem_access:
    case HVMOP_altp2m_change_gfn:
        break;
    default:
        return -EOPNOTSUPP;
    }

    d = ( a.cmd != HVMOP_altp2m_vcpu_enable_notify ) ?
        rcu_lock_domain_by_any_id(a.domain) : rcu_lock_current_domain();

    if ( d == NULL )
        return -ESRCH;

    if ( !is_hvm_domain(d) )
    {
        rc = -EOPNOTSUPP;
        goto out;
    }

    if ( (a.cmd != HVMOP_altp2m_get_domain_state) &&
         (a.cmd != HVMOP_altp2m_set_domain_state) &&
         !d->arch.altp2m_active )
    {
        rc = -EOPNOTSUPP;
        goto out;
    }

    if ( (rc = xsm_hvm_altp2mhvm_op(XSM_TARGET, d)) )
        goto out;

    switch ( a.cmd )
    {
    case HVMOP_altp2m_get_domain_state:
        if ( !d->arch.hvm_domain.params[HVM_PARAM_ALTP2M] )
        {
            rc = -EINVAL;
            break;
        }

        a.u.domain_state.state = altp2m_active(d);
        rc = __copy_to_guest(arg, &a, 1) ? -EFAULT : 0;
        break;

    case HVMOP_altp2m_set_domain_state:
    {
        struct vcpu *v;
        bool_t ostate;

        if ( !d->arch.hvm_domain.params[HVM_PARAM_ALTP2M] ||
             nestedhvm_enabled(d) )
        {
            rc = -EINVAL;
            break;
        }

        ostate = d->arch.altp2m_active;
        d->arch.altp2m_active = !!a.u.domain_state.state;

        /* If the alternate p2m state has changed, handle appropriately */
        if ( d->arch.altp2m_active != ostate &&
             (ostate || !(rc = p2m_init_altp2m_by_id(d, 0))) )
        {
            for_each_vcpu( d, v )
            {
                if ( !ostate )
                    altp2m_vcpu_initialise(v);
                else
                    altp2m_vcpu_destroy(v);
            }

            if ( ostate )
                p2m_flush_altp2m(d);
        }
        break;
    }

    case HVMOP_altp2m_vcpu_enable_notify:
    {
        struct vcpu *curr = current;
        p2m_type_t p2mt;

        if ( a.u.enable_notify.pad || a.domain != DOMID_SELF ||
             a.u.enable_notify.vcpu_id != curr->vcpu_id )
            rc = -EINVAL;

        if ( !gfn_eq(vcpu_altp2m(curr).veinfo_gfn, INVALID_GFN) ||
             mfn_eq(get_gfn_query_unlocked(curr->domain,
                    a.u.enable_notify.gfn, &p2mt), INVALID_MFN) )
            return -EINVAL;

        vcpu_altp2m(curr).veinfo_gfn = _gfn(a.u.enable_notify.gfn);
        altp2m_vcpu_update_vmfunc_ve(curr);
        break;
    }

    case HVMOP_altp2m_create_p2m:
        if ( !(rc = p2m_init_next_altp2m(d, &a.u.view.view)) )
            rc = __copy_to_guest(arg, &a, 1) ? -EFAULT : 0;
        break;

    case HVMOP_altp2m_destroy_p2m:
        rc = p2m_destroy_altp2m_by_id(d, a.u.view.view);
        break;

    case HVMOP_altp2m_switch_p2m:
        rc = p2m_switch_domain_altp2m_by_id(d, a.u.view.view);
        break;

    case HVMOP_altp2m_set_mem_access:
        if ( a.u.set_mem_access.pad )
            rc = -EINVAL;
        else
            rc = p2m_set_mem_access(d, _gfn(a.u.set_mem_access.gfn), 1, 0, 0,
                                    a.u.set_mem_access.hvmmem_access,
                                    a.u.set_mem_access.view);
        break;

    case HVMOP_altp2m_change_gfn:
        if ( a.u.change_gfn.pad1 || a.u.change_gfn.pad2 )
            rc = -EINVAL;
        else
            rc = p2m_change_altp2m_gfn(d, a.u.change_gfn.view,
                    _gfn(a.u.change_gfn.old_gfn),
                    _gfn(a.u.change_gfn.new_gfn));
        break;
    default:
        ASSERT_UNREACHABLE();
    }

 out:
    rcu_unlock_domain(d);

    return rc;
}

static int hvmop_get_mem_type(
    XEN_GUEST_HANDLE_PARAM(xen_hvm_get_mem_type_t) arg)
{
    struct xen_hvm_get_mem_type a;
    struct domain *d;
    p2m_type_t t;
    int rc;

    if ( copy_from_guest(&a, arg, 1) )
        return -EFAULT;

    d = rcu_lock_domain_by_any_id(a.domid);
    if ( d == NULL )
        return -ESRCH;

    rc = xsm_hvm_param(XSM_TARGET, d, HVMOP_get_mem_type);
    if ( rc )
        goto out;

    rc = -EINVAL;
    if ( !is_hvm_domain(d) )
        goto out;

    /*
     * Use get_gfn query as we are interested in the current
     * type, not in allocating or unsharing. That'll happen
     * on access.
     */
    get_gfn_query_unlocked(d, a.pfn, &t);
    if ( p2m_is_mmio(t) )
        a.mem_type =  HVMMEM_mmio_dm;
    else if ( t == p2m_ioreq_server )
        a.mem_type = HVMMEM_ioreq_server;
    else if ( p2m_is_readonly(t) )
        a.mem_type =  HVMMEM_ram_ro;
    else if ( p2m_is_ram(t) )
        a.mem_type =  HVMMEM_ram_rw;
    else if ( p2m_is_pod(t) )
        a.mem_type =  HVMMEM_ram_rw;
    else if ( p2m_is_grant(t) )
        a.mem_type =  HVMMEM_ram_rw;
    else
        a.mem_type =  HVMMEM_mmio_dm;

    rc = -EFAULT;
    if ( __copy_to_guest(arg, &a, 1) )
        goto out;
    rc = 0;

 out:
    rcu_unlock_domain(d);

    return rc;
}

/*
 * Note that this value is effectively part of the ABI, even if we don't need
 * to make it a formal part of it: A guest suspended for migration in the
 * middle of a continuation would fail to work if resumed on a hypervisor
 * using a different value.
 */
#define HVMOP_op_mask 0xff

static bool_t hvm_allow_p2m_type_change(p2m_type_t old, p2m_type_t new)
{
    if ( p2m_is_ram(old) ||
         (p2m_is_hole(old) && new == p2m_mmio_dm) ||
         (old == p2m_ioreq_server && new == p2m_ram_rw) )
        return 1;

    return 0;
}

static int hvmop_set_mem_type(
    XEN_GUEST_HANDLE_PARAM(xen_hvm_set_mem_type_t) arg,
    unsigned long *iter)
{
    unsigned long start_iter = *iter;
    struct xen_hvm_set_mem_type a;
    struct domain *d;
    int rc;

    /* Interface types to internal p2m types */
    static const p2m_type_t memtype[] = {
        [HVMMEM_ram_rw]  = p2m_ram_rw,
        [HVMMEM_ram_ro]  = p2m_ram_ro,
        [HVMMEM_mmio_dm] = p2m_mmio_dm,
        [HVMMEM_unused] = p2m_invalid,
        [HVMMEM_ioreq_server] = p2m_ioreq_server
    };

    if ( copy_from_guest(&a, arg, 1) )
        return -EFAULT;

    rc = rcu_lock_remote_domain_by_id(a.domid, &d);
    if ( rc != 0 )
        return rc;

    rc = -EINVAL;
    if ( !is_hvm_domain(d) )
        goto out;

    rc = xsm_hvm_control(XSM_DM_PRIV, d, HVMOP_set_mem_type);
    if ( rc )
        goto out;

    rc = -EINVAL;
    if ( a.nr < start_iter ||
         ((a.first_pfn + a.nr - 1) < a.first_pfn) ||
         ((a.first_pfn + a.nr - 1) > domain_get_maximum_gpfn(d)) )
        goto out;

    if ( a.hvmmem_type >= ARRAY_SIZE(memtype) ||
         unlikely(a.hvmmem_type == HVMMEM_unused) )
        goto out;

    while ( a.nr > start_iter )
    {
        unsigned long pfn = a.first_pfn + start_iter;
        p2m_type_t t;

        get_gfn_unshare(d, pfn, &t);
        if ( p2m_is_paging(t) )
        {
            put_gfn(d, pfn);
            p2m_mem_paging_populate(d, pfn);
            rc = -EAGAIN;
            goto out;
        }
        if ( p2m_is_shared(t) )
        {
            put_gfn(d, pfn);
            rc = -EAGAIN;
            goto out;
        }
        if ( !hvm_allow_p2m_type_change(t, memtype[a.hvmmem_type]) )
        {
            put_gfn(d, pfn);
            goto out;
        }

        rc = p2m_change_type_one(d, pfn, t, memtype[a.hvmmem_type]);
        put_gfn(d, pfn);

        if ( rc )
            goto out;

        /* Check for continuation if it's not the last interation */
        if ( a.nr > ++start_iter && !(start_iter & HVMOP_op_mask) &&
             hypercall_preempt_check() )
        {
            rc = -ERESTART;
            goto out;
        }
    }
    rc = 0;

 out:
    rcu_unlock_domain(d);
    *iter = start_iter;

    return rc;
}

long do_hvm_op(unsigned long op, XEN_GUEST_HANDLE_PARAM(void) arg)
{
    unsigned long start_iter, mask;
    long rc = 0;

    switch ( op & HVMOP_op_mask )
    {
    default:
        mask = ~0UL;
        break;
    case HVMOP_modified_memory:
    case HVMOP_set_mem_type:
        mask = HVMOP_op_mask;
        break;
    }

    start_iter = op & ~mask;
    switch ( op &= mask )
    {
    case HVMOP_create_ioreq_server:
        rc = hvmop_create_ioreq_server(
            guest_handle_cast(arg, xen_hvm_create_ioreq_server_t));
        break;
    
    case HVMOP_get_ioreq_server_info:
        rc = hvmop_get_ioreq_server_info(
            guest_handle_cast(arg, xen_hvm_get_ioreq_server_info_t));
        break;
    
    case HVMOP_map_io_range_to_ioreq_server:
        rc = hvmop_map_io_range_to_ioreq_server(
            guest_handle_cast(arg, xen_hvm_io_range_t));
        break;
    
    case HVMOP_unmap_io_range_from_ioreq_server:
        rc = hvmop_unmap_io_range_from_ioreq_server(
            guest_handle_cast(arg, xen_hvm_io_range_t));
        break;

    case HVMOP_set_ioreq_server_state:
        rc = hvmop_set_ioreq_server_state(
            guest_handle_cast(arg, xen_hvm_set_ioreq_server_state_t));
        break;
    
    case HVMOP_destroy_ioreq_server:
        rc = hvmop_destroy_ioreq_server(
            guest_handle_cast(arg, xen_hvm_destroy_ioreq_server_t));
        break;
    
    case HVMOP_set_evtchn_upcall_vector:
        rc = hvmop_set_evtchn_upcall_vector(
            guest_handle_cast(arg, xen_hvm_evtchn_upcall_vector_t));
        break;
    
    case HVMOP_set_param:
        rc = hvmop_set_param(
            guest_handle_cast(arg, xen_hvm_param_t));
        break;

    case HVMOP_get_param:
        rc = hvmop_get_param(
            guest_handle_cast(arg, xen_hvm_param_t));
        break;

    case HVMOP_set_pci_intx_level:
        rc = hvmop_set_pci_intx_level(
            guest_handle_cast(arg, xen_hvm_set_pci_intx_level_t));
        break;

    case HVMOP_set_isa_irq_level:
        rc = hvmop_set_isa_irq_level(
            guest_handle_cast(arg, xen_hvm_set_isa_irq_level_t));
        break;

    case HVMOP_inject_msi:
        rc = hvmop_inject_msi(
            guest_handle_cast(arg, xen_hvm_inject_msi_t));
        break;

    case HVMOP_set_pci_link_route:
        rc = hvmop_set_pci_link_route(
            guest_handle_cast(arg, xen_hvm_set_pci_link_route_t));
        break;

    case HVMOP_flush_tlbs:
        rc = guest_handle_is_null(arg) ? hvmop_flush_tlb_all() : -EINVAL;
        break;

    case HVMOP_track_dirty_vram:
    {
        struct xen_hvm_track_dirty_vram a;
        struct domain *d;

        if ( copy_from_guest(&a, arg, 1) )
            return -EFAULT;

        rc = rcu_lock_remote_domain_by_id(a.domid, &d);
        if ( rc != 0 )
            return rc;

        rc = -EINVAL;
        if ( !is_hvm_domain(d) )
            goto tdv_fail;

        if ( a.nr > GB(1) >> PAGE_SHIFT )
            goto tdv_fail;

        rc = xsm_hvm_control(XSM_DM_PRIV, d, op);
        if ( rc )
            goto tdv_fail;

        rc = -ESRCH;
        if ( d->is_dying )
            goto tdv_fail;

        rc = -EINVAL;
        if ( d->vcpu == NULL || d->vcpu[0] == NULL )
            goto tdv_fail;

        if ( shadow_mode_enabled(d) )
            rc = shadow_track_dirty_vram(d, a.first_pfn, a.nr, a.dirty_bitmap);
        else
            rc = hap_track_dirty_vram(d, a.first_pfn, a.nr, a.dirty_bitmap);

    tdv_fail:
        rcu_unlock_domain(d);
        break;
    }

    case HVMOP_modified_memory:
    {
        struct xen_hvm_modified_memory a;
        struct domain *d;

        if ( copy_from_guest(&a, arg, 1) )
            return -EFAULT;

        rc = rcu_lock_remote_domain_by_id(a.domid, &d);
        if ( rc != 0 )
            return rc;

        rc = -EINVAL;
        if ( !is_hvm_domain(d) )
            goto modmem_fail;

        rc = xsm_hvm_control(XSM_DM_PRIV, d, op);
        if ( rc )
            goto modmem_fail;

        rc = -EINVAL;
        if ( a.nr < start_iter ||
             ((a.first_pfn + a.nr - 1) < a.first_pfn) ||
             ((a.first_pfn + a.nr - 1) > domain_get_maximum_gpfn(d)) )
            goto modmem_fail;

        rc = 0;
        if ( !paging_mode_log_dirty(d) )
            goto modmem_fail;

        while ( a.nr > start_iter )
        {
            unsigned long pfn = a.first_pfn + start_iter;
            struct page_info *page;

            page = get_page_from_gfn(d, pfn, NULL, P2M_UNSHARE);
            if ( page )
            {
                paging_mark_dirty(d, page_to_mfn(page));
                /* These are most probably not page tables any more */
                /* don't take a long time and don't die either */
                sh_remove_shadows(d, _mfn(page_to_mfn(page)), 1, 0);
                put_page(page);
            }

            /* Check for continuation if it's not the last interation */
            if ( a.nr > ++start_iter && !(start_iter & HVMOP_op_mask) &&
                 hypercall_preempt_check() )
            {
                rc = -ERESTART;
                break;
            }
        }

    modmem_fail:
        rcu_unlock_domain(d);
        break;
    }

    case HVMOP_get_mem_type:
        rc = hvmop_get_mem_type(
            guest_handle_cast(arg, xen_hvm_get_mem_type_t));
        break;

    case HVMOP_set_mem_type:
        rc = hvmop_set_mem_type(
            guest_handle_cast(arg, xen_hvm_set_mem_type_t),
            &start_iter);
        break;

    case HVMOP_pagetable_dying:
    {
        struct xen_hvm_pagetable_dying a;
        struct domain *d;

        if ( copy_from_guest(&a, arg, 1) )
            return -EFAULT;

        d = rcu_lock_domain_by_any_id(a.domid);
        if ( d == NULL )
            return -ESRCH;

        rc = -EINVAL;
        if ( is_hvm_domain(d) && paging_mode_shadow(d) )
            rc = xsm_hvm_param(XSM_TARGET, d, op);
        if ( !rc )
            pagetable_dying(d, a.gpa);

        rcu_unlock_domain(d);
        break;
    }

    case HVMOP_get_time: {
        xen_hvm_get_time_t gxt;

        gxt.now = NOW();
        if ( copy_to_guest(arg, &gxt, 1) )
            rc = -EFAULT;
        break;
    }

    case HVMOP_xentrace: {
        xen_hvm_xentrace_t tr;

        if ( copy_from_guest(&tr, arg, 1 ) )
            return -EFAULT;

        if ( tr.extra_bytes > sizeof(tr.extra)
             || (tr.event & ~((1u<<TRC_SUBCLS_SHIFT)-1)) )
            return -EINVAL;

        /* Cycles will be taken at the vmexit and vmenter */
        trace_var(tr.event | TRC_GUEST, 0 /*!cycles*/,
                  tr.extra_bytes, tr.extra);
        break;
    }

    case HVMOP_inject_trap: 
    {
        xen_hvm_inject_trap_t tr;
        struct domain *d;
        struct vcpu *v;

        if ( copy_from_guest(&tr, arg, 1 ) )
            return -EFAULT;

        rc = rcu_lock_remote_domain_by_id(tr.domid, &d);
        if ( rc != 0 )
            return rc;

        rc = -EINVAL;
        if ( !is_hvm_domain(d) )
            goto injtrap_fail;

        rc = xsm_hvm_control(XSM_DM_PRIV, d, op);
        if ( rc )
            goto injtrap_fail;

        rc = -ENOENT;
        if ( tr.vcpuid >= d->max_vcpus || (v = d->vcpu[tr.vcpuid]) == NULL )
            goto injtrap_fail;
        
        if ( v->arch.hvm_vcpu.inject_trap.vector != -1 )
            rc = -EBUSY;
        else 
        {
            v->arch.hvm_vcpu.inject_trap.vector = tr.vector;
            v->arch.hvm_vcpu.inject_trap.type = tr.type;
            v->arch.hvm_vcpu.inject_trap.error_code = tr.error_code;
            v->arch.hvm_vcpu.inject_trap.insn_len = tr.insn_len;
            v->arch.hvm_vcpu.inject_trap.cr2 = tr.cr2;
            rc = 0;
        }

    injtrap_fail:
        rcu_unlock_domain(d);
        break;
    }

    case HVMOP_guest_request_vm_event:
        if ( guest_handle_is_null(arg) )
            monitor_guest_request();
        else
            rc = -EINVAL;
        break;

    case HVMOP_altp2m:
        rc = do_altp2m_op(arg);
        break;

    default:
    {
        gdprintk(XENLOG_DEBUG, "Bad HVM op %ld.\n", op);
        rc = -ENOSYS;
        break;
    }
    }

    if ( rc == -ERESTART )
    {
        ASSERT(!(start_iter & mask));
        rc = hypercall_create_continuation(__HYPERVISOR_hvm_op, "lh",
                                           op | start_iter, arg);
    }

    return rc;
}

int hvm_debug_op(struct vcpu *v, int32_t op)
{
    int rc;

    switch ( op )
    {
        case XEN_DOMCTL_DEBUG_OP_SINGLE_STEP_ON:
        case XEN_DOMCTL_DEBUG_OP_SINGLE_STEP_OFF:
            rc = -EOPNOTSUPP;
            if ( !cpu_has_monitor_trap_flag )
                break;
            rc = 0;
            vcpu_pause(v);
            v->arch.hvm_vcpu.single_step =
                (op == XEN_DOMCTL_DEBUG_OP_SINGLE_STEP_ON);
            vcpu_unpause(v); /* guest will latch new state */
            break;
        default:
            rc = -ENOSYS;
            break;
    }

    return rc;
}

void hvm_toggle_singlestep(struct vcpu *v)
{
    ASSERT(atomic_read(&v->pause_count));

    if ( !hvm_is_singlestep_supported() )
        return;

    v->arch.hvm_vcpu.single_step = !v->arch.hvm_vcpu.single_step;
}

int hvm_set_mode(struct vcpu *v, int mode)
{

    switch ( mode )
    {
    case 4:
        v->arch.hvm_vcpu.guest_efer &= ~(EFER_LMA | EFER_LME);
        break;
    case 8:
        v->arch.hvm_vcpu.guest_efer |= (EFER_LMA | EFER_LME);
        break;
    default:
        return -EOPNOTSUPP;
    }

    hvm_update_guest_efer(v);

    if ( hvm_funcs.set_mode )
        return hvm_funcs.set_mode(v, mode);

    return 0;
}

void hvm_domain_soft_reset(struct domain *d)
{
    hvm_destroy_all_ioreq_servers(d);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */

