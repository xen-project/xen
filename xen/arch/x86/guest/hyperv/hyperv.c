/******************************************************************************
 * arch/x86/guest/hyperv/hyperv.c
 *
 * Support for detecting and running under Hyper-V.
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
 *
 * Copyright (c) 2019 Microsoft.
 */
#include <xen/init.h>
#include <xen/version.h>

#include <asm/fixmap.h>
#include <asm/guest.h>
#include <asm/guest/hyperv-tlfs.h>
#include <asm/processor.h>

#include "private.h"

struct ms_hyperv_info __read_mostly ms_hyperv;
DEFINE_PER_CPU_READ_MOSTLY(void *, hv_input_page);
DEFINE_PER_CPU_READ_MOSTLY(void *, hv_vp_assist);
DEFINE_PER_CPU_READ_MOSTLY(unsigned int, hv_vp_index);

unsigned int __read_mostly hv_max_vp_index;
static bool __read_mostly hcall_page_ready;

static uint64_t generate_guest_id(void)
{
    union hv_guest_os_id id = {};

    id.vendor = HV_XEN_VENDOR_ID;
    id.major = xen_major_version();
    id.minor = xen_minor_version();

    return id.raw;
}

static const struct hypervisor_ops ops;

const struct hypervisor_ops *__init hyperv_probe(void)
{
    uint32_t eax, ebx, ecx, edx;
    uint64_t required_msrs = HV_X64_MSR_HYPERCALL_AVAILABLE |
        HV_X64_MSR_VP_INDEX_AVAILABLE;

    cpuid(0x40000000, &eax, &ebx, &ecx, &edx);
    if ( !((ebx == 0x7263694d) &&  /* "Micr" */
           (ecx == 0x666f736f) &&  /* "osof" */
           (edx == 0x76482074)) )  /* "t Hv" */
        return NULL;

    cpuid(0x40000001, &eax, &ebx, &ecx, &edx);
    if ( eax != 0x31237648 )    /* Hv#1 */
        return NULL;

    /* Extract more information from Hyper-V */
    cpuid(HYPERV_CPUID_FEATURES, &eax, &ebx, &ecx, &edx);
    ms_hyperv.features = eax;
    ms_hyperv.misc_features = edx;

    ms_hyperv.hints = cpuid_eax(HYPERV_CPUID_ENLIGHTMENT_INFO);

    if ( ms_hyperv.hints & HV_X64_ENLIGHTENED_VMCS_RECOMMENDED )
        ms_hyperv.nested_features = cpuid_eax(HYPERV_CPUID_NESTED_FEATURES);

    cpuid(HYPERV_CPUID_IMPLEMENT_LIMITS, &eax, &ebx, &ecx, &edx);
    ms_hyperv.max_vp_index = eax;
    ms_hyperv.max_lp_index = ebx;

    if ( (ms_hyperv.features & required_msrs) != required_msrs )
    {
        /*
         * Oops, required MSRs are not available. Treat this as
         * "Hyper-V is not available".
         */
        memset(&ms_hyperv, 0, sizeof(ms_hyperv));
        return NULL;
    }

    return &ops;
}

static void __init setup_hypercall_page(void)
{
    union hv_x64_msr_hypercall_contents hypercall_msr;
    union hv_guest_os_id guest_id;
    unsigned long mfn;

    BUILD_BUG_ON(HV_HYP_PAGE_SHIFT != PAGE_SHIFT);

    rdmsrl(HV_X64_MSR_GUEST_OS_ID, guest_id.raw);
    if ( !guest_id.raw )
    {
        guest_id.raw = generate_guest_id();
        wrmsrl(HV_X64_MSR_GUEST_OS_ID, guest_id.raw);
    }

    rdmsrl(HV_X64_MSR_HYPERCALL, hypercall_msr.as_uint64);
    if ( !hypercall_msr.enable )
    {
        mfn = HV_HCALL_MFN;
        hypercall_msr.enable = 1;
        hypercall_msr.guest_physical_address = mfn;
        wrmsrl(HV_X64_MSR_HYPERCALL, hypercall_msr.as_uint64);
    }
    else
        mfn = hypercall_msr.guest_physical_address;

    rdmsrl(HV_X64_MSR_HYPERCALL, hypercall_msr.as_uint64);
    BUG_ON(!hypercall_msr.enable);

    set_fixmap_x(FIX_X_HYPERV_HCALL, mfn << PAGE_SHIFT);

    hcall_page_ready = true;
}

static int setup_hypercall_pcpu_arg(void)
{
    uint64_t vp_index_msr;

    if ( this_cpu(hv_input_page) )
        return 0;

    this_cpu(hv_input_page) = alloc_xenheap_page();
    if ( !this_cpu(hv_input_page) )
    {
        printk("CPU%u: Failed to allocate hypercall input page\n",
               smp_processor_id());
        return -ENOMEM;
    }

    rdmsrl(HV_X64_MSR_VP_INDEX, vp_index_msr);
    this_cpu(hv_vp_index) = vp_index_msr;

    if ( vp_index_msr > hv_max_vp_index )
        hv_max_vp_index = vp_index_msr;

    return 0;
}

static int setup_vp_assist(void)
{
    union hv_vp_assist_page_msr msr;

    if ( !this_cpu(hv_vp_assist) )
    {
        this_cpu(hv_vp_assist) = alloc_xenheap_page();
        if ( !this_cpu(hv_vp_assist) )
        {
            printk("CPU%u: Failed to allocate vp_assist page\n",
                   smp_processor_id());
            return -ENOMEM;
        }

        clear_page(this_cpu(hv_vp_assist));
    }

    rdmsrl(HV_X64_MSR_VP_ASSIST_PAGE, msr.raw);
    msr.pfn = virt_to_mfn(this_cpu(hv_vp_assist));
    msr.enabled = 1;
    wrmsrl(HV_X64_MSR_VP_ASSIST_PAGE, msr.raw);

    return 0;
}

static void __init setup(void)
{
    ASM_CONSTANT(HV_HCALL_PAGE, __fix_x_to_virt(FIX_X_HYPERV_HCALL));

    setup_hypercall_page();

    if ( setup_hypercall_pcpu_arg() )
        panic("Hyper-V hypercall percpu arg setup failed\n");

    if ( setup_vp_assist() )
        panic("VP assist page setup failed\n");
}

static int ap_setup(void)
{
    int rc;

    rc = setup_hypercall_pcpu_arg();
    if ( rc )
        return rc;

    return setup_vp_assist();
}

static void __init e820_fixup(struct e820map *e820)
{
    uint64_t s = HV_HCALL_MFN << PAGE_SHIFT;

    if ( !e820_add_range(e820, s, s + PAGE_SIZE, E820_RESERVED) )
        panic("Unable to reserve Hyper-V hypercall range\n");
}

static int flush_tlb(const cpumask_t *mask, const void *va,
                     unsigned int flags)
{
    if ( !(ms_hyperv.hints & HV_X64_REMOTE_TLB_FLUSH_RECOMMENDED) )
        return -EOPNOTSUPP;

    if ( !hcall_page_ready || !this_cpu(hv_input_page) )
        return -ENXIO;

    return hyperv_flush_tlb(mask, va, flags);
}

static const struct hypervisor_ops __initconstrel ops = {
    .name = "Hyper-V",
    .setup = setup,
    .ap_setup = ap_setup,
    .e820_fixup = e820_fixup,
    .flush_tlb = flush_tlb,
};

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
