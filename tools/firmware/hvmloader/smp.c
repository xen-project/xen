/*
 * smp.c: Secondary processor bringup and initialisation.
 *
 * Copyright (c) 2008, Citrix Systems, Inc.
 * 
 * Authors:
 *    Keir Fraser <keir@xen.org>
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

#include "util.h"
#include "config.h"
#include "apic_regs.h"
#include "hypercall.h"

#include <xen/asm/x86-defns.h>
#include <xen/hvm/hvm_vcpu.h>

#include <xen/vcpu.h>

static int ap_callin;

/** True if x2apic support is exposed to the guest. */
static bool has_x2apic;

/**
 * Lookup table of APIC IDs.
 *
 * Each entry is populated for its respective CPU as they come online. This is
 * required for generating the MADT with minimal assumptions about ID
 * relationships.
 */
uint32_t *cpu_to_apicid;

static uint32_t read_apic_id(void)
{
    uint32_t apic_id;

    if ( has_x2apic )
        cpuid(0xb, NULL, NULL, NULL, &apic_id);
    else
    {
        cpuid(1, NULL, &apic_id, NULL, NULL);
        apic_id >>= 24;
    }

    return apic_id;
}

static void cpu_setup(unsigned int cpu)
{
    uint32_t apicid = cpu_to_apicid[cpu] = read_apic_id();

    printf(" - CPU%u APIC ID %u ... ", cpu, apicid);
    cacheattr_init();
    printf("done.\n");

    if ( !cpu ) /* Used on the BSP too */
        return;

    wmb();
    ap_callin = 1;

    /* After this point, the BSP will shut us down. */

    for ( ;; )
        asm volatile ( "hlt" );
}

static void boot_cpu(unsigned int cpu)
{
    static uint8_t ap_stack[PAGE_SIZE] __attribute__ ((aligned (16)));
    static struct vcpu_hvm_context ap;

    /* Initialise shared variables. */
    ap_callin = 0;
    wmb();

    /* Wake up the secondary processor */
    ap = (struct vcpu_hvm_context) {
        .mode = VCPU_HVM_MODE_32B,
        .cpu_regs.x86_32 = {
            .eip = (unsigned long)cpu_setup,
            .esp = (unsigned long)ap_stack + ARRAY_SIZE(ap_stack),

            .eax = cpu,

            /* Protected Mode, no paging. */
            .cr0 = X86_CR0_PE,

            /* 32bit Flat Mode */
            .cs_limit = -1U,
            .ds_limit = -1U,
            .ss_limit = -1U,
            .es_limit = -1U,
            .tr_limit = 0x67,
            .cs_ar = 0xc9b,
            .ds_ar = 0xc93,
            .es_ar = 0xc93,
            .ss_ar = 0xc93,
            .tr_ar = 0x8b,
        },
    };

    if ( hypercall_vcpu_op(VCPUOP_initialise, cpu, &ap) )
        BUG();
    if ( hypercall_vcpu_op(VCPUOP_up, cpu, NULL) )
        BUG();

    /*
     * Wait for the secondary processor to complete initialisation.
     * Do not touch shared resources meanwhile.
     */
    while ( !ap_callin )
        cpu_relax();

    /* Take the secondary processor offline. */
    if ( hypercall_vcpu_op(VCPUOP_down, cpu, NULL) )
        BUG();
}

void smp_initialise(void)
{
    unsigned int i, nr_cpus = hvm_info->nr_vcpus;
    uint32_t ecx, max_leaf;

    cpuid(0, &max_leaf, NULL, NULL, NULL);
    if ( max_leaf >= 0xb )
    {
        cpuid(1, NULL, NULL, &ecx, NULL);
        has_x2apic = (ecx >> 21) & 1;
        if ( has_x2apic )
            printf("x2APIC supported\n");
    }

    printf("Multiprocessor initialisation:\n");
    cpu_to_apicid = scratch_alloc(sizeof(*cpu_to_apicid) * nr_cpus,
                                  sizeof(*cpu_to_apicid));
    cpu_setup(0);
    for ( i = 1; i < nr_cpus; i++ )
        boot_cpu(i);
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
