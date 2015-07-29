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

#define AP_BOOT_EIP 0x1000
extern char ap_boot_start[], ap_boot_end[];

static int ap_callin, ap_cpuid;

asm (
    "    .text                       \n"
    "    .code16                     \n"
    "ap_boot_start: .code16          \n"
    "    mov   %cs,%ax               \n"
    "    mov   %ax,%ds               \n"
    "    lgdt  gdt_desr-ap_boot_start\n"
    "    xor   %ax, %ax              \n"
    "    inc   %ax                   \n"
    "    lmsw  %ax                   \n"
    "    ljmpl $0x08,$1f             \n"
    "gdt_desr:                       \n"
    "    .word gdt_end - gdt - 1     \n"
    "    .long gdt                   \n"
    "ap_boot_end: .code32            \n"
    "1:  mov   $0x10,%eax            \n"
    "    mov   %eax,%ds              \n"
    "    mov   %eax,%es              \n"
    "    mov   %eax,%ss              \n"
    "    movl  $stack_top,%esp       \n"
    "    movl  %esp,%ebp             \n"
    "    call  ap_start              \n"
    "1:  hlt                         \n"
    "    jmp  1b                     \n"
    "                                \n"
    "    .align 8                    \n"
    "gdt:                            \n"
    "    .quad 0x0000000000000000    \n"
    "    .quad 0x00cf9a000000ffff    \n" /* 0x08: Flat code segment */
    "    .quad 0x00cf92000000ffff    \n" /* 0x10: Flat data segment */
    "gdt_end:                        \n"
    "                                \n"
    "    .bss                        \n"
    "    .align    8                 \n"
    "stack:                          \n"
    "    .skip    0x4000             \n"
    "stack_top:                      \n"
    "    .text                       \n"
    );

void ap_start(void); /* non-static avoids unused-function compiler warning */
/*static*/ void ap_start(void)
{
    printf(" - CPU%d ... ", ap_cpuid);
    cacheattr_init();
    printf("done.\n");
    wmb();
    ap_callin = 1;
}

static void lapic_wait_ready(void)
{
    while ( lapic_read(APIC_ICR) & APIC_ICR_BUSY )
        cpu_relax();
}

static void boot_cpu(unsigned int cpu)
{
    unsigned int icr2 = SET_APIC_DEST_FIELD(LAPIC_ID(cpu));

    /* Initialise shared variables. */
    ap_cpuid = cpu;
    ap_callin = 0;
    wmb();

    /* Wake up the secondary processor: INIT-SIPI-SIPI... */
    lapic_wait_ready();
    lapic_write(APIC_ICR2, icr2);
    lapic_write(APIC_ICR, APIC_DM_INIT);
    lapic_wait_ready();
    lapic_write(APIC_ICR2, icr2);
    lapic_write(APIC_ICR, APIC_DM_STARTUP | (AP_BOOT_EIP >> 12));
    lapic_wait_ready();
    lapic_write(APIC_ICR2, icr2);
    lapic_write(APIC_ICR, APIC_DM_STARTUP | (AP_BOOT_EIP >> 12));
    lapic_wait_ready();

    /*
     * Wait for the secondary processor to complete initialisation.
     * Do not touch shared resources meanwhile.
     */
    while ( !ap_callin )
        cpu_relax();

    /* Take the secondary processor offline. */
    lapic_write(APIC_ICR2, icr2);
    lapic_write(APIC_ICR, APIC_DM_INIT);
    lapic_wait_ready();    
}

void smp_initialise(void)
{
    unsigned int i, nr_cpus = hvm_info->nr_vcpus;

    memcpy((void *)AP_BOOT_EIP, ap_boot_start, ap_boot_end - ap_boot_start);

    printf("Multiprocessor initialisation:\n");
    ap_start();
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
