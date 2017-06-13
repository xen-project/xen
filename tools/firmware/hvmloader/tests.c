/*
 * tests.c: HVM environment tests.
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

#include "config.h"
#include "util.h"
#include <xen/arch-x86/hvm/start_info.h>

#define TEST_FAIL 0
#define TEST_PASS 1
#define TEST_SKIP 2

/*
 * Memory layout during tests:
 *  4MB to 8MB is cleared.
 *  Page directory resides at 4MB.
 *  2 page table pages reside at 4MB+4kB to 4MB+12kB.
 *  Pagetables identity-map 0-8MB, except 4kB at va 6MB maps to pa 5MB.
 */
#define TEST_MEM_BASE (4ul << 20)
#define TEST_MEM_SIZE (4ul << 20)
#define PD_START TEST_MEM_BASE
#define PT_START (PD_START + 4096)

static void setup_paging(void)
{
    uint32_t *pd = (uint32_t *)PD_START;
    uint32_t *pt = (uint32_t *)PT_START;
    uint32_t i;

    /* Identity map 0-8MB. */
    for ( i = 0; i < 2; i++ )
        pd[i] = (unsigned long)pt + (i<<12) + 3;
    for ( i = 0; i < 2 * 1024; i++ )
        pt[i] = (i << 12) + 3;

    /* Page at virtual 6MB maps to physical 5MB. */
    pt[6u<<8] -= 0x100000u;
}

static void start_paging(void)
{
    asm volatile (
        "mov %%eax,%%cr3; mov %%cr0,%%eax; "
        "orl $0x80000000,%%eax; mov %%eax,%%cr0; "
        "jmp 1f; 1:"
        : : "a" (PD_START) : "memory" );
}

static void stop_paging(void)
{
    asm volatile (
        "mov %%cr0,%%eax; andl $0x7fffffff,%%eax; mov %%eax,%%cr0; "
        "jmp 1f; 1:"
        : : : "eax", "memory" );
}

/*
 * rep_io_test: Tests REP INSB both forwards and backwards (EF.DF={0,1}) across
 * a discontiguous page boundary.
 */
static int rep_io_test(void)
{
    uint32_t *p;
    uint32_t i, p0, p1, p2;
    int okay = TEST_PASS;

    static const struct {
        unsigned long addr;
        uint32_t expected;
    } check[] = {
        { 0x00500000, 0x987654ff },
        { 0x00500ffc, 0xff000000 },
        { 0x005ffffc, 0xff000000 },
        { 0x00601000, 0x000000ff },
        { 0, 0 }
    };

    start_paging();

    /* Phys 5MB = 0xdeadbeef */
    *(uint32_t *)0x500000ul = 0xdeadbeef;

    /* Phys 5MB = 0x98765432 */
    *(uint32_t *)0x600000ul = 0x98765432;

    /* Phys 0x5fffff = Phys 0x500000 = 0xff (byte) */
    asm volatile (
        "rep insb"
        : "=d" (p0), "=c" (p1), "=D" (p2)
        : "0" (0x5f), "1" (2), "2" (0x5ffffful) : "memory" );

    /* Phys 0x500fff = Phys 0x601000 = 0xff (byte) */
    asm volatile (
        "std ; rep insb ; cld"
        : "=d" (p0), "=c" (p1), "=D" (p2)
        : "0" (0x5f), "1" (2), "2" (0x601000ul) : "memory" );

    stop_paging();

    i = 0;
    for ( p = (uint32_t *)0x4ff000ul; p < (uint32_t *)0x602000ul; p++ )
    {
        uint32_t expected = 0;
        if ( check[i].addr == (unsigned long)p )
        {
            expected = check[i].expected;
            i++;
        }
        if ( *p != expected )
        {
            printf("Bad value at 0x%08lx: saw %08x expected %08x\n",
                   (unsigned long)p, *p, expected);
            okay = TEST_FAIL;
        }
    }

    return okay;
}

static int shadow_gs_test(void)
{
    uint64_t *pd = (uint64_t *)PD_START;
    uint32_t i, eax, ebx, ecx, edx;

    /* Skip this test if the CPU does not support long mode. */
    cpuid(0x80000000, &eax, &ebx, &ecx, &edx);
    if ( eax < 0x80000001 )
        return TEST_SKIP;
    cpuid(0x80000001, &eax, &ebx, &ecx, &edx);
    if ( !(edx & (1u<<29)) )
        return TEST_SKIP;

    /* Long mode pagetable setup: Identity map 0-8MB with 2MB mappings. */
    *pd = (unsigned long)pd + 0x1007; /* Level 4 */
    pd += 512;
    *pd = (unsigned long)pd + 0x1007; /* Level 3 */
    pd += 512;
    for ( i = 0; i < 4; i++ )         /* Level 2 */
        *pd++ = (i << 21) + 0x1e3;

    asm volatile (
        /* CR4.PAE=1 */
        "mov $0x20,%%ebx; "
        "mov %%ebx,%%cr4; "
        /* CR3 */
        "mov %%eax,%%cr3; "
        /* EFER.LME=1 */
        "mov $0xc0000080,%%ecx; rdmsr; btsl $8,%%eax; wrmsr; "
        /* CR0.PG=1 */
        "mov %%cr0,%%eax; btsl $31,%%eax; mov %%eax,%%cr0; "
        "jmp 1f; 1: "
        /* GS_BASE=2; SHADOW_GS_BASE=3 */
        "mov $0xc0000101,%%ecx; xor %%edx,%%edx; mov $2,%%eax; wrmsr; "
        "mov $0xc0000102,%%ecx; xor %%edx,%%edx; mov $3,%%eax; wrmsr; "
        /* Push LRETQ stack frame. */
        "pushl $0; pushl $"STR(SEL_CODE32)"; pushl $0; pushl $2f; "
        /* Jump to 64-bit mode. */
        "ljmp $"STR(SEL_CODE64)",$1f; 1: "
        /* Swap GS_BASE and SHADOW_GS_BASE */
        ".byte 0x0f,0x01,0xf8; " /* SWAPGS */
        /* Jump to 32-bit mode. */
        ".byte 0x89, 0xe4; "     /* MOV ESP,ESP */
        ".byte 0x48, 0xcb; 2: "  /* LRETQ */
        /* Read SHADOW_GS_BASE: should now contain 2 */
        "mov $0xc0000102,%%ecx; rdmsr; mov %%eax,%%ebx; "
        /* CR0.PG=0 */
        "mov %%cr0,%%eax; btcl $31,%%eax; mov %%eax,%%cr0; "
        "jmp 1f; 1:"
        /* EFER.LME=0 */
        "mov $0xc0000080,%%ecx; rdmsr; btcl $8,%%eax; wrmsr; "
        /* CR4.PAE=0 */
        "xor %%eax,%%eax; mov %%eax,%%cr4; "
        : "=b" (ebx) : "a" (PD_START) : "ecx", "edx", "memory" );

    return (ebx == 2) ? TEST_PASS : TEST_FAIL;
}

void perform_tests(void)
{
    unsigned int i, passed, skipped;
    static struct {
        int (* const test)(void);
        const char *description;
    } tests[] = {
        { rep_io_test, "REP INSB across page boundaries" },
        { shadow_gs_test, "GS base MSRs and SWAPGS" },
        { NULL, NULL }
    };

    printf("Testing HVM environment:\n");

    BUILD_BUG_ON(SCRATCH_PHYSICAL_ADDRESS > HVMLOADER_PHYSICAL_ADDRESS);
    if ( hvm_info->low_mem_pgend <
         ((TEST_MEM_BASE + TEST_MEM_SIZE) >> PAGE_SHIFT) )
    {
        printf("Skipping tests due to insufficient memory (<%luMB)\n",
               (TEST_MEM_BASE + TEST_MEM_SIZE) >> 20);
        return;
    }

    if ( (unsigned long)_end > TEST_MEM_BASE )
    {
        printf("Skipping tests due to overlap with base image\n");
        return;
    }

    if ( hvm_start_info->cmdline_paddr &&
         hvm_start_info->cmdline_paddr < TEST_MEM_BASE + TEST_MEM_SIZE &&
         ((hvm_start_info->cmdline_paddr +
           strlen((char *)(uintptr_t)hvm_start_info->cmdline_paddr)) >=
          TEST_MEM_BASE) )
    {
        printf("Skipping tests due to overlap with command line\n");
        return;
    }

    if ( hvm_start_info->rsdp_paddr )
    {
        printf("Skipping tests due to non-zero RSDP address\n");
        return;
    }

    if ( hvm_start_info->nr_modules )
    {
        const struct hvm_modlist_entry *modlist =
            (void *)(uintptr_t)hvm_start_info->modlist_paddr;

        if ( hvm_start_info->modlist_paddr > UINTPTR_MAX ||
             ((UINTPTR_MAX - (uintptr_t)modlist) / sizeof(*modlist) <
              hvm_start_info->nr_modules) )
        {
            printf("Skipping tests due to inaccessible module list\n");
            return;
        }

        if ( TEST_MEM_BASE < (uintptr_t)(modlist +
                                         hvm_start_info->nr_modules) &&
             (uintptr_t)modlist < TEST_MEM_BASE + TEST_MEM_SIZE )
        {
            printf("Skipping tests due to overlap with module list\n");
            return;
        }

        for ( i = 0; i < hvm_start_info->nr_modules; ++i )
        {
            if ( TEST_MEM_BASE < modlist[i].paddr + modlist[i].size &&
                 modlist[i].paddr < TEST_MEM_BASE + TEST_MEM_SIZE )
            {
                printf("Skipping tests due to overlap with module %u\n", i);
                return;
            }

            if ( modlist[i].cmdline_paddr &&
                 modlist[i].cmdline_paddr < TEST_MEM_BASE + TEST_MEM_SIZE &&
                 ((modlist[i].cmdline_paddr +
                   strlen((char *)(uintptr_t)modlist[i].cmdline_paddr)) >=
                  TEST_MEM_BASE) )
            {
                printf("Skipping tests due to overlap with module %u cmdline\n",
                       i);
                return;
            }
        }
    }

    passed = skipped = 0;
    for ( i = 0; tests[i].test; i++ )
    {
        printf(" - %s ... ", tests[i].description);
        memset((char *)(4ul << 20), 0, 4ul << 20);
        setup_paging();
        switch ( (*tests[i].test)() )
        {
        case TEST_PASS:
            printf("passed\n");
            passed++;
            break;
        case TEST_FAIL:
            printf("failed\n");
            break;
        case TEST_SKIP:
            printf("skipped\n");
            skipped++;
            break;
        }
    }

    printf("Passed %d of %d tests\n", passed, i);
    if ( skipped != 0 )
        printf("Skipped %d of %d tests\n", skipped, i);
    if ( (passed + skipped) != i )
    {
        printf("FAILED %d of %d tests\n", i - passed - skipped, i);
        BUG();
    }
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
