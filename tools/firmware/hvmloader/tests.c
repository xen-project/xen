/*
 * tests.c: HVM environment tests.
 *
 * Copyright (c) 2008, Citrix Systems, Inc.
 * 
 * Authors:
 *    Keir Fraser <keir.fraser@citrix.com>
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

#include "util.h"

/*
 * Memory layout during tests:
 *  4MB to 8MB is cleared.
 *  Page directory resides at 8MB.
 *  4 page table pages reside at 8MB+4kB to 8MB+20kB.
 *  Pagetables identity-map 0-16MB, except 4kB at va 6MB maps to pa 5MB.
 */
#define PD_START (8ul << 20)
#define PT_START (PD_START + 4096)

static void setup_paging(void)
{
    uint32_t *pd = (uint32_t *)PD_START;
    uint32_t *pt = (uint32_t *)PT_START;
    uint32_t i;

    /* Identity map 0-16MB. */
    for ( i = 0; i < 4; i++ )
        pd[i] = (unsigned long)pt + (i<<12) + 3;
    for ( i = 0; i < (4*1024); i++ )
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
    int okay = 1;

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
    for ( p = (uint32_t *)0x400000ul; p < (uint32_t *)0x700000ul; p++ )
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
            okay = 0;
        }
    }

    return okay;
}

void perform_tests(void)
{
    int i, passed;

    static struct {
        int (* const test)(void);
        const char *description;
    } tests[] = {
        { rep_io_test, "REP INSB across page boundaries" },
        { NULL, NULL }
    };

    printf("Testing HVM environment:\n");

    passed = 0;
    for ( i = 0; tests[i].test; i++ )
    {
        printf(" - %s ... ", tests[i].description);
        memset((char *)(4ul << 20), 0, 4ul << 20);
        setup_paging();
        if ( (*tests[i].test)() )
        {
            printf("passed\n");
            passed++;
        }
        else
        {
            printf("failed\n");
        }
    }

    printf("Passed %d/%d tests\n", passed, i);
    BUG_ON(passed != i);
}
