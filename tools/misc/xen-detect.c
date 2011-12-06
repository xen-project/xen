/******************************************************************************
 * xen_detect.c
 * 
 * Simple GNU C / POSIX application to detect execution on Xen VMM platform.
 * 
 * Copyright (c) 2007, XenSource Inc.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <setjmp.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>

static void cpuid(uint32_t idx, uint32_t *regs, int pv_context)
{
#ifdef __i386__
    /* Use the stack to avoid reg constraint failures with some gcc flags */
    asm volatile (
        "push %%eax; push %%ebx; push %%ecx; push %%edx\n\t"
        "test %1,%1 ; jz 1f ; ud2a ; .ascii \"xen\" ; 1: cpuid\n\t"
        "mov %%eax,(%2); mov %%ebx,4(%2)\n\t"
        "mov %%ecx,8(%2); mov %%edx,12(%2)\n\t"
        "pop %%edx; pop %%ecx; pop %%ebx; pop %%eax\n\t"
        : : "a" (idx), "c" (pv_context), "S" (regs) : "memory" );
#else
    asm volatile (
        "test %5,%5 ; jz 1f ; ud2a ; .ascii \"xen\" ; 1: cpuid\n\t"
        : "=a" (regs[0]), "=b" (regs[1]), "=c" (regs[2]), "=d" (regs[3])
        : "0" (idx), "1" (pv_context), "2" (0) );
#endif
}

static int check_for_xen(int pv_context)
{
    uint32_t regs[4];
    char signature[13];
    uint32_t base;

    for ( base = 0x40000000; base < 0x40010000; base += 0x100 )
    {
        cpuid(base, regs, pv_context);

        *(uint32_t *)(signature + 0) = regs[1];
        *(uint32_t *)(signature + 4) = regs[2];
        *(uint32_t *)(signature + 8) = regs[3];
        signature[12] = '\0';

        if ( !strcmp("XenVMMXenVMM", signature) && (regs[0] >= (base + 2)) )
            goto found;
    }

    return 0;

 found:
    cpuid(base + 1, regs, pv_context);
    return regs[0];
}

static jmp_buf sigill_jmp;
void sigill_handler(int sig)
{
    longjmp(sigill_jmp, 1);
}

static void usage(void)
{
    printf("Usage: xen_detect [options]\n");
    printf("Options:\n");
    printf("  -h, --help    Display this information\n");
    printf("  -q, --quiet   Quiesce normal informational output\n");
    printf("  -P, --pv      Exit status 1 if not running as PV guest\n");
    printf("  -H, --hvm     Exit status 1 if not running as HVM guest.\n");
    printf("  -N, --none    Exit status 1 if running on Xen (PV or HVM)\n");
}

int main(int argc, char **argv)
{
    enum { XEN_PV = 1, XEN_HVM = 2, XEN_NONE = 3 } detected = 0, expected = 0;
    uint32_t version = 0;
    int ch, quiet = 0;

    const static char sopts[] = "hqPHN";
    const static struct option lopts[] = {
        { "help",  0, NULL, 'h' },
        { "quiet", 0, NULL, 'q' },
        { "pv",    0, NULL, 'P' },
        { "hvm",   0, NULL, 'H' },
        { "none",  0, NULL, 'N' },
        { 0, 0, 0, 0}
    };

    while ( (ch = getopt_long(argc, argv, sopts, lopts, NULL)) != -1 )
    {
        switch ( ch )
        {
        case 'q':
            quiet = 1;
            break;
        case 'P':
            expected = XEN_PV;
            break;
        case 'H':
            expected = XEN_HVM;
            break;
        case 'N':
            expected = XEN_NONE;
            break;
        default:
            usage();
            exit(1);
        }
    }

    /* Check for execution in HVM context. */
    detected = XEN_HVM;
    if ( (version = check_for_xen(0)) != 0 )
        goto out;

    /*
     * Set up a signal handler to test the paravirtualised CPUID instruction.
     * If executed outside Xen PV context, the extended opcode will fault, we
     * will longjmp via the signal handler, and print "Not running on Xen".
     */
    detected = XEN_PV;
    if ( !setjmp(sigill_jmp)
         && (signal(SIGILL, sigill_handler) != SIG_ERR)
         && ((version = check_for_xen(1)) != 0) )
        goto out;

    detected = XEN_NONE;

 out:
    if ( quiet )
        /* nothing */;
    else if ( detected == XEN_NONE )
        printf("Not running on Xen.\n");
    else
        printf("Running in %s context on Xen v%d.%d.\n",
               (detected == XEN_PV) ? "PV" : "HVM",
               (uint16_t)(version >> 16), (uint16_t)version);

    return expected && (expected != detected);
}
