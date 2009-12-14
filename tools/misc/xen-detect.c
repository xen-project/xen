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
#include <stdio.h>
#include <string.h>
#include <setjmp.h>
#include <signal.h>

static void cpuid(uint32_t idx,
                  uint32_t *eax,
                  uint32_t *ebx,
                  uint32_t *ecx,
                  uint32_t *edx,
                  int pv_context)
{
    asm volatile (
        "test %1,%1 ; jz 1f ; ud2a ; .ascii \"xen\" ; 1: cpuid"
        : "=a" (*eax), "=b" (*ebx), "=c" (*ecx), "=d" (*edx)
        : "0" (idx), "1" (pv_context) );
}

static int check_for_xen(int pv_context)
{
    uint32_t eax, ebx, ecx, edx;
    char signature[13];
    uint32_t base;

    for ( base = 0x40000000; base < 0x40010000; base += 0x100 )
    {
        cpuid(base, &eax, &ebx, &ecx, &edx, pv_context);

        *(uint32_t *)(signature + 0) = ebx;
        *(uint32_t *)(signature + 4) = ecx;
        *(uint32_t *)(signature + 8) = edx;
        signature[12] = '\0';

        if ( !strcmp("XenVMMXenVMM", signature) && (eax >= (base + 2)) )
            goto found;
    }

    return 0;

 found:
    cpuid(base + 1, &eax, &ebx, &ecx, &edx, pv_context);
    printf("Running in %s context on Xen v%d.%d.\n",
           pv_context ? "PV" : "HVM", (uint16_t)(eax >> 16), (uint16_t)eax);
    return 1;
}

static jmp_buf sigill_jmp;
void sigill_handler(int sig)
{
    longjmp(sigill_jmp, 1);
}

int main(void)
{
    /* Check for execution in HVM context. */
    if ( check_for_xen(0) )
        return 0;

    /*
     * Set up a signal handler to test the paravirtualised CPUID instruction.
     * If executed outside Xen PV context, the extended opcode will fault, we
     * will longjmp via the signal handler, and print "Not running on Xen".
     */
    if ( !setjmp(sigill_jmp)
         && (signal(SIGILL, sigill_handler) != SIG_ERR)
         && check_for_xen(1) )
        return 0;

    printf("Not running on Xen.\n");
    return 0;
}
