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
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static int pv_context;

static void cpuid(uint32_t idx,
                  uint32_t *eax,
                  uint32_t *ebx,
                  uint32_t *ecx,
                  uint32_t *edx)
{
    asm volatile (
        "test %1,%1 ; jz 1f ; ud2a ; .ascii \"xen\" ; 1: cpuid"
        : "=a" (*eax), "=b" (*ebx), "=c" (*ecx), "=d" (*edx)
        : "0" (idx), "1" (pv_context) );
}

static int check_for_xen(void)
{
    uint32_t eax, ebx, ecx, edx;
    char signature[13];
    uint32_t base;

    for ( base = 0x40000000; base < 0x40010000; base += 0x100 )
    {
        cpuid(base, &eax, &ebx, &ecx, &edx);

        *(uint32_t *)(signature + 0) = ebx;
        *(uint32_t *)(signature + 4) = ecx;
        *(uint32_t *)(signature + 8) = edx;
        signature[12] = '\0';

        if ( !strcmp("XenVMMXenVMM", signature) && (eax >= (base + 2)) )
            goto found;
    }

    return 0;

 found:
    cpuid(base + 1, &eax, &ebx, &ecx, &edx);
    printf("Running in %s context on Xen v%d.%d.\n",
           pv_context ? "PV" : "HVM", (uint16_t)(eax >> 16), (uint16_t)eax);
    return 1;
}

int main(void)
{
    pid_t pid;
    int status;
    uint32_t dummy;

    /* Check for execution in HVM context. */
    if ( check_for_xen() )
        return 0;

    /* Now we check for execution in PV context. */
    pv_context = 1;

    /*
     * Fork a child to test the paravirtualised CPUID instruction.
     * If executed outside Xen PV context, the extended opcode will fault.
     */
    pid = fork();
    switch ( pid )
    {
    case 0:
        /* Child: test paravirtualised CPUID opcode and then exit cleanly. */
        cpuid(0x40000000, &dummy, &dummy, &dummy, &dummy);
        exit(0);
    case -1:
        fprintf(stderr, "Fork failed.\n");
        return 0;
    }

    /*
     * Parent waits for child to terminate and checks for clean exit.
     * Only if the exit is clean is it safe for us to try the extended CPUID.
     */
    waitpid(pid, &status, 0);
    if ( WIFEXITED(status) && check_for_xen() )
        return 0;

    printf("Not running on Xen.\n");
    return 0;
}
