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

#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/stat.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <setjmp.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>

enum guest_type {
    XEN_PV = 1,
    XEN_HVM = 2,
    XEN_NONE = 3
};

static char *type;
static char *ver;

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
    if ( regs[0] )
    {
        int r = asprintf(&ver, "V%u.%u", (uint16_t)(regs[0] >> 16),
                         (uint16_t)regs[0]);
        if ( r < 0 )
        {
            perror("asprintf failed\n");
            exit(EXIT_FAILURE);
        }
    }
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
    printf("  -H, --hvm     Exit status 1 if not running as HVM or PVH guest.\n");
    printf("  -N, --none    Exit status 1 if running on Xen (PV or HVM)\n");
}

static bool check_dir(const char *filename)
{
    FILE *f;
    struct stat stab;
    bool res;

    f = fopen(filename, "r");
    if ( !f )
        return false;
    res = !fstat(fileno(f), &stab) && S_ISDIR(stab.st_mode);
    fclose(f);

    return res;
}

static char *read_file_content(const char *filename)
{
    FILE *f;
    struct stat stab;
    char *content = NULL;
    int datalen;

    f = fopen(filename, "r");
    if ( !f )
        return NULL;

    if ( fstat(fileno(f), &stab) || !S_ISREG(stab.st_mode) ||
         stab.st_size > INT_MAX || !stab.st_size )
        goto out;

    content = malloc(stab.st_size + 1);
    if ( !content )
        goto out;

    /* For sysfs file, datalen is always PAGE_SIZE. 'read'
     * will return the number of bytes of the actual content,
     * rs <= datalen is expected.
     */
    datalen = fread(content, 1, stab.st_size, f);
    content[datalen] = 0;
    if ( ferror(f) )
    {
        free(content);
        content = NULL;
    }

 out:
    fclose(f);
    return content;
}

static enum guest_type check_sysfs(void)
{
    char *str, *tmp;
    enum guest_type res = XEN_NONE;

    if ( !check_dir("/sys/hypervisor") )
        return 0;

    str = read_file_content("/sys/hypervisor/type");
    if ( !str || strcmp(str, "xen\n") )
        goto out;
    free(str);

    str = read_file_content("/sys/hypervisor/guest_type");
    if ( !str )
        return 0;
    str[strlen(str) - 1] = 0;
    type = str;
    if ( !strcmp(type, "PV") )
        res = XEN_PV;
    else
        res = XEN_HVM;

    str = read_file_content("/sys/hypervisor/version/major");
    if ( str )
        str[strlen(str) - 1] = 0;
    tmp = read_file_content("/sys/hypervisor/version/minor");
    if ( tmp )
        tmp[strlen(tmp) - 1] = 0;
    if ( str && tmp )
    {
        int r = asprintf(&ver, "V%s.%s", str, tmp);
        if ( r < 0 )
        {
            perror("asprintf failed\n");
            exit(EXIT_FAILURE);
        }
    } else
        ver = strdup("unknown version");
    free(tmp);

 out:
    free(str);
    return res;
}

int main(int argc, char **argv)
{
    enum guest_type detected, expected = 0;
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

    detected = check_sysfs();
    if ( detected )
        goto out;

    /* Check for execution in HVM context. */
    detected = XEN_HVM;
    type = "HVM";
    if ( check_for_xen(0) )
        goto out;

    /*
     * Set up a signal handler to test the paravirtualised CPUID instruction.
     * If executed outside Xen PV context, the extended opcode will fault, we
     * will longjmp via the signal handler, and print "Not running on Xen".
     */
    detected = XEN_PV;
    type = "PV";
    if ( !setjmp(sigill_jmp)
         && (signal(SIGILL, sigill_handler) != SIG_ERR)
         && check_for_xen(1) )
        goto out;

    detected = XEN_NONE;

 out:
    if ( quiet )
        /* nothing */;
    else if ( detected == XEN_NONE )
        printf("Not running on Xen.\n");
    else
        printf("Running in %s context on Xen %s.\n", type, ver);

    free(ver);

    return expected && (expected != detected);
}
