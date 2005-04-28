/******************************************************************************
 * tools/xentrace/xenctx.c
 *
 * Tool for dumping the cpu context
 *
 * Copyright (C) 2005 by Intel Corp
 *
 * Author: Arun Sharma <arun.sharma@intel.com>
 * Date:   February 2005
 */

#include <time.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <argp.h>
#include <signal.h>

#include "xc.h"

#ifdef __i386__
void print_ctx(vcpu_guest_context_t *ctx1)
{
    struct cpu_user_regs *regs = &ctx1->user_regs;

    printf("eip: %08lx\t", regs->eip);
    printf("esp: %08lx\n", regs->esp);

    printf("eax: %08lx\t", regs->eax);
    printf("ebx: %08lx\t", regs->ebx);
    printf("ecx: %08lx\t", regs->ecx);
    printf("edx: %08lx\n", regs->edx);

    printf("esi: %08lx\t", regs->esi);
    printf("edi: %08lx\t", regs->edi);
    printf("ebp: %08lx\n", regs->ebp);

    printf(" cs: %08lx\t", regs->cs);
    printf(" ds: %08lx\t", regs->ds);
    printf(" fs: %08lx\t", regs->fs);
    printf(" gs: %08lx\n", regs->gs);

}
#endif

void dump_ctx(u32 domid, u32 vcpu)
{
    int ret;
    xc_domaininfo_t info;
    vcpu_guest_context_t ctx;

    int xc_handle = xc_interface_open(); /* for accessing control interface */

    ret = xc_domain_getfullinfo(xc_handle, domid, vcpu, &info, &ctx);
    if (ret != 0) {
        perror("xc_domain_getfullinfo");
        exit(-1);
    }
    print_ctx(&ctx);
    xc_interface_close(xc_handle);
}

int main(int argc, char **argv)
{
    int vcpu = 0;

    if (argc < 2) {
        printf("usage: xenctx <domid> <optional vcpu>\n");
        exit(-1);
    }

    if (argc == 3)
        vcpu = atoi(argv[2]);

    dump_ctx(atoi(argv[1]), vcpu);

    return 0;
}
