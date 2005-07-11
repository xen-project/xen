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

    printf("eip: %08x\t", regs->eip);
    printf("esp: %08x\n", regs->esp);

    printf("eax: %08x\t", regs->eax);
    printf("ebx: %08x\t", regs->ebx);
    printf("ecx: %08x\t", regs->ecx);
    printf("edx: %08x\n", regs->edx);

    printf("esi: %08x\t", regs->esi);
    printf("edi: %08x\t", regs->edi);
    printf("ebp: %08x\n", regs->ebp);

    printf(" cs: %08x\t", regs->cs);
    printf(" ds: %08x\t", regs->ds);
    printf(" fs: %08x\t", regs->fs);
    printf(" gs: %08x\n", regs->gs);

}
#elif defined(__x86_64__)
void print_ctx(vcpu_guest_context_t *ctx1)
{
    struct cpu_user_regs *regs = &ctx1->user_regs;

    printf("rip: %08lx\t", regs->rip);
    printf("rsp: %08lx\n", regs->rsp);

    printf("rax: %08lx\t", regs->rax);
    printf("rbx: %08lx\t", regs->rbx);
    printf("rcx: %08lx\t", regs->rcx);
    printf("rdx: %08lx\n", regs->rdx);

    printf("rsi: %08lx\t", regs->rsi);
    printf("rdi: %08lx\t", regs->rdi);
    printf("rbp: %08lx\n", regs->rbp);

    printf("r8: %08lx\t", regs->r8);
    printf("r9: %08lx\t", regs->r9);
    printf("r10: %08lx\t", regs->r10);
    printf("r11: %08lx\n", regs->r11);

    printf("r12: %08lx\t", regs->r12);
    printf("r13: %08lx\t", regs->r13);
    printf("r14: %08lx\t", regs->r14);
    printf("r15: %08lx\n", regs->r15);

    printf(" cs: %08x\t", regs->cs);
    printf(" ds: %08x\t", regs->ds);
    printf(" fs: %08x\t", regs->fs);
    printf(" gs: %08x\n", regs->gs);

}
#endif

void dump_ctx(u32 domid, u32 vcpu)
{
    int ret;
    vcpu_guest_context_t ctx;

    int xc_handle = xc_interface_open(); /* for accessing control interface */

    ret = xc_domain_get_vcpu_context(xc_handle, domid, vcpu, &ctx);
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
