#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <xen/xen.h>
#include <sys/mman.h>

#define __packed __attribute__((packed))

#include "x86_emulate/x86_emulate.h"
#include "blowfish.h"

#define MMAP_SZ 16384

/* EFLAGS bit definitions. */
#define EFLG_OF (1<<11)
#define EFLG_DF (1<<10)
#define EFLG_SF (1<<7)
#define EFLG_ZF (1<<6)
#define EFLG_AF (1<<4)
#define EFLG_PF (1<<2)
#define EFLG_CF (1<<0)

static unsigned int bytes_read;

static int read(
    unsigned int seg,
    unsigned long offset,
    void *p_data,
    unsigned int bytes,
    struct x86_emulate_ctxt *ctxt)
{
    bytes_read += bytes;
    memcpy(p_data, (void *)offset, bytes);
    return X86EMUL_OKAY;
}

static int fetch(
    unsigned int seg,
    unsigned long offset,
    void *p_data,
    unsigned int bytes,
    struct x86_emulate_ctxt *ctxt)
{
    memcpy(p_data, (void *)offset, bytes);
    return X86EMUL_OKAY;
}

static int write(
    unsigned int seg,
    unsigned long offset,
    void *p_data,
    unsigned int bytes,
    struct x86_emulate_ctxt *ctxt)
{
    memcpy((void *)offset, p_data, bytes);
    return X86EMUL_OKAY;
}

static int cmpxchg(
    unsigned int seg,
    unsigned long offset,
    void *old,
    void *new,
    unsigned int bytes,
    struct x86_emulate_ctxt *ctxt)
{
    memcpy((void *)offset, new, bytes);
    return X86EMUL_OKAY;
}

static int cpuid(
    unsigned int *eax,
    unsigned int *ebx,
    unsigned int *ecx,
    unsigned int *edx,
    struct x86_emulate_ctxt *ctxt)
{
    asm ("cpuid" : "+a" (*eax), "+c" (*ecx), "=d" (*edx), "=b" (*ebx));
    return X86EMUL_OKAY;
}

#define cpu_has_mmx ({ \
    unsigned int eax = 1, ecx = 0, edx; \
    cpuid(&eax, &ecx, &ecx, &edx, NULL); \
    (edx & (1U << 23)) != 0; \
})

#define cpu_has_sse ({ \
    unsigned int eax = 1, ecx = 0, edx; \
    cpuid(&eax, &ecx, &ecx, &edx, NULL); \
    (edx & (1U << 25)) != 0; \
})

#define cpu_has_sse2 ({ \
    unsigned int eax = 1, ecx = 0, edx; \
    cpuid(&eax, &ecx, &ecx, &edx, NULL); \
    (edx & (1U << 26)) != 0; \
})

static inline uint64_t xgetbv(uint32_t xcr)
{
    uint32_t lo, hi;

    asm ( ".byte 0x0f, 0x01, 0xd0" : "=a" (lo), "=d" (hi) : "c" (xcr) );

    return ((uint64_t)hi << 32) | lo;
}

#define cpu_has_avx ({ \
    unsigned int eax = 1, ecx = 0; \
    cpuid(&eax, &eax, &ecx, &eax, NULL); \
    if ( !(ecx & (1U << 27)) || ((xgetbv(0) & 6) != 6) ) \
        ecx = 0; \
    (ecx & (1U << 28)) != 0; \
})

#define cpu_has_avx2 ({ \
    unsigned int eax = 1, ebx, ecx = 0; \
    cpuid(&eax, &ebx, &ecx, &eax, NULL); \
    if ( !(ecx & (1U << 27)) || ((xgetbv(0) & 6) != 6) ) \
        ebx = 0; \
    else { \
        eax = 7, ecx = 0; \
        cpuid(&eax, &ebx, &ecx, &eax, NULL); \
    } \
    (ebx & (1U << 5)) != 0; \
})

int get_fpu(
    void (*exception_callback)(void *, struct cpu_user_regs *),
    void *exception_callback_arg,
    enum x86_emulate_fpu_type type,
    struct x86_emulate_ctxt *ctxt)
{
    switch ( type )
    {
    case X86EMUL_FPU_fpu:
        break;
    case X86EMUL_FPU_mmx:
        if ( cpu_has_mmx )
            break;
    case X86EMUL_FPU_xmm:
        if ( cpu_has_sse )
            break;
    case X86EMUL_FPU_ymm:
        if ( cpu_has_avx )
            break;
    default:
        return X86EMUL_UNHANDLEABLE;
    }
    return X86EMUL_OKAY;
}

static struct x86_emulate_ops emulops = {
    .read       = read,
    .insn_fetch = fetch,
    .write      = write,
    .cmpxchg    = cmpxchg,
    .cpuid      = cpuid,
    .get_fpu    = get_fpu,
};

int main(int argc, char **argv)
{
    struct x86_emulate_ctxt ctxt;
    struct cpu_user_regs regs;
    char *instr;
    unsigned int *res, i, j;
    unsigned long sp;
    bool stack_exec;
    int rc;
#ifndef __x86_64__
    unsigned int bcdres_native, bcdres_emul;
#endif

    ctxt.regs = &regs;
    ctxt.force_writeback = 0;
    ctxt.addr_size = 8 * sizeof(void *);
    ctxt.sp_size   = 8 * sizeof(void *);

    res = mmap((void *)0x100000, MMAP_SZ, PROT_READ|PROT_WRITE|PROT_EXEC,
               MAP_FIXED|MAP_PRIVATE|MAP_ANONYMOUS, 0, 0);
    if ( res == MAP_FAILED )
    {
        fprintf(stderr, "mmap to low address failed\n");
        exit(1);
    }
    instr = (char *)res + 0x100;

#ifdef __x86_64__
    asm ("movq %%rsp, %0" : "=g" (sp));
#else
    asm ("movl %%esp, %0" : "=g" (sp));
#endif
    stack_exec = mprotect((void *)(sp & -0x1000L) - (MMAP_SZ - 0x1000),
                          MMAP_SZ, PROT_READ|PROT_WRITE|PROT_EXEC) == 0;
    if ( !stack_exec )
        printf("Warning: Stack could not be made executable (%d).\n", errno);

    printf("%-40s", "Testing addl %%ecx,(%%eax)...");
    instr[0] = 0x01; instr[1] = 0x08;
    regs.eflags = 0x200;
    regs.eip    = (unsigned long)&instr[0];
    regs.ecx    = 0x12345678;
    regs.eax    = (unsigned long)res;
    *res        = 0x7FFFFFFF;
    rc = x86_emulate(&ctxt, &emulops);
    if ( (rc != X86EMUL_OKAY) || 
         (*res != 0x92345677) || 
         (regs.eflags != 0xa94) ||
         (regs.eip != (unsigned long)&instr[2]) )
        goto fail;
    printf("okay\n");

    printf("%-40s", "Testing addl %%ecx,%%eax...");
    instr[0] = 0x01; instr[1] = 0xc8;
    regs.eflags = 0x200;
    regs.eip    = (unsigned long)&instr[0];
    regs.ecx    = 0x12345678;
    regs.eax    = 0x7FFFFFFF;
    rc = x86_emulate(&ctxt, &emulops);
    if ( (rc != X86EMUL_OKAY) || 
         (regs.ecx != 0x12345678) ||
         (regs.eax != 0x92345677) ||
         (regs.eflags != 0xa94) ||
         (regs.eip != (unsigned long)&instr[2]) )
        goto fail;
    printf("okay\n");

    printf("%-40s", "Testing xorl (%%eax),%%ecx...");
    instr[0] = 0x33; instr[1] = 0x08;
    regs.eflags = 0x200;
    regs.eip    = (unsigned long)&instr[0];
#ifdef __x86_64__
    regs.ecx    = 0xFFFFFFFF12345678UL;
#else
    regs.ecx    = 0x12345678UL;
#endif
    regs.eax    = (unsigned long)res;
    rc = x86_emulate(&ctxt, &emulops);
    if ( (rc != X86EMUL_OKAY) || 
         (*res != 0x92345677) || 
         (regs.ecx != 0x8000000FUL) ||
         (regs.eip != (unsigned long)&instr[2]) )
        goto fail;
    printf("okay\n");

    printf("%-40s", "Testing movl (%%eax),%%ecx...");
    instr[0] = 0x8b; instr[1] = 0x08;
    regs.eflags = 0x200;
    regs.eip    = (unsigned long)&instr[0];
    regs.ecx    = ~0UL;
    regs.eax    = (unsigned long)res;
    rc = x86_emulate(&ctxt, &emulops);
    if ( (rc != X86EMUL_OKAY) || 
         (*res != 0x92345677) || 
         (regs.ecx != 0x92345677UL) ||
         (regs.eip != (unsigned long)&instr[2]) )
        goto fail;
    printf("okay\n");

    printf("%-40s", "Testing lock cmpxchgb %%cl,(%%ebx)...");
    instr[0] = 0xf0; instr[1] = 0x0f; instr[2] = 0xb0; instr[3] = 0x0b;
    regs.eflags = 0x200;
    regs.eip    = (unsigned long)&instr[0];
    regs.eax    = 0x92345677UL;
    regs.ecx    = 0xAA;
    regs.ebx    = (unsigned long)res;
    rc = x86_emulate(&ctxt, &emulops);
    if ( (rc != X86EMUL_OKAY) || 
         (*res != 0x923456AA) || 
         (regs.eflags != 0x244) ||
         (regs.eax != 0x92345677UL) ||
         (regs.eip != (unsigned long)&instr[4]) )
        goto fail;
    printf("okay\n");

    printf("%-40s", "Testing lock cmpxchgb %%cl,(%%ebx)...");
    instr[0] = 0xf0; instr[1] = 0x0f; instr[2] = 0xb0; instr[3] = 0x0b;
    regs.eflags = 0x200;
    regs.eip    = (unsigned long)&instr[0];
    regs.eax    = 0xAABBCC77UL;
    regs.ecx    = 0xFF;
    regs.ebx    = (unsigned long)res;
    rc = x86_emulate(&ctxt, &emulops);
    if ( (rc != X86EMUL_OKAY) || 
         (*res != 0x923456AA) || 
         ((regs.eflags&0xad5) != 0xa91) ||
         (regs.eax != 0xAABBCCAA) ||
         (regs.ecx != 0xFF) ||
         (regs.eip != (unsigned long)&instr[4]) )
        goto fail;
    printf("okay\n");

    printf("%-40s", "Testing xchgl %%ecx,(%%eax)...");
    instr[0] = 0x87; instr[1] = 0x08;
    regs.eflags = 0x200;
    regs.eip    = (unsigned long)&instr[0];
    regs.ecx    = 0x12345678;
    regs.eax    = (unsigned long)res;
    rc = x86_emulate(&ctxt, &emulops);
    if ( (rc != X86EMUL_OKAY) || 
         (*res != 0x12345678) || 
         (regs.eflags != 0x200) ||
         (regs.ecx != 0x923456AA) ||
         (regs.eip != (unsigned long)&instr[2]) )
        goto fail;
    printf("okay\n");

    printf("%-40s", "Testing lock cmpxchgl %%ecx,(%%ebx)...");
    instr[0] = 0xf0; instr[1] = 0x0f; instr[2] = 0xb1; instr[3] = 0x0b;
    regs.eflags = 0x200;
    *res        = 0x923456AA;
    regs.eip    = (unsigned long)&instr[0];
    regs.eax    = 0x923456AAUL;
    regs.ecx    = 0xDDEEFF00L;
    regs.ebx    = (unsigned long)res;
    rc = x86_emulate(&ctxt, &emulops);
    if ( (rc != X86EMUL_OKAY) || 
         (*res != 0xDDEEFF00) || 
         (regs.eflags != 0x244) ||
         (regs.eax != 0x923456AAUL) ||
         (regs.eip != (unsigned long)&instr[4]) )
        goto fail;
    printf("okay\n");

    printf("%-40s", "Testing rep movsw...");
    instr[0] = 0xf3; instr[1] = 0x66; instr[2] = 0xa5;
    *res        = 0x22334455;
    regs.eflags = 0x200;
    regs.ecx    = 23;
    regs.eip    = (unsigned long)&instr[0];
    regs.esi    = (unsigned long)res + 0;
    regs.edi    = (unsigned long)res + 2;
    rc = x86_emulate(&ctxt, &emulops);
    if ( (rc != X86EMUL_OKAY) || 
         (*res != 0x44554455) ||
         (regs.eflags != 0x200) ||
         (regs.ecx != 22) || 
         (regs.esi != ((unsigned long)res + 2)) ||
         (regs.edi != ((unsigned long)res + 4)) ||
         (regs.eip != (unsigned long)&instr[0]) )
        goto fail;
    printf("okay\n");

    printf("%-40s", "Testing btrl $0x1,(%edi)...");
    instr[0] = 0x0f; instr[1] = 0xba; instr[2] = 0x37; instr[3] = 0x01;
    *res        = 0x2233445F;
    regs.eflags = 0x200;
    regs.eip    = (unsigned long)&instr[0];
    regs.edi    = (unsigned long)res;
    rc = x86_emulate(&ctxt, &emulops);
    if ( (rc != X86EMUL_OKAY) ||
         (*res != 0x2233445D) ||
         ((regs.eflags&0x201) != 0x201) ||
         (regs.eip != (unsigned long)&instr[4]) )
        goto fail;
    printf("okay\n");

    printf("%-40s", "Testing btrl %eax,(%edi)...");
    instr[0] = 0x0f; instr[1] = 0xb3; instr[2] = 0x07;
    *res        = 0x2233445F;
    regs.eflags = 0x200;
    regs.eip    = (unsigned long)&instr[0];
    regs.eax    = -32;
    regs.edi    = (unsigned long)(res+1);
    rc = x86_emulate(&ctxt, &emulops);
    if ( (rc != X86EMUL_OKAY) ||
         (*res != 0x2233445E) ||
         ((regs.eflags&0x201) != 0x201) ||
         (regs.eip != (unsigned long)&instr[3]) )
        goto fail;
    printf("okay\n");

    res[0] = 0x12345678;
    res[1] = 0x87654321;

    printf("%-40s", "Testing cmpxchg8b (%edi) [succeeding]...");
    instr[0] = 0x0f; instr[1] = 0xc7; instr[2] = 0x0f;
    regs.eflags = 0x200;
    regs.eax    = res[0];
    regs.edx    = res[1];
    regs.ebx    = 0x9999AAAA;
    regs.ecx    = 0xCCCCFFFF;
    regs.eip    = (unsigned long)&instr[0];
    regs.edi    = (unsigned long)res;
    rc = x86_emulate(&ctxt, &emulops);
    if ( (rc != X86EMUL_OKAY) ||
         (res[0] != 0x9999AAAA) ||
         (res[1] != 0xCCCCFFFF) ||
         ((regs.eflags&0x240) != 0x240) ||
         (regs.eip != (unsigned long)&instr[3]) )
        goto fail;
    printf("okay\n");

    printf("%-40s", "Testing cmpxchg8b (%edi) [failing]...");
    instr[0] = 0x0f; instr[1] = 0xc7; instr[2] = 0x0f;
    regs.eflags = 0x200;
    regs.eip    = (unsigned long)&instr[0];
    regs.edi    = (unsigned long)res;
    rc = x86_emulate(&ctxt, &emulops);
    if ( (rc != X86EMUL_OKAY) || 
         (res[0] != 0x9999AAAA) ||
         (res[1] != 0xCCCCFFFF) ||
         (regs.eax != 0x9999AAAA) ||
         (regs.edx != 0xCCCCFFFF) ||
         ((regs.eflags&0x240) != 0x200) ||
         (regs.eip != (unsigned long)&instr[3]) )
        goto fail;
    printf("okay\n");

    printf("%-40s", "Testing movsxbd (%%eax),%%ecx...");
    instr[0] = 0x0f; instr[1] = 0xbe; instr[2] = 0x08;
    regs.eflags = 0x200;
    regs.eip    = (unsigned long)&instr[0];
    regs.ecx    = 0x12345678;
    regs.eax    = (unsigned long)res;
    *res        = 0x82;
    rc = x86_emulate(&ctxt, &emulops);
    if ( (rc != X86EMUL_OKAY) ||
         (*res != 0x82) ||
         (regs.ecx != 0xFFFFFF82) ||
         ((regs.eflags&0x240) != 0x200) ||
         (regs.eip != (unsigned long)&instr[3]) )
        goto fail;
    printf("okay\n");

    printf("%-40s", "Testing movzxwd (%%eax),%%ecx...");
    instr[0] = 0x0f; instr[1] = 0xb7; instr[2] = 0x08;
    regs.eflags = 0x200;
    regs.eip    = (unsigned long)&instr[0];
    regs.ecx    = 0x12345678;
    regs.eax    = (unsigned long)res;
    *res        = 0x1234aa82;
    rc = x86_emulate(&ctxt, &emulops);
    if ( (rc != X86EMUL_OKAY) ||
         (*res != 0x1234aa82) ||
         (regs.ecx != 0xaa82) ||
         ((regs.eflags&0x240) != 0x200) ||
         (regs.eip != (unsigned long)&instr[3]) )
        goto fail;
    printf("okay\n");

#ifndef __x86_64__
    printf("%-40s", "Testing arpl %cx,(%%eax)...");
    instr[0] = 0x63; instr[1] = 0x08;
    regs.eflags = 0x200;
    regs.eip    = (unsigned long)&instr[0];
    regs.ecx    = 0x22222222;
    regs.eax    = (unsigned long)res;
    *res        = 0x33331111;
    bytes_read  = 0;
    rc = x86_emulate(&ctxt, &emulops);
    if ( (rc != X86EMUL_OKAY) ||
         (*res != 0x33331112) ||
         (regs.ecx != 0x22222222) ||
         !(regs.eflags & EFLG_ZF) ||
         (regs.eip != (unsigned long)&instr[2]) )
        goto fail;
#else
    printf("%-40s", "Testing movsxd (%%rax),%%rcx...");
    instr[0] = 0x48; instr[1] = 0x63; instr[2] = 0x08;
    regs.eip    = (unsigned long)&instr[0];
    regs.ecx    = 0x123456789abcdef;
    regs.eax    = (unsigned long)res;
    *res        = 0xfedcba98;
    bytes_read  = 0;
    rc = x86_emulate(&ctxt, &emulops);
    if ( (rc != X86EMUL_OKAY) ||
         (*res != 0xfedcba98) ||
         (regs.ecx != 0xfffffffffedcba98) ||
         (regs.eip != (unsigned long)&instr[3]) )
        goto fail;
    if ( bytes_read != 4 )
    {
        printf("%u bytes read - ", bytes_read);
        goto fail;
    }
#endif
    printf("okay\n");

    printf("%-40s", "Testing xadd %%ax,(%%ecx)...");
    instr[0] = 0x66; instr[1] = 0x0f; instr[2] = 0xc1; instr[3] = 0x01;
    regs.eflags = 0x200;
    regs.eip    = (unsigned long)&instr[0];
    regs.ecx    = (unsigned long)res;
    regs.eax    = 0x12345678;
    *res        = 0x11111111;
    rc = x86_emulate(&ctxt, &emulops);
    if ( (rc != X86EMUL_OKAY) ||
         (*res != 0x11116789) ||
         (regs.eax != 0x12341111) ||
         ((regs.eflags&0x240) != 0x200) ||
         (regs.eip != (unsigned long)&instr[4]) )
        goto fail;
    printf("okay\n");

    printf("%-40s", "Testing dec %%ax...");
#ifndef __x86_64__
    instr[0] = 0x66; instr[1] = 0x48;
#else
    instr[0] = 0x66; instr[1] = 0xff; instr[2] = 0xc8;
#endif
    regs.eflags = 0x200;
    regs.eip    = (unsigned long)&instr[0];
    regs.eax    = 0x00000000;
    rc = x86_emulate(&ctxt, &emulops);
    if ( (rc != X86EMUL_OKAY) ||
         (regs.eax != 0x0000ffff) ||
         ((regs.eflags&0x240) != 0x200) ||
         (regs.eip != (unsigned long)&instr[2 + (ctxt.addr_size > 32)]) )
        goto fail;
    printf("okay\n");

    printf("%-40s", "Testing lea 8(%%ebp),%%eax...");
    instr[0] = 0x8d; instr[1] = 0x45; instr[2] = 0x08;
    regs.eflags = 0x200;
    regs.eip    = (unsigned long)&instr[0];
    regs.eax    = 0x12345678;
    regs.ebp    = 0xaaaaaaaa;
    rc = x86_emulate(&ctxt, &emulops);
    if ( (rc != X86EMUL_OKAY) ||
         (regs.eax != 0xaaaaaab2) ||
         ((regs.eflags&0x240) != 0x200) ||
         (regs.eip != (unsigned long)&instr[3]) )
        goto fail;
    printf("okay\n");

    printf("%-40s", "Testing daa/das (all inputs)...");
#ifndef __x86_64__
    /* Bits 0-7: AL; Bit 8: EFLG_AF; Bit 9: EFLG_CF; Bit 10: DAA vs. DAS. */
    for ( i = 0; i < 0x800; i++ )
    {
        regs.eflags  = (i & 0x200) ? EFLG_CF : 0;
        regs.eflags |= (i & 0x100) ? EFLG_AF : 0;
        if ( i & 0x400 )
            __asm__ (
                "pushf; and $0xffffffee,(%%esp); or %1,(%%esp); popf; das; "
                "pushf; popl %1"
                : "=a" (bcdres_native), "=r" (regs.eflags)
                : "0" (i & 0xff), "1" (regs.eflags) );
        else
            __asm__ (
                "pushf; and $0xffffffee,(%%esp); or %1,(%%esp); popf; daa; "
                "pushf; popl %1"
                : "=a" (bcdres_native), "=r" (regs.eflags)
                : "0" (i & 0xff), "1" (regs.eflags) );
        bcdres_native |= (regs.eflags & EFLG_PF) ? 0x1000 : 0;
        bcdres_native |= (regs.eflags & EFLG_ZF) ? 0x800 : 0;
        bcdres_native |= (regs.eflags & EFLG_SF) ? 0x400 : 0;
        bcdres_native |= (regs.eflags & EFLG_CF) ? 0x200 : 0;
        bcdres_native |= (regs.eflags & EFLG_AF) ? 0x100 : 0;

        instr[0] = (i & 0x400) ? 0x2f: 0x27; /* daa/das */
        regs.eflags  = (i & 0x200) ? EFLG_CF : 0;
        regs.eflags |= (i & 0x100) ? EFLG_AF : 0;
        regs.eip    = (unsigned long)&instr[0];
        regs.eax    = (unsigned char)i;
        rc = x86_emulate(&ctxt, &emulops);
        bcdres_emul  = regs.eax;
        bcdres_emul |= (regs.eflags & EFLG_PF) ? 0x1000 : 0;
        bcdres_emul |= (regs.eflags & EFLG_ZF) ? 0x800 : 0;
        bcdres_emul |= (regs.eflags & EFLG_SF) ? 0x400 : 0;
        bcdres_emul |= (regs.eflags & EFLG_CF) ? 0x200 : 0;
        bcdres_emul |= (regs.eflags & EFLG_AF) ? 0x100 : 0;
        if ( (rc != X86EMUL_OKAY) || (regs.eax > 255) ||
             (regs.eip != (unsigned long)&instr[1]) )
            goto fail;

        if ( bcdres_emul != bcdres_native )
        {
            printf("%s:    AL=%02x %s %s\n"
                   "Output: AL=%02x %s %s %s %s %s\n"
                   "Emul.:  AL=%02x %s %s %s %s %s\n",
                   (i & 0x400) ? "DAS" : "DAA",
                   (unsigned char)i,
                   (i & 0x200) ? "CF" : "  ",
                   (i & 0x100) ? "AF" : "  ",
                   (unsigned char)bcdres_native,
                   (bcdres_native & 0x200) ? "CF" : "  ",
                   (bcdres_native & 0x100) ? "AF" : "  ",
                   (bcdres_native & 0x1000) ? "PF" : "  ",
                   (bcdres_native & 0x800) ? "ZF" : "  ",
                   (bcdres_native & 0x400) ? "SF" : "  ",
                   (unsigned char)bcdres_emul,
                   (bcdres_emul & 0x200) ? "CF" : "  ",
                   (bcdres_emul & 0x100) ? "AF" : "  ",
                   (bcdres_emul & 0x1000) ? "PF" : "  ",
                   (bcdres_emul & 0x800) ? "ZF" : "  ",
                   (bcdres_emul & 0x400) ? "SF" : "  ");
            goto fail;
        }
    }
    printf("okay\n");
#else
    printf("skipped\n");
#endif

#define decl_insn(which) extern const unsigned char which[], which##_len[]
#define put_insn(which, insn) ".pushsection .test, \"ax\", @progbits\n" \
                              #which ": " insn "\n"                     \
                              ".equ " #which "_len, .-" #which "\n"     \
                              ".popsection"
#define set_insn(which) (regs.eip = (unsigned long)memcpy(instr, which, \
                                             (unsigned long)which##_len))
#define check_eip(which) (regs.eip == (unsigned long)instr + \
                                      (unsigned long)which##_len)

    printf("%-40s", "Testing movq %mm3,(%ecx)...");
    if ( stack_exec && cpu_has_mmx )
    {
        decl_insn(movq_to_mem);

        asm volatile ( "pcmpeqb %%mm3, %%mm3\n"
                       put_insn(movq_to_mem, "movq %%mm3, (%0)")
                       :: "c" (NULL) );

        set_insn(movq_to_mem);
        memset(res, 0x33, 64);
        memset(res + 8, 0xff, 8);
        regs.ecx    = (unsigned long)res;
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) || memcmp(res, res + 8, 32) ||
             !check_eip(movq_to_mem) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing movq (%edx),%mm5...");
    if ( stack_exec && cpu_has_mmx )
    {
        decl_insn(movq_from_mem);

        asm volatile ( "pcmpgtb %%mm5, %%mm5\n"
                       put_insn(movq_from_mem, "movq (%0), %%mm5")
                       :: "d" (NULL) );

        set_insn(movq_from_mem);
        regs.ecx    = 0;
        regs.edx    = (unsigned long)res;
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(movq_from_mem) )
            goto fail;
        asm ( "pcmpeqb %%mm3, %%mm3\n\t"
              "pcmpeqb %%mm5, %%mm3\n\t"
              "pmovmskb %%mm3, %0" : "=r" (rc) );
        if ( rc != 0xff )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing movdqu %xmm2,(%ecx)...");
    if ( stack_exec && cpu_has_sse2 )
    {
        decl_insn(movdqu_to_mem);

        asm volatile ( "pcmpeqb %%xmm2, %%xmm2\n"
                       put_insn(movdqu_to_mem, "movdqu %%xmm2, (%0)")
                       :: "c" (NULL) );

        set_insn(movdqu_to_mem);
        memset(res, 0x55, 64);
        memset(res + 8, 0xff, 16);
        regs.ecx    = (unsigned long)res;
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) || memcmp(res, res + 8, 32) ||
             !check_eip(movdqu_to_mem) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing movdqu (%edx),%xmm4...");
    if ( stack_exec && cpu_has_sse2 )
    {
        decl_insn(movdqu_from_mem);

        asm volatile ( "pcmpgtb %%xmm4, %%xmm4\n"
                       put_insn(movdqu_from_mem, "movdqu (%0), %%xmm4")
                       :: "d" (NULL) );

        set_insn(movdqu_from_mem);
        regs.ecx    = 0;
        regs.edx    = (unsigned long)res;
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(movdqu_from_mem) )
            goto fail;
        asm ( "pcmpeqb %%xmm2, %%xmm2\n\t"
              "pcmpeqb %%xmm4, %%xmm2\n\t"
              "pmovmskb %%xmm2, %0" : "=r" (rc) );
        if ( rc != 0xffff )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing vmovdqu %ymm2,(%ecx)...");
    if ( stack_exec && cpu_has_avx )
    {
        decl_insn(vmovdqu_to_mem);

        asm volatile ( "vpcmpeqb %%xmm2, %%xmm2, %%xmm2\n"
                       put_insn(vmovdqu_to_mem, "vmovdqu %%ymm2, (%0)")
                       :: "c" (NULL) );

        set_insn(vmovdqu_to_mem);
        memset(res, 0x55, 128);
        memset(res + 16, 0xff, 16);
        memset(res + 20, 0x00, 16);
        regs.ecx    = (unsigned long)res;
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) || memcmp(res, res + 16, 64) ||
             !check_eip(vmovdqu_to_mem) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing vmovdqu (%edx),%ymm4...");
    if ( stack_exec && cpu_has_avx )
    {
        decl_insn(vmovdqu_from_mem);

#if 0 /* Don't use AVX2 instructions for now */
        asm volatile ( "vpcmpgtb %%ymm4, %%ymm4, %%ymm4\n"
#else
        asm volatile ( "vpcmpgtb %%xmm4, %%xmm4, %%xmm4\n\t"
                       "vinsertf128 $1, %%xmm4, %%ymm4, %%ymm4\n"
#endif
                       put_insn(vmovdqu_from_mem, "vmovdqu (%0), %%ymm4")
                       :: "d" (NULL) );

        set_insn(vmovdqu_from_mem);
        memset(res + 4, 0xff, 16);
        regs.ecx    = 0;
        regs.edx    = (unsigned long)res;
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(vmovdqu_from_mem) )
            goto fail;
#if 0 /* Don't use AVX2 instructions for now */
        asm ( "vpcmpeqb %%ymm2, %%ymm2, %%ymm2\n\t"
              "vpcmpeqb %%ymm4, %%ymm2, %%ymm0\n\t"
              "vpmovmskb %%ymm1, %0" : "=r" (rc) );
#else
        asm ( "vextractf128 $1, %%ymm4, %%xmm3\n\t"
              "vpcmpeqb %%xmm2, %%xmm2, %%xmm2\n\t"
              "vpcmpeqb %%xmm4, %%xmm2, %%xmm0\n\t"
              "vpcmpeqb %%xmm3, %%xmm2, %%xmm1\n\t"
              "vpmovmskb %%xmm0, %0\n\t"
              "vpmovmskb %%xmm1, %1" : "=r" (rc), "=r" (i) );
        rc |= i << 16;
#endif
        if ( rc != 0xffffffff )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing movsd %xmm5,(%ecx)...");
    memset(res, 0x77, 64);
    memset(res + 10, 0x66, 8);
    if ( stack_exec && cpu_has_sse2 )
    {
        decl_insn(movsd_to_mem);

        asm volatile ( "movlpd %0, %%xmm5\n\t"
                       "movhpd %0, %%xmm5\n"
                       put_insn(movsd_to_mem, "movsd %%xmm5, (%1)")
                       :: "m" (res[10]), "c" (NULL) );

        set_insn(movsd_to_mem);
        regs.ecx    = (unsigned long)(res + 2);
        regs.edx    = 0;
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) || memcmp(res, res + 8, 32) ||
             !check_eip(movsd_to_mem) )
            goto fail;
        printf("okay\n");
    }
    else
    {
        printf("skipped\n");
        memset(res + 2, 0x66, 8);
    }

    printf("%-40s", "Testing movaps (%edx),%xmm7...");
    if ( stack_exec && cpu_has_sse )
    {
        decl_insn(movaps_from_mem);

        asm volatile ( "xorps %%xmm7, %%xmm7\n"
                       put_insn(movaps_from_mem, "movaps (%0), %%xmm7")
                       :: "d" (NULL) );

        set_insn(movaps_from_mem);
        regs.ecx    = 0;
        regs.edx    = (unsigned long)res;
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(movaps_from_mem) )
            goto fail;
        asm ( "cmpeqps %1, %%xmm7\n\t"
              "movmskps %%xmm7, %0" : "=r" (rc) : "m" (res[8]) );
        if ( rc != 0xf )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing vmovsd %xmm5,(%ecx)...");
    memset(res, 0x88, 64);
    memset(res + 10, 0x77, 8);
    if ( stack_exec && cpu_has_avx )
    {
        decl_insn(vmovsd_to_mem);

        asm volatile ( "vbroadcastsd %0, %%ymm5\n"
                       put_insn(vmovsd_to_mem, "vmovsd %%xmm5, (%1)")
                       :: "m" (res[10]), "c" (NULL) );

        set_insn(vmovsd_to_mem);
        regs.ecx    = (unsigned long)(res + 2);
        regs.edx    = 0;
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) || memcmp(res, res + 8, 32) ||
             !check_eip(vmovsd_to_mem) )
            goto fail;
        printf("okay\n");
    }
    else
    {
        printf("skipped\n");
        memset(res + 2, 0x77, 8);
    }

    printf("%-40s", "Testing vmovaps (%edx),%ymm7...");
    if ( stack_exec && cpu_has_avx )
    {
        decl_insn(vmovaps_from_mem);

        asm volatile ( "vxorps %%ymm7, %%ymm7, %%ymm7\n"
                       put_insn(vmovaps_from_mem, "vmovaps (%0), %%ymm7")
                       :: "d" (NULL) );

        set_insn(vmovaps_from_mem);
        regs.ecx    = 0;
        regs.edx    = (unsigned long)res;
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(vmovaps_from_mem) )
            goto fail;
        asm ( "vcmpeqps %1, %%ymm7, %%ymm0\n\t"
              "vmovmskps %%ymm0, %0" : "=r" (rc) : "m" (res[8]) );
        if ( rc != 0xff )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

#undef decl_insn
#undef put_insn
#undef set_insn
#undef check_eip

    for ( j = 1; j <= 2; j++ )
    {
#if defined(__i386__)
        if ( j == 2 ) break;
        memcpy(res, blowfish32_code, sizeof(blowfish32_code));
#else
        ctxt.addr_size = 16 << j;
        ctxt.sp_size   = 16 << j;
        memcpy(res, (j == 1) ? blowfish32_code : blowfish64_code,
               (j == 1) ? sizeof(blowfish32_code) : sizeof(blowfish64_code));
#endif
        printf("Testing blowfish %u-bit code sequence", j*32);
        regs.eax = 2;
        regs.edx = 1;
        regs.eip = (unsigned long)res;
        regs.esp = (unsigned long)res + MMAP_SZ - 4;
        if ( j == 2 )
        {
            ctxt.addr_size = ctxt.sp_size = 64;
            *(uint32_t *)(unsigned long)regs.esp = 0;
            regs.esp -= 4;
        }
        *(uint32_t *)(unsigned long)regs.esp = 0x12345678;
        regs.eflags = 2;
        i = 0;
        while ( regs.eip != 0x12345678 )
        {
            if ( (i++ & 8191) == 0 )
                printf(".");
            rc = x86_emulate(&ctxt, &emulops);
            if ( rc != X86EMUL_OKAY )
            {
                printf("failed at %%eip == %08x\n", (unsigned int)regs.eip);
                return 1;
            }
        }
        if ( (regs.esp != ((unsigned long)res + MMAP_SZ)) ||
             (regs.eax != 2) || (regs.edx != 1) )
            goto fail;
        printf("okay\n");
    }

    printf("%-40s", "Testing blowfish native execution...");    
    asm volatile (
#if defined(__i386__)
        "movl $0x100000,%%ecx; call *%%ecx"
#else
        "movl $0x100000,%%ecx; call *%%rcx"
#endif
        : "=a" (regs.eax), "=d" (regs.edx)
        : "0" (2), "1" (1) : "ecx" );
    if ( (regs.eax != 2) || (regs.edx != 1) )
        goto fail;
    printf("okay\n");

    return 0;

 fail:
    printf("failed!\n");
    return 1;
}
