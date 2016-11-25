#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <xen/xen.h>
#include <sys/mman.h>

#include "x86_emulate/x86_emulate.h"
#include "blowfish.h"

static const struct {
    const void *code;
    size_t size;
    unsigned int bitness;
    const char*name;
} blobs[] = {
    { blowfish_x86_32, sizeof(blowfish_x86_32), 32, "blowfish" },
    { blowfish_x86_32_mno_accumulate_outgoing_args,
      sizeof(blowfish_x86_32_mno_accumulate_outgoing_args),
      32, "blowfish (push)" },
#ifdef __x86_64__
    { blowfish_x86_64, sizeof(blowfish_x86_64), 64, "blowfish" },
#endif
};

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
    unsigned int leaf = *eax;

    asm ("cpuid" : "+a" (*eax), "+c" (*ecx), "=d" (*edx), "=b" (*ebx));

    /* The emulator doesn't itself use MOVBE, so we can always run the test. */
    if ( leaf == 1 )
        *ecx |= 1U << 22;

    return X86EMUL_OKAY;
}

#define cache_line_size() ({ \
    unsigned int eax = 1, ebx, ecx = 0, edx; \
    cpuid(&eax, &ebx, &ecx, &edx, NULL); \
    edx & (1U << 19) ? (ebx >> 5) & 0x7f8 : 0; \
})

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

#define cpu_has_xsave ({ \
    unsigned int eax = 1, ecx = 0; \
    cpuid(&eax, &eax, &ecx, &eax, NULL); \
    /* Intentionally checking OSXSAVE here. */ \
    (ecx & (1U << 27)) != 0; \
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

static int read_cr(
    unsigned int reg,
    unsigned long *val,
    struct x86_emulate_ctxt *ctxt)
{
    /* Fake just enough state for the emulator's _get_fpu() to be happy. */
    switch ( reg )
    {
    case 0:
        *val = 0x00000001; /* PE */
        return X86EMUL_OKAY;

    case 4:
        /* OSFXSR, OSXMMEXCPT, and maybe OSXSAVE */
        *val = 0x00000600 | (cpu_has_xsave ? 0x00040000 : 0);
        return X86EMUL_OKAY;
    }

    return X86EMUL_UNHANDLEABLE;
}

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
    .read_cr    = read_cr,
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
         ((regs.eflags & 0xad5) != 0xa91) ||
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

#ifdef __x86_64__
    printf("%-40s", "Testing btcq %r8,(%r11)...");
    instr[0] = 0x4d; instr[1] = 0x0f; instr[2] = 0xbb; instr[3] = 0x03;
    regs.eflags = 0x200;
    regs.rip    = (unsigned long)&instr[0];
    regs.r8     = (-1L << 40) + 1;
    regs.r11    = (unsigned long)(res + (1L << 35));
    rc = x86_emulate(&ctxt, &emulops);
    if ( (rc != X86EMUL_OKAY) ||
         (*res != 0x2233445C) ||
         (regs.eflags != 0x201) ||
         (regs.rip != (unsigned long)&instr[4]) )
        goto fail;
    printf("okay\n");
#endif

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

    printf("%-40s", "Testing cmovz %ecx,%eax...");
    instr[0] = 0x0f; instr[1] = 0x44; instr[2] = 0xc1;
    regs.eflags = 0x200;
    regs.eip    = (unsigned long)&instr[0];
    regs.rax    = 0x1111111122222222;
    regs.rcx    = 0x3333333344444444;
    rc = x86_emulate(&ctxt, &emulops);
    if ( (rc != X86EMUL_OKAY) ||
         (regs.rax != 0x0000000022222222) ||
         (regs.rcx != 0x3333333344444444) ||
         (regs.eflags != 0x200) ||
         (regs.eip != (unsigned long)&instr[3]) )
        goto fail;
    printf("okay\n");
#endif

    printf("%-40s", "Testing movbe (%%ecx),%%eax...");
    instr[0] = 0x0f; instr[1] = 0x38; instr[2] = 0xf0; instr[3] = 0x01;
    regs.eflags = 0x200;
    regs.eip    = (unsigned long)&instr[0];
    regs.ecx    = (unsigned long)res;
    regs.eax    = 0x11111111;
    *res        = 0x12345678;
    rc = x86_emulate(&ctxt, &emulops);
    if ( (rc != X86EMUL_OKAY) ||
         (*res != 0x12345678) ||
         (regs.eax != 0x78563412) ||
         (regs.eflags != 0x200) ||
         (regs.eip != (unsigned long)&instr[4]) )
        goto fail;
    printf("okay\n");

    printf("%-40s", "Testing movbe %%ax,(%%ecx)...");
    instr[0] = 0x66; instr[1] = 0x0f; instr[2] = 0x38; instr[3] = 0xf1; instr[4] = 0x01;
    regs.eip = (unsigned long)&instr[0];
    rc = x86_emulate(&ctxt, &emulops);
    if ( (rc != X86EMUL_OKAY) ||
         (*res != 0x12341234) ||
         (regs.eax != 0x78563412) ||
         (regs.eflags != 0x200) ||
         (regs.eip != (unsigned long)&instr[5]) )
        goto fail;
    printf("okay\n");

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

    printf("%-40s", "Testing movq %%xmm0,32(%%ecx)...");
    if ( stack_exec && cpu_has_sse2 )
    {
        decl_insn(movq_to_mem2);

        asm volatile ( "pcmpgtb %%xmm0, %%xmm0\n"
                       put_insn(movq_to_mem2, "movq %%xmm0, 32(%0)")
                       :: "c" (NULL) );

        memset(res, 0xbd, 64);
        set_insn(movq_to_mem2);
        regs.ecx = (unsigned long)res;
        regs.edx = 0;
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(movq_to_mem2) ||
             *((uint64_t *)res + 4) ||
             memcmp(res, res + 10, 24) ||
             memcmp(res, res + 6, 8) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing vmovq %%xmm1,32(%%edx)...");
    if ( stack_exec && cpu_has_avx )
    {
        decl_insn(vmovq_to_mem);

        asm volatile ( "pcmpgtb %%xmm1, %%xmm1\n"
                       put_insn(vmovq_to_mem, "vmovq %%xmm1, 32(%0)")
                       :: "d" (NULL) );

        memset(res, 0xdb, 64);
        set_insn(vmovq_to_mem);
        regs.ecx = 0;
        regs.edx = (unsigned long)res;
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(vmovq_to_mem) ||
             *((uint64_t *)res + 4) ||
             memcmp(res, res + 10, 24) ||
             memcmp(res, res + 6, 8) )
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

    printf("%-40s", "Testing movd %%mm3,32(%%ecx)...");
    if ( stack_exec && cpu_has_mmx )
    {
        decl_insn(movd_to_mem);

        asm volatile ( "pcmpeqb %%mm3, %%mm3\n"
                       put_insn(movd_to_mem, "movd %%mm3, 32(%0)")
                       :: "c" (NULL) );

        memset(res, 0xbd, 64);
        set_insn(movd_to_mem);
        regs.ecx = (unsigned long)res;
        regs.edx = 0;
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(movd_to_mem) ||
             res[8] + 1 ||
             memcmp(res, res + 9, 28) ||
             memcmp(res, res + 6, 8) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing movd %%xmm2,32(%%edx)...");
    if ( stack_exec && cpu_has_sse2 )
    {
        decl_insn(movd_to_mem2);

        asm volatile ( "pcmpeqb %%xmm2, %%xmm2\n"
                       put_insn(movd_to_mem2, "movd %%xmm2, 32(%0)")
                       :: "d" (NULL) );

        memset(res, 0xdb, 64);
        set_insn(movd_to_mem2);
        regs.ecx = 0;
        regs.edx = (unsigned long)res;
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(movd_to_mem2) ||
             res[8] + 1 ||
             memcmp(res, res + 9, 28) ||
             memcmp(res, res + 6, 8) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing vmovd %%xmm1,32(%%ecx)...");
    if ( stack_exec && cpu_has_avx )
    {
        decl_insn(vmovd_to_mem);

        asm volatile ( "pcmpeqb %%xmm1, %%xmm1\n"
                       put_insn(vmovd_to_mem, "vmovd %%xmm1, 32(%0)")
                       :: "c" (NULL) );

        memset(res, 0xbd, 64);
        set_insn(vmovd_to_mem);
        regs.ecx = (unsigned long)res;
        regs.edx = 0;
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(vmovd_to_mem) ||
             res[8] + 1 ||
             memcmp(res, res + 9, 28) ||
             memcmp(res, res + 6, 8) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing movd %%mm3,%%ebx...");
    if ( stack_exec && cpu_has_mmx )
    {
        decl_insn(movd_to_reg);

        /*
         * Intentionally not specifying "b" as an input (or even output) here
         * to not keep the compiler from using the variable, which in turn
         * allows noticing whether the emulator touches the actual register
         * instead of the regs field.
         */
        asm volatile ( "pcmpeqb %%mm3, %%mm3\n"
                       put_insn(movd_to_reg, "movd %%mm3, %%ebx")
                       :: );

        set_insn(movd_to_reg);
#ifdef __x86_64__
        regs.rbx = 0xbdbdbdbdbdbdbdbdUL;
#else
        regs.ebx = 0xbdbdbdbdUL;
#endif
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) || !check_eip(movd_to_reg) ||
             regs.ebx != 0xffffffff )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing movd %%xmm2,%%ebx...");
    if ( stack_exec && cpu_has_sse2 )
    {
        decl_insn(movd_to_reg2);

        /* See comment next to movd above. */
        asm volatile ( "pcmpeqb %%xmm2, %%xmm2\n"
                       put_insn(movd_to_reg2, "movd %%xmm2, %%ebx")
                       :: );

        set_insn(movd_to_reg2);
#ifdef __x86_64__
        regs.rbx = 0xbdbdbdbdbdbdbdbdUL;
#else
        regs.ebx = 0xbdbdbdbdUL;
#endif
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) || !check_eip(movd_to_reg2) ||
             regs.ebx != 0xffffffff )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing vmovd %%xmm1,%%ebx...");
    if ( stack_exec && cpu_has_avx )
    {
        decl_insn(vmovd_to_reg);

        /* See comment next to movd above. */
        asm volatile ( "pcmpeqb %%xmm1, %%xmm1\n"
                       put_insn(vmovd_to_reg, "vmovd %%xmm1, %%ebx")
                       :: );

        set_insn(vmovd_to_reg);
#ifdef __x86_64__
        regs.rbx = 0xbdbdbdbdbdbdbdbdUL;
#else
        regs.ebx = 0xbdbdbdbdUL;
#endif
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) || !check_eip(vmovd_to_reg) ||
             regs.ebx != 0xffffffff )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

#ifdef __x86_64__
    printf("%-40s", "Testing movq %%mm3,32(%%ecx)...");
    if ( stack_exec && cpu_has_mmx )
    {
        decl_insn(movq_to_mem3);

        asm volatile ( "pcmpeqb %%mm3, %%mm3\n"
                       put_insn(movq_to_mem3, "rex64 movd %%mm3, 32(%0)")
                       :: "c" (NULL) );

        memset(res, 0xbd, 64);
        set_insn(movq_to_mem3);
        regs.ecx = (unsigned long)res;
        regs.edx = 0;
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(movq_to_mem3) ||
             *((long *)res + 4) + 1 ||
             memcmp(res, res + 10, 24) ||
             memcmp(res, res + 6, 8) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing movq %%xmm2,32(%%edx)...");
    if ( stack_exec )
    {
        decl_insn(movq_to_mem4);

        asm volatile ( "pcmpeqb %%xmm2, %%xmm2\n"
                       put_insn(movq_to_mem4, "rex64 movd %%xmm2, 32(%0)")
                       :: "d" (NULL) );

        memset(res, 0xdb, 64);
        set_insn(movq_to_mem4);
        regs.ecx = 0;
        regs.edx = (unsigned long)res;
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(movq_to_mem4) ||
             *((long *)res + 4) + 1 ||
             memcmp(res, res + 10, 24) ||
             memcmp(res, res + 6, 8) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing vmovq %%xmm1,32(%%ecx)...");
    if ( stack_exec && cpu_has_avx )
    {
        decl_insn(vmovq_to_mem2);

        asm volatile ( "pcmpeqb %%xmm1, %%xmm1\n"
#if 0 /* This doesn't work, as the assembler will pick opcode D6. */
                       put_insn(vmovq_to_mem2, "vmovq %%xmm1, 32(%0)")
#else
                       put_insn(vmovq_to_mem2, ".byte 0xc4, 0xe1, 0xf9, 0x7e, 0x49, 0x20")
#endif
                       :: "c" (NULL) );

        memset(res, 0xbd, 64);
        set_insn(vmovq_to_mem2);
        regs.ecx = (unsigned long)res;
        regs.edx = 0;
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(vmovq_to_mem2) ||
             *((long *)res + 4) + 1 ||
             memcmp(res, res + 10, 24) ||
             memcmp(res, res + 6, 8) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing movq %%mm3,%%rbx...");
    if ( stack_exec && cpu_has_mmx )
    {
        decl_insn(movq_to_reg);

        /* See comment next to movd above. */
        asm volatile ( "pcmpeqb %%mm3, %%mm3\n"
                       put_insn(movq_to_reg, "movq %%mm3, %%rbx")
                       :: );

        set_insn(movq_to_reg);
        regs.rbx = 0xbdbdbdbdbdbdbdbdUL;
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || regs.rbx + 1 || !check_eip(movq_to_reg) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing movq %%xmm2,%%rbx...");
    if ( stack_exec )
    {
        decl_insn(movq_to_reg2);

        /* See comment next to movd above. */
        asm volatile ( "pcmpeqb %%xmm2, %%xmm2\n"
                       put_insn(movq_to_reg2, "movq %%xmm2, %%rbx")
                       :: );

        set_insn(movq_to_reg2);
        regs.rbx = 0xbdbdbdbdbdbdbdbdUL;
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || regs.rbx + 1 || !check_eip(movq_to_reg2) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing vmovq %%xmm1,%%rbx...");
    if ( stack_exec && cpu_has_avx )
    {
        decl_insn(vmovq_to_reg);

        /* See comment next to movd above. */
        asm volatile ( "pcmpeqb %%xmm1, %%xmm1\n"
                       put_insn(vmovq_to_reg, "vmovq %%xmm1, %%rbx")
                       :: );

        set_insn(vmovq_to_reg);
        regs.rbx = 0xbdbdbdbdbdbdbdbdUL;
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || regs.rbx + 1 || !check_eip(vmovq_to_reg) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");
#endif

#undef decl_insn
#undef put_insn
#undef set_insn
#undef check_eip

    j = cache_line_size();
    snprintf(instr, (char *)res + MMAP_SZ - instr,
             "Testing clzero (%u-byte line)...", j);
    printf("%-40s", instr);
    if ( j >= sizeof(*res) && j <= MMAP_SZ / 4 )
    {
        instr[0] = 0x0f; instr[1] = 0x01; instr[2] = 0xfc;
        regs.eflags = 0x200;
        regs.eip    = (unsigned long)&instr[0];
        regs.eax    = (unsigned long)res + MMAP_SZ / 2 + j - 1;
        memset((void *)res + MMAP_SZ / 4, ~0, 3 * MMAP_SZ / 4);
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) ||
             (regs.eax != (unsigned long)res + MMAP_SZ / 2 + j - 1) ||
             (regs.eflags != 0x200) ||
             (regs.eip != (unsigned long)&instr[3]) ||
             (res[MMAP_SZ / 2 / sizeof(*res) - 1] != ~0U) ||
             (res[(MMAP_SZ / 2 + j) / sizeof(*res)] != ~0U) )
            goto fail;
        for ( i = 0; i < j; i += sizeof(*res) )
            if ( res[(MMAP_SZ / 2 + i) / sizeof(*res)] )
                break;
        if ( i < j )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    for ( j = 0; j < sizeof(blobs) / sizeof(*blobs); j++ )
    {
        memcpy(res, blobs[j].code, blobs[j].size);
        ctxt.addr_size = ctxt.sp_size = blobs[j].bitness;

        printf("Testing %s %u-bit code sequence",
               blobs[j].name, ctxt.addr_size);
        regs.eax = 2;
        regs.edx = 1;
        regs.eip = (unsigned long)res;
        regs.esp = (unsigned long)res + MMAP_SZ - 4;
        if ( ctxt.addr_size == 64 )
        {
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

        if ( ctxt.addr_size != sizeof(void *) * CHAR_BIT )
            continue;

        i = printf("Testing %s native execution...", blobs[j].name);
        asm volatile (
#if defined(__i386__)
            "movl $0x100000,%%ecx; call *%%ecx"
#else
            "movl $0x100000,%%ecx; call *%%rcx"
#endif
            : "=a" (regs.eax), "=d" (regs.edx)
            : "0" (2), "1" (1) : "ecx"
#ifdef __x86_64__
              , "rsi", "rdi", "r8", "r9", "r10", "r11"
#endif
        );
        if ( (regs.eax != 2) || (regs.edx != 1) )
            goto fail;
        printf("%*sokay\n", i < 40 ? 40 - i : 0, "");
    }

    return 0;

 fail:
    printf("failed!\n");
    return 1;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
