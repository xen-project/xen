#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <sys/mman.h>

#include "x86_emulate.h"
#include "blowfish.h"

#define verbose false /* Switch to true for far more logging. */

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
    if ( verbose )
        printf("** %s(%u, %p,, %u,)\n", __func__, seg, (void *)offset, bytes);

    switch ( seg )
    {
        uint64_t value;

    case x86_seg_gdtr:
        /* Fake system segment type matching table index. */
        if ( (offset & 7) || (bytes > 8) )
            return X86EMUL_UNHANDLEABLE;
#ifdef __x86_64__
        if ( !(offset & 8) )
        {
            memset(p_data, 0, bytes);
            return X86EMUL_OKAY;
        }
        value = (offset - 8) >> 4;
#else
        value = (offset - 8) >> 3;
#endif
        if ( value >= 0x10 )
            return X86EMUL_UNHANDLEABLE;
        value |= value << 40;
        memcpy(p_data, &value, bytes);
        return X86EMUL_OKAY;

    case x86_seg_ldtr:
        /* Fake user segment type matching table index. */
        if ( (offset & 7) || (bytes > 8) )
            return X86EMUL_UNHANDLEABLE;
        value = offset >> 3;
        if ( value >= 0x10 )
            return X86EMUL_UNHANDLEABLE;
        value |= (value | 0x10) << 40;
        memcpy(p_data, &value, bytes);
        return X86EMUL_OKAY;

    default:
        if ( !is_x86_user_segment(seg) )
            return X86EMUL_UNHANDLEABLE;
        bytes_read += bytes;
        break;
    }
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
    if ( verbose )
        printf("** %s(%u, %p,, %u,)\n", __func__, seg, (void *)offset, bytes);

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
    if ( verbose )
        printf("** %s(%u, %p,, %u,)\n", __func__, seg, (void *)offset, bytes);

    if ( !is_x86_user_segment(seg) )
        return X86EMUL_UNHANDLEABLE;
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
    if ( verbose )
        printf("** %s(%u, %p,, %u,)\n", __func__, seg, (void *)offset, bytes);

    if ( !is_x86_user_segment(seg) )
        return X86EMUL_UNHANDLEABLE;
    memcpy((void *)offset, new, bytes);
    return X86EMUL_OKAY;
}

static int read_segment(
    enum x86_segment seg,
    struct segment_register *reg,
    struct x86_emulate_ctxt *ctxt)
{
    if ( !is_x86_user_segment(seg) )
        return X86EMUL_UNHANDLEABLE;
    memset(reg, 0, sizeof(*reg));
    reg->attr.fields.p = 1;
    return X86EMUL_OKAY;
}

static int read_msr(
    unsigned int reg,
    uint64_t *val,
    struct x86_emulate_ctxt *ctxt)
{
    switch ( reg )
    {
    case 0xc0000080: /* EFER */
        *val = ctxt->addr_size > 32 ? 0x500 /* LME|LMA */ : 0;
        return X86EMUL_OKAY;

    case 0xc0000103: /* TSC_AUX */
#define TSC_AUX_VALUE 0xCACACACA
        *val = TSC_AUX_VALUE;
        return X86EMUL_OKAY;
    }

    return X86EMUL_UNHANDLEABLE;
}

static struct x86_emulate_ops emulops = {
    .read       = read,
    .insn_fetch = fetch,
    .write      = write,
    .cmpxchg    = cmpxchg,
    .read_segment = read_segment,
    .cpuid      = emul_test_cpuid,
    .read_cr    = emul_test_read_cr,
    .read_msr   = read_msr,
    .get_fpu    = emul_test_get_fpu,
};

int main(int argc, char **argv)
{
    struct x86_emulate_ctxt ctxt;
    struct cpu_user_regs regs;
    char *instr;
    unsigned int *res, i, j;
    bool stack_exec;
    int rc;
#ifndef __x86_64__
    unsigned int bcdres_native, bcdres_emul;
#endif

    /* Disable output buffering. */
    setbuf(stdout, NULL);

    ctxt.regs = &regs;
    ctxt.force_writeback = 0;
    ctxt.vendor    = X86_VENDOR_UNKNOWN;
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

    stack_exec = emul_test_make_stack_executable();

    if ( !stack_exec )
        printf("Warning: Stack could not be made executable (%d).\n", errno);

    printf("%-40s", "Testing addl %ecx,(%eax)...");
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

    printf("%-40s", "Testing addl %ecx,%eax...");
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

    printf("%-40s", "Testing xorl (%eax),%ecx...");
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

    printf("%-40s", "Testing movl (%eax),%ecx...");
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

    printf("%-40s", "Testing lock cmpxchgb %cl,(%ebx)...");
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

    printf("%-40s", "Testing lock cmpxchgb %cl,(%ebx)...");
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

    printf("%-40s", "Testing xchgl %ecx,(%eax)...");
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

    printf("%-40s", "Testing lock cmpxchgl %ecx,(%ebx)...");
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

    printf("%-40s", "Testing cmpxchg8b (%edi) [opsize]...");
    instr[0] = 0x66; instr[1] = 0x0f; instr[2] = 0xc7; instr[3] = 0x0f;
    res[0]      = 0x12345678;
    res[1]      = 0x87654321;
    regs.eflags = 0x200;
    regs.eip    = (unsigned long)&instr[0];
    regs.edi    = (unsigned long)res;
    rc = x86_emulate(&ctxt, &emulops);
    if ( (rc != X86EMUL_OKAY) ||
         (res[0] != 0x12345678) ||
         (res[1] != 0x87654321) ||
         (regs.eax != 0x12345678) ||
         (regs.edx != 0x87654321) ||
         ((regs.eflags&0x240) != 0x200) ||
         (regs.eip != (unsigned long)&instr[4]) )
        goto fail;
    printf("okay\n");

    printf("%-40s", "Testing movsxbd (%eax),%ecx...");
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

    printf("%-40s", "Testing movzxwd (%eax),%ecx...");
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
    printf("%-40s", "Testing arpl %cx,(%eax)...");
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
    printf("%-40s", "Testing movsxd (%rax),%rcx...");
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

    printf("%-40s", "Testing xadd %ax,(%ecx)...");
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

    printf("%-40s", "Testing dec %ax...");
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

    printf("%-40s", "Testing lea 8(%ebp),%eax...");
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

#ifndef __x86_64__
    printf("%-40s", "Testing daa/das (all inputs)...");
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
#else /* x86-64 */
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

    printf("%-40s", "Testing movbe (%ecx),%eax...");
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

    printf("%-40s", "Testing movbe %ax,(%ecx)...");
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

    printf("%-40s", "Testing popcnt (%edx),%cx...");
    if ( cpu_has_popcnt )
    {
        instr[0] = 0x66; instr[1] = 0xf3;
        instr[2] = 0x0f; instr[3] = 0xb8; instr[4] = 0x0a;

        *res        = 0xfedcba98;
        regs.edx    = (unsigned long)res;
        regs.eflags = 0xac3;
        regs.eip    = (unsigned long)&instr[0];
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) || (uint16_t)regs.ecx != 8 || *res != 0xfedcba98 ||
             (regs.eflags & 0xfeb) != 0x202 ||
             (regs.eip != (unsigned long)&instr[5]) )
            goto fail;
        printf("okay\n");

        printf("%-40s", "Testing popcnt (%edx),%ecx...");
        regs.eflags = 0xac3;
        regs.eip    = (unsigned long)&instr[1];
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) || regs.ecx != 20 || *res != 0xfedcba98 ||
             (regs.eflags & 0xfeb) != 0x202 ||
             (regs.eip != (unsigned long)&instr[5]) )
            goto fail;
        printf("okay\n");

#ifdef __x86_64__
        printf("%-40s", "Testing popcnt (%rdx),%rcx...");
        instr[0]    = 0xf3;
        instr[1]    = 0x48;
        res[1]      = 0x12345678;
        regs.eflags = 0xac3;
        regs.eip    = (unsigned long)&instr[0];
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) || regs.ecx != 33 ||
             res[0] != 0xfedcba98 || res[1] != 0x12345678 ||
             (regs.eflags & 0xfeb) != 0x202 ||
             (regs.eip != (unsigned long)&instr[5]) )
            goto fail;
        printf("okay\n");
#endif
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing lar (null selector)...");
    instr[0] = 0x0f; instr[1] = 0x02; instr[2] = 0xc1;
    regs.eflags = 0x240;
    regs.eip    = (unsigned long)&instr[0];
    regs.ecx    = 0;
    regs.eax    = 0x11111111;
    rc = x86_emulate(&ctxt, &emulops);
    if ( (rc != X86EMUL_OKAY) ||
         (regs.eax != 0x11111111) ||
         (regs.eflags != 0x200) ||
         (regs.eip != (unsigned long)&instr[3]) )
        goto fail;
    printf("okay\n");

    printf("%-40s", "Testing lsl (null selector)...");
    instr[0] = 0x0f; instr[1] = 0x03; instr[2] = 0xca;
    regs.eflags = 0x240;
    regs.eip    = (unsigned long)&instr[0];
    regs.edx    = 0;
    regs.ecx    = 0x11111111;
    rc = x86_emulate(&ctxt, &emulops);
    if ( (rc != X86EMUL_OKAY) ||
         (regs.ecx != 0x11111111) ||
         (regs.eflags != 0x200) ||
         (regs.eip != (unsigned long)&instr[3]) )
        goto fail;
    printf("okay\n");

    printf("%-40s", "Testing verr (null selector)...");
    instr[0] = 0x0f; instr[1] = 0x00; instr[2] = 0x21;
    regs.eflags = 0x240;
    regs.eip    = (unsigned long)&instr[0];
    regs.ecx    = (unsigned long)res;
    *res        = 0;
    rc = x86_emulate(&ctxt, &emulops);
    if ( (rc != X86EMUL_OKAY) ||
         (regs.eflags != 0x200) ||
         (regs.eip != (unsigned long)&instr[3]) )
        goto fail;
    printf("okay\n");

    printf("%-40s", "Testing verw (null selector)...");
    instr[0] = 0x0f; instr[1] = 0x00; instr[2] = 0x2a;
    regs.eflags = 0x240;
    regs.eip    = (unsigned long)&instr[0];
    regs.ecx    = 0;
    regs.edx    = (unsigned long)res;
    rc = x86_emulate(&ctxt, &emulops);
    if ( (rc != X86EMUL_OKAY) ||
         (regs.eflags != 0x200) ||
         (regs.eip != (unsigned long)&instr[3]) )
        goto fail;
    printf("okay\n");

    printf("%-40s", "Testing lar/lsl/verr/verw (all types)...");
    for ( i = 0; i < 0x20; ++i )
    {
        unsigned int sel = i < 0x10 ?
#ifndef __x86_64__
                                      (i << 3) + 8
#else
                                      (i << 4) + 8
#endif
                                    : ((i - 0x10) << 3) | 4;
        bool failed;

#ifndef __x86_64__
# define LAR_VALID 0xffff1a3eU
# define LSL_VALID 0xffff0a0eU
#else
# define LAR_VALID 0xffff1a04U
# define LSL_VALID 0xffff0a04U
#endif
#define VERR_VALID 0xccff0000U
#define VERW_VALID 0x00cc0000U

        instr[0] = 0x0f; instr[1] = 0x02; instr[2] = 0xc2;
        regs.eflags = (LAR_VALID >> i) & 1 ? 0x200 : 0x240;
        regs.eip    = (unsigned long)&instr[0];
        regs.edx    = sel;
        regs.eax    = 0x11111111;
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) ||
             (regs.eip != (unsigned long)&instr[3]) )
            goto fail;
        if ( (LAR_VALID >> i) & 1 )
            failed = (regs.eflags != 0x240) ||
                     ((regs.eax & 0xf0ff00) != (i << 8));
        else
            failed = (regs.eflags != 0x200) ||
                     (regs.eax != 0x11111111);
        if ( failed )
        {
            printf("LAR %04x (type %02x) ", sel, i);
            goto fail;
        }

        instr[0] = 0x0f; instr[1] = 0x03; instr[2] = 0xd1;
        regs.eflags = (LSL_VALID >> i) & 1 ? 0x200 : 0x240;
        regs.eip    = (unsigned long)&instr[0];
        regs.ecx    = sel;
        regs.edx    = 0x11111111;
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) ||
             (regs.eip != (unsigned long)&instr[3]) )
            goto fail;
        if ( (LSL_VALID >> i) & 1 )
            failed = (regs.eflags != 0x240) ||
                     (regs.edx != (i & 0xf));
        else
            failed = (regs.eflags != 0x200) ||
                     (regs.edx != 0x11111111);
        if ( failed )
        {
            printf("LSL %04x (type %02x) ", sel, i);
            goto fail;
        }

        instr[0] = 0x0f; instr[1] = 0x00; instr[2] = 0xe2;
        regs.eflags = (VERR_VALID >> i) & 1 ? 0x200 : 0x240;
        regs.eip    = (unsigned long)&instr[0];
        regs.ecx    = 0;
        regs.edx    = sel;
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) ||
             (regs.eip != (unsigned long)&instr[3]) )
            goto fail;
        if ( regs.eflags != ((VERR_VALID >> i) & 1 ? 0x240 : 0x200) )
        {
            printf("VERR %04x (type %02x) ", sel, i);
            goto fail;
        }

        instr[0] = 0x0f; instr[1] = 0x00; instr[2] = 0xe9;
        regs.eflags = (VERW_VALID >> i) & 1 ? 0x200 : 0x240;
        regs.eip    = (unsigned long)&instr[0];
        regs.ecx    = sel;
        regs.edx    = 0;
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) ||
             (regs.eip != (unsigned long)&instr[3]) )
            goto fail;
        if ( regs.eflags != ((VERW_VALID >> i) & 1 ? 0x240 : 0x200) )
        {
            printf("VERW %04x (type %02x) ", sel, i);
            goto fail;
        }
    }
    printf("okay\n");

#define decl_insn(which) extern const unsigned char which[], \
                         which##_end[] asm ( ".L" #which "_end" )
#define put_insn(which, insn) ".pushsection .test, \"ax\", @progbits\n" \
                              #which ": " insn "\n"                     \
                              ".L" #which "_end:\n"                     \
                              ".popsection"
#define set_insn(which) (regs.eip = (unsigned long)(which))
#define valid_eip(which) (regs.eip >= (unsigned long)(which) && \
                          regs.eip < (unsigned long)which##_end)
#define check_eip(which) (regs.eip == (unsigned long)which##_end)

    printf("%-40s", "Testing andn (%edx),%ecx,%ebx...");
    if ( stack_exec && cpu_has_bmi1 )
    {
        decl_insn(andn);

        asm volatile ( put_insn(andn, "andn (%0), %%ecx, %%ebx")
                       :: "d" (NULL) );
        set_insn(andn);

        *res        = 0xfedcba98;
        regs.ecx    = 0xcccc3333;
        regs.edx    = (unsigned long)res;
        regs.eflags = 0xac3;
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) || regs.ebx != 0x32108888 ||
             regs.ecx != 0xcccc3333 || *res != 0xfedcba98 ||
             (regs.eflags & 0xfeb) != 0x202 || !check_eip(andn) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing bextr %edx,(%ecx),%ebx...");
    if ( stack_exec && cpu_has_bmi1 )
    {
        decl_insn(bextr);
#ifdef __x86_64__
        decl_insn(bextr64);
#endif

        asm volatile ( put_insn(bextr, "bextr %%edx, (%0), %%ebx")
                       :: "c" (NULL) );
        set_insn(bextr);

        regs.ecx    = (unsigned long)res;
        regs.edx    = 0x0a03;
        regs.eflags = 0xa43;
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) || regs.ebx != ((*res >> 3) & 0x3ff) ||
             regs.edx != 0x0a03 || *res != 0xfedcba98 ||
             (regs.eflags & 0xf6b) != 0x202 || !check_eip(bextr) )
            goto fail;
        printf("okay\n");
#ifdef __x86_64__
        printf("%-40s", "Testing bextr %r9,(%r10),%r11...");

        asm volatile ( put_insn(bextr64, "bextr %r9, (%r10), %r11") );
        set_insn(bextr64);

        res[0]      = 0x76543210;
        res[1]      = 0xfedcba98;
        regs.r10    = (unsigned long)res;
        regs.r9     = 0x211e;
        regs.eflags = 0xa43;
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) || regs.r9 != 0x211e ||
             regs.r11 != (((unsigned long)(res[1] << 1) << 1) |
                          (res[0] >> 30)) ||
             res[0] != 0x76543210 || res[1] != 0xfedcba98 ||
             (regs.eflags & 0xf6b) != 0x202 || !check_eip(bextr64) )
            goto fail;
        printf("okay\n");
#endif
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing blsi (%edx),%ecx...");
    if ( stack_exec && cpu_has_bmi1 )
    {
        decl_insn(blsi);

        asm volatile ( put_insn(blsi, "blsi (%0), %%ecx")
                       :: "d" (NULL) );
        set_insn(blsi);

        *res        = 0xfedcba98;
        regs.edx    = (unsigned long)res;
        regs.eflags = 0xac2;
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) || regs.ecx != 8 || *res != 0xfedcba98 ||
             (regs.eflags & 0xf6b) != 0x203 || !check_eip(blsi) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing blsmsk (%edx),%ecx...");
    if ( stack_exec && cpu_has_bmi1 )
    {
        decl_insn(blsmsk);

        asm volatile ( put_insn(blsmsk, "blsmsk (%0), %%ecx")
                       :: "d" (NULL) );
        set_insn(blsmsk);

        regs.eflags = 0xac3;
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) || regs.ecx != 0xf || *res != 0xfedcba98 ||
             (regs.eflags & 0xf6b) != 0x202 || !check_eip(blsmsk) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing blsr (%edx),%ecx...");
    if ( stack_exec && cpu_has_bmi1 )
    {
        decl_insn(blsr);

        asm volatile ( put_insn(blsr, "blsr (%0), %%ecx")
                       :: "d" (NULL) );
        set_insn(blsr);

        regs.eflags = 0xac3;
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) || regs.ecx != 0xfedcba90 ||
             (regs.eflags & 0xf6b) != 0x202 || !check_eip(blsr) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing bzhi %edx,(%ecx),%ebx...");
    if ( stack_exec && cpu_has_bmi2 )
    {
        decl_insn(bzhi);

        asm volatile ( put_insn(bzhi, "bzhi %%edx, (%0), %%ebx")
                       :: "c" (NULL) );
        set_insn(bzhi);

        regs.ecx    = (unsigned long)res;
        regs.edx    = 0xff13;
        regs.eflags = 0xa43;
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) || regs.ebx != (*res & 0x7ffff) ||
             regs.edx != 0xff13 || *res != 0xfedcba98 ||
             (regs.eflags & 0xf6b) != 0x202 || !check_eip(bzhi) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing mulx (%eax),%ecx,%ebx...");
    if ( cpu_has_bmi2 )
    {
        decl_insn(mulx);

        asm volatile ( put_insn(mulx, "mulx (%0), %%ecx, %%ebx")
                       :: "a" (NULL) );
        set_insn(mulx);

        regs.eax    = (unsigned long)res;
        regs.edx    = 0x12345678;
        regs.eflags = 0xac3;
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) || regs.ebx != 0x121fa00a ||
             regs.ecx != 0x35068740 || *res != 0xfedcba98 ||
             regs.eflags != 0xac3 || !check_eip(mulx) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing pdep (%edx),%ecx,%ebx...");
    if ( stack_exec && cpu_has_bmi2 )
    {
        decl_insn(pdep);

        asm volatile ( put_insn(pdep, "pdep (%0), %%ecx, %%ebx")
                       :: "d" (NULL) );
        set_insn(pdep);

        regs.ecx    = 0x8cef;
        regs.edx    = (unsigned long)res;
        regs.eflags = 0xa43;
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) || regs.ebx != 0x850b298 ||
             regs.ecx != 0x8cef || *res != 0xfedcba98 ||
             regs.eflags != 0xa43 || !check_eip(pdep) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing pext (%edx),%ecx,%ebx...");
    if ( stack_exec && cpu_has_bmi2 )
    {
        decl_insn(pext);

        asm volatile ( put_insn(pext, "pext (%0), %%ecx, %%ebx")
                       :: "d" (NULL) );
        set_insn(pext);

        regs.ecx    = 0x137f8cef;
        regs.edx    = (unsigned long)res;
        regs.eflags = 0xa43;
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) || regs.ebx != 0x12f95 ||
             regs.ecx != 0x137f8cef || *res != 0xfedcba98 ||
             regs.eflags != 0xa43 || !check_eip(pext) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing rorx $16,(%ecx),%ebx...");
    if ( cpu_has_bmi2 )
    {
        decl_insn(rorx);

        asm volatile ( put_insn(rorx, "rorx $16, (%0), %%ebx")
                       :: "c" (NULL) );
        set_insn(rorx);

        regs.ecx    = (unsigned long)res;
        regs.eflags = 0xa43;
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) || regs.ebx != 0xba98fedc ||
             *res != 0xfedcba98 ||
             regs.eflags != 0xa43 || !check_eip(rorx) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing sarx %edx,(%ecx),%ebx...");
    if ( stack_exec && cpu_has_bmi2 )
    {
        decl_insn(sarx);

        asm volatile ( put_insn(sarx, "sarx %%edx, (%0), %%ebx")
                       :: "c" (NULL) );
        set_insn(sarx);

        regs.ecx    = (unsigned long)res;
        regs.edx    = 0xff13;
        regs.eflags = 0xa43;
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) ||
             regs.ebx != ((signed)*res >> (regs.edx & 0x1f)) ||
             regs.edx != 0xff13 || *res != 0xfedcba98 ||
             regs.eflags != 0xa43 || !check_eip(sarx) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing shlx %edx,(%ecx),%ebx...");
    if ( stack_exec && cpu_has_bmi2 )
    {
        decl_insn(shlx);

        asm volatile ( put_insn(shlx, "shlx %%edx, (%0), %%ebx")
                       :: "c" (NULL) );
        set_insn(shlx);

        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) ||
             regs.ebx != (*res << (regs.edx & 0x1f)) ||
             regs.edx != 0xff13 || *res != 0xfedcba98 ||
             regs.eflags != 0xa43 || !check_eip(shlx) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing shrx %edx,(%ecx),%ebx...");
    if ( stack_exec && cpu_has_bmi2 )
    {
        decl_insn(shrx);

        asm volatile ( put_insn(shrx, "shrx %%edx, (%0), %%ebx")
                       :: "c" (NULL) );
        set_insn(shrx);

        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) ||
             regs.ebx != (*res >> (regs.edx & 0x1f)) ||
             regs.edx != 0xff13 || *res != 0xfedcba98 ||
             regs.eflags != 0xa43 || !check_eip(shrx) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing adcx/adox ...");
    {
        static const unsigned int data[] = {
            0x01234567, 0x12345678, 0x23456789, 0x3456789a,
            0x456789ab, 0x56789abc, 0x6789abcd, 0x789abcde,
            0x89abcdef, 0x9abcdef0, 0xabcdef01, 0xbcdef012,
            0xcdef0123, 0xdef01234, 0xef012345, 0xf0123456
        };
        decl_insn(adx);
        unsigned int cf, of;

        asm volatile ( put_insn(adx, ".Lloop%=:\n\t"
                                     "adcx (%[addr]), %k[dst1]\n\t"
                                     "adox -%c[full]-%c[elem](%[addr],%[cnt],2*%c[elem]), %k[dst2]\n\t"
                                     "lea %c[elem](%[addr]),%[addr]\n\t"
                                     "loop .Lloop%=\n\t"
                                     "adcx %k[cnt], %k[dst1]\n\t"
                                     "adox %k[cnt], %k[dst2]\n\t" )
                       : [addr] "=S" (regs.esi), [cnt] "=c" (regs.ecx),
                         [dst1] "=a" (regs.eax), [dst2] "=d" (regs.edx)
                       : [full] "i" (sizeof(data)), [elem] "i" (sizeof(*data)),
                         "[addr]" (data), "[cnt]" (ARRAY_SIZE(data)),
                         "[dst1]" (0), "[dst2]" (0) );

        set_insn(adx);
        regs.eflags = 0x2d6;
        of = cf = i = 0;
        while ( (rc = x86_emulate(&ctxt, &emulops)) == X86EMUL_OKAY )
        {
            ++i;
            /*
             * Count CF/OF being set after each loop iteration during the
             * first half (to observe different counts), in order to catch
             * the wrong flag being fiddled with.
             */
            if ( i < ARRAY_SIZE(data) * 2 && !(i % 4) )
            {
                if ( regs.eflags & 0x001 )
                   ++cf;
                if ( regs.eflags & 0x800 )
                   ++of;
            }
            if ( !valid_eip(adx) )
                break;
        }
        if ( (rc != X86EMUL_OKAY) ||
             i != ARRAY_SIZE(data) * 4 + 2 || cf != 1 || of != 5 ||
             regs.eax != 0xffffffff || regs.ecx || regs.edx != 0xffffffff ||
             !check_eip(adx) || regs.eflags != 0x2d6 )
            goto fail;
        printf("okay\n");
    }

    printf("%-40s", "Testing bextr $0x0a03,(%ecx),%ebx...");
    if ( stack_exec && cpu_has_tbm )
    {
        decl_insn(bextr_imm);
#ifdef __x86_64__
        decl_insn(bextr64_imm);
#endif

        asm volatile ( put_insn(bextr_imm, "bextr $0x0a03, (%0), %%ebx")
                       :: "c" (NULL) );
        set_insn(bextr_imm);

        *res        = 0xfedcba98;
        regs.ecx    = (unsigned long)res;
        regs.eflags = 0xa43;
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) || regs.ebx != ((*res >> 3) & 0x3ff) ||
             *res != 0xfedcba98 ||
             (regs.eflags & 0xf6b) != 0x202 || !check_eip(bextr_imm) )
            goto fail;
        printf("okay\n");
#ifdef __x86_64__
        printf("%-40s", "Testing bextr $0x211e,(%r10),%r11...");

        asm volatile ( put_insn(bextr64_imm, "bextr $0x211e, (%r10), %r11") );
        set_insn(bextr64_imm);

        res[0]      = 0x76543210;
        res[1]      = 0xfedcba98;
        regs.r10    = (unsigned long)res;
        regs.eflags = 0xa43;
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) ||
             regs.r11 != (((unsigned long)(res[1] << 1) << 1) |
                          (res[0] >> 30)) ||
             res[0] != 0x76543210 || res[1] != 0xfedcba98 ||
             (regs.eflags & 0xf6b) != 0x202 || !check_eip(bextr64_imm) )
            goto fail;
        printf("okay\n");
#endif
    }
    else
        printf("skipped\n");

    res[0]      = 0xfedcba98;
    res[1]      = 0x01234567;
    regs.edx    = (unsigned long)res;

    printf("%-40s", "Testing blcfill 4(%edx),%ecx...");
    if ( stack_exec && cpu_has_tbm )
    {
        decl_insn(blcfill);

        asm volatile ( put_insn(blcfill, "blcfill 4(%0), %%ecx")
                       :: "d" (NULL) );
        set_insn(blcfill);

        regs.eflags = 0xac3;
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) || res[1] != 0x01234567 ||
             regs.ecx != ((res[1] + 1) & res[1]) ||
             (regs.eflags & 0xfeb) != 0x202 || !check_eip(blcfill) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing blci 4(%edx),%ecx...");
    if ( stack_exec && cpu_has_tbm )
    {
        decl_insn(blci);

        asm volatile ( put_insn(blci, "blci 4(%0), %%ecx")
                       :: "d" (NULL) );
        set_insn(blci);

        regs.eflags = 0xac3;
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) || res[1] != 0x01234567 ||
             regs.ecx != (~(res[1] + 1) | res[1]) ||
             (regs.eflags & 0xfeb) != 0x282 || !check_eip(blci) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing blcic 4(%edx),%ecx...");
    if ( stack_exec && cpu_has_tbm )
    {
        decl_insn(blcic);

        asm volatile ( put_insn(blcic, "blcic 4(%0), %%ecx")
                       :: "d" (NULL) );
        set_insn(blcic);

        regs.eflags = 0xac3;
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) || res[1] != 0x01234567 ||
             regs.ecx != ((res[1] + 1) & ~res[1]) ||
             (regs.eflags & 0xfeb) != 0x202 || !check_eip(blcic) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing blcmsk 4(%edx),%ecx...");
    if ( stack_exec && cpu_has_tbm )
    {
        decl_insn(blcmsk);

        asm volatile ( put_insn(blcmsk, "blcmsk 4(%0), %%ecx")
                       :: "d" (NULL) );
        set_insn(blcmsk);

        regs.eflags = 0xac3;
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) || res[1] != 0x01234567 ||
             regs.ecx != ((res[1] + 1) ^ res[1]) ||
             (regs.eflags & 0xfeb) != 0x202 || !check_eip(blcmsk) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing blcs 4(%edx),%ecx...");
    if ( stack_exec && cpu_has_tbm )
    {
        decl_insn(blcs);

        asm volatile ( put_insn(blcs, "blcs 4(%0), %%ecx")
                       :: "d" (NULL) );
        set_insn(blcs);

        regs.eflags = 0xac3;
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) || res[1] != 0x01234567 ||
             regs.ecx != ((res[1] + 1) | res[1]) ||
             (regs.eflags & 0xfeb) != 0x202 || !check_eip(blcs) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing blsfill (%edx),%ecx...");
    if ( stack_exec && cpu_has_tbm )
    {
        decl_insn(blsfill);

        asm volatile ( put_insn(blsfill, "blsfill (%0), %%ecx")
                       :: "d" (NULL) );
        set_insn(blsfill);

        regs.eflags = 0xac3;
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) || res[0] != 0xfedcba98 ||
             regs.ecx != ((res[0] - 1) | res[0]) ||
             (regs.eflags & 0xfeb) != 0x282 || !check_eip(blsfill) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing blsic (%edx),%ecx...");
    if ( stack_exec && cpu_has_tbm )
    {
        decl_insn(blsic);

        asm volatile ( put_insn(blsic, "blsic (%0), %%ecx")
                       :: "d" (NULL) );
        set_insn(blsic);

        regs.eflags = 0xac3;
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) || res[0] != 0xfedcba98 ||
             regs.ecx != ((res[0] - 1) | ~res[0]) ||
             (regs.eflags & 0xfeb) != 0x282 || !check_eip(blsic) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing t1mskc 4(%edx),%ecx...");
    if ( stack_exec && cpu_has_tbm )
    {
        decl_insn(t1mskc);

        asm volatile ( put_insn(t1mskc, "t1mskc 4(%0), %%ecx")
                       :: "d" (NULL) );
        set_insn(t1mskc);

        regs.eflags = 0xac3;
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) || res[1] != 0x01234567 ||
             regs.ecx != ((res[1] + 1) | ~res[1]) ||
             (regs.eflags & 0xfeb) != 0x282 || !check_eip(t1mskc) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing tzmsk (%edx),%ecx...");
    if ( stack_exec && cpu_has_tbm )
    {
        decl_insn(tzmsk);

        asm volatile ( put_insn(tzmsk, "tzmsk (%0), %%ecx")
                       :: "d" (NULL) );
        set_insn(tzmsk);

        regs.eflags = 0xac3;
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) || res[0] != 0xfedcba98 ||
             regs.ecx != ((res[0] - 1) & ~res[0]) ||
             (regs.eflags & 0xfeb) != 0x202 || !check_eip(tzmsk) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing rdpid %ecx...");
    instr[0] = 0xF3; instr[1] = 0x0f; instr[2] = 0xC7; instr[3] = 0xf9;
    regs.eip = (unsigned long)&instr[0];
    rc = x86_emulate(&ctxt, &emulops);
    if ( (rc != X86EMUL_OKAY) ||
         (regs.ecx != TSC_AUX_VALUE) ||
         (regs.eip != (unsigned long)&instr[4]) )
        goto fail;
    printf("okay\n");

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

    printf("%-40s", "Testing movq %xmm0,32(%ecx)...");
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

    printf("%-40s", "Testing vmovq %xmm1,32(%edx)...");
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

    printf("%-40s", "Testing movd %mm3,32(%ecx)...");
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

    printf("%-40s", "Testing movd %xmm2,32(%edx)...");
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

    printf("%-40s", "Testing vmovd %xmm1,32(%ecx)...");
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

    printf("%-40s", "Testing movd %mm3,%ebx...");
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

    printf("%-40s", "Testing movd %xmm2,%ebx...");
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

    printf("%-40s", "Testing vmovd %xmm1,%ebx...");
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
    printf("%-40s", "Testing movq %mm3,32(%ecx)...");
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

    printf("%-40s", "Testing movq %xmm2,32(%edx)...");
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

    printf("%-40s", "Testing vmovq %xmm1,32(%ecx)...");
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

    printf("%-40s", "Testing movq %mm3,%rbx...");
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

    printf("%-40s", "Testing movq %xmm2,%rbx...");
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

    printf("%-40s", "Testing vmovq %xmm1,%rbx...");
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

    for ( j = 0; j < ARRAY_SIZE(blobs); j++ )
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
