#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <sys/mman.h>

#include "x86-emulate.h"
#include "blowfish.h"
#include "sse.h"
#include "sse2.h"
#include "sse4.h"
#include "sse2-avx.h"
#include "sse4-avx.h"
#include "avx.h"

#define verbose false /* Switch to true for far more logging. */

static void blowfish_set_regs(struct cpu_user_regs *regs)
{
    regs->eax = 2;
    regs->edx = 1;
}

static bool blowfish_check_regs(const struct cpu_user_regs *regs)
{
    return regs->eax == 2 && regs->edx == 1;
}

static bool simd_check_sse(void)
{
    return cpu_has_sse;
}

static bool simd_check_sse2(void)
{
    return cpu_has_sse2;
}

static bool simd_check_sse4(void)
{
    return cpu_has_sse4_2;
}

static bool simd_check_avx(void)
{
    return cpu_has_avx;
}
#define simd_check_sse2_avx  simd_check_avx
#define simd_check_sse4_avx  simd_check_avx

static void simd_set_regs(struct cpu_user_regs *regs)
{
    if ( cpu_has_mmx )
        asm volatile ( "emms" );
}

static bool simd_check_regs(const struct cpu_user_regs *regs)
{
    if ( !regs->eax )
        return true;
    printf("[line %u] ", (unsigned int)regs->eax);
    return false;
}

static const struct {
    const void *code;
    size_t size;
    unsigned int bitness;
    const char*name;
    bool (*check_cpu)(void);
    void (*set_regs)(struct cpu_user_regs *);
    bool (*check_regs)(const struct cpu_user_regs *);
} blobs[] = {
#define BLOWFISH(bits, desc, tag)                   \
    { .code = blowfish_x86_ ## bits ## tag,         \
      .size = sizeof(blowfish_x86_ ## bits ## tag), \
      .bitness = bits, .name = #desc,               \
      .set_regs = blowfish_set_regs,                \
      .check_regs = blowfish_check_regs }
#ifdef __x86_64__
    BLOWFISH(64, blowfish, ),
#endif
    BLOWFISH(32, blowfish, ),
    BLOWFISH(32, blowfish (push), _mno_accumulate_outgoing_args),
#undef BLOWFISH
#define SIMD_(bits, desc, feat, form)                               \
    { .code = feat ## _x86_ ## bits ## _D ## _ ## form,             \
      .size = sizeof(feat ## _x86_ ## bits ## _D ## _ ## form),     \
      .bitness = bits, .name = #desc,                               \
      .check_cpu = simd_check_ ## feat,                             \
      .set_regs = simd_set_regs,                                    \
      .check_regs = simd_check_regs }
#ifdef __x86_64__
# define SIMD(desc, feat, form) SIMD_(64, desc, feat, form), \
                                SIMD_(32, desc, feat, form)
#else
# define SIMD(desc, feat, form) SIMD_(32, desc, feat, form)
#endif
    SIMD(SSE scalar single,      sse,         f4),
    SIMD(SSE packed single,      sse,       16f4),
    SIMD(SSE2 scalar single,     sse2,        f4),
    SIMD(SSE2 packed single,     sse2,      16f4),
    SIMD(SSE2 scalar double,     sse2,        f8),
    SIMD(SSE2 packed double,     sse2,      16f8),
    SIMD(SSE2 packed s8,         sse2,      16i1),
    SIMD(SSE2 packed u8,         sse2,      16u1),
    SIMD(SSE2 packed s16,        sse2,      16i2),
    SIMD(SSE2 packed u16,        sse2,      16u2),
    SIMD(SSE2 packed s32,        sse2,      16i4),
    SIMD(SSE2 packed u32,        sse2,      16u4),
    SIMD(SSE2 packed s64,        sse2,      16i8),
    SIMD(SSE2 packed u64,        sse2,      16u8),
    SIMD(SSE4 scalar single,     sse4,        f4),
    SIMD(SSE4 packed single,     sse4,      16f4),
    SIMD(SSE4 scalar double,     sse4,        f8),
    SIMD(SSE4 packed double,     sse4,      16f8),
    SIMD(SSE4 packed s8,         sse4,      16i1),
    SIMD(SSE4 packed u8,         sse4,      16u1),
    SIMD(SSE4 packed s16,        sse4,      16i2),
    SIMD(SSE4 packed u16,        sse4,      16u2),
    SIMD(SSE4 packed s32,        sse4,      16i4),
    SIMD(SSE4 packed u32,        sse4,      16u4),
    SIMD(SSE4 packed s64,        sse4,      16i8),
    SIMD(SSE4 packed u64,        sse4,      16u8),
    SIMD(SSE2/AVX packed s8,     sse2_avx,  16i1),
    SIMD(SSE2/AVX packed u8,     sse2_avx,  16u1),
    SIMD(SSE2/AVX packed s16,    sse2_avx,  16i2),
    SIMD(SSE2/AVX packed u16,    sse2_avx,  16u2),
    SIMD(SSE2/AVX packed s32,    sse2_avx,  16i4),
    SIMD(SSE2/AVX packed u32,    sse2_avx,  16u4),
    SIMD(SSE2/AVX packed s64,    sse2_avx,  16i8),
    SIMD(SSE2/AVX packed u64,    sse2_avx,  16u8),
    SIMD(SSE4/AVX packed s8,     sse4_avx,  16i1),
    SIMD(SSE4/AVX packed u8,     sse4_avx,  16u1),
    SIMD(SSE4/AVX packed s16,    sse4_avx,  16i2),
    SIMD(SSE4/AVX packed u16,    sse4_avx,  16u2),
    SIMD(SSE4/AVX packed s32,    sse4_avx,  16i4),
    SIMD(SSE4/AVX packed u32,    sse4_avx,  16u4),
    SIMD(SSE4/AVX packed s64,    sse4_avx,  16i8),
    SIMD(SSE4/AVX packed u64,    sse4_avx,  16u8),
    SIMD(AVX scalar single,      avx,         f4),
    SIMD(AVX 128bit single,      avx,       16f4),
    SIMD(AVX 256bit single,      avx,       32f4),
    SIMD(AVX scalar double,      avx,         f8),
    SIMD(AVX 128bit double,      avx,       16f8),
    SIMD(AVX 256bit double,      avx,       32f8),
#undef SIMD_
#undef SIMD
};

static unsigned int bytes_read;

static int read(
    enum x86_segment seg,
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
    enum x86_segment seg,
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
    enum x86_segment seg,
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
    enum x86_segment seg,
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
    reg->p = 1;
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
    .put_fpu    = emul_test_put_fpu,
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
    ctxt.lma       = sizeof(void *) == 8;
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

    stack_exec = emul_test_init();

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
         !(regs.eflags & X86_EFLAGS_ZF) ||
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
    /* Bits 0-7: AL; Bit 8: EFLAGS.AF; Bit 9: EFLAGS.CF; Bit 10: DAA vs. DAS. */
    for ( i = 0; i < 0x800; i++ )
    {
        regs.eflags  = (i & 0x200) ? X86_EFLAGS_CF : 0;
        regs.eflags |= (i & 0x100) ? X86_EFLAGS_AF : 0;
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
        bcdres_native |= (regs.eflags & X86_EFLAGS_PF) ? 0x1000 : 0;
        bcdres_native |= (regs.eflags & X86_EFLAGS_ZF) ? 0x800 : 0;
        bcdres_native |= (regs.eflags & X86_EFLAGS_SF) ? 0x400 : 0;
        bcdres_native |= (regs.eflags & X86_EFLAGS_CF) ? 0x200 : 0;
        bcdres_native |= (regs.eflags & X86_EFLAGS_AF) ? 0x100 : 0;

        instr[0] = (i & 0x400) ? 0x2f: 0x27; /* daa/das */
        regs.eflags  = (i & 0x200) ? X86_EFLAGS_CF : 0;
        regs.eflags |= (i & 0x100) ? X86_EFLAGS_AF : 0;
        regs.eip    = (unsigned long)&instr[0];
        regs.eax    = (unsigned char)i;
        rc = x86_emulate(&ctxt, &emulops);
        bcdres_emul  = regs.eax;
        bcdres_emul |= (regs.eflags & X86_EFLAGS_PF) ? 0x1000 : 0;
        bcdres_emul |= (regs.eflags & X86_EFLAGS_ZF) ? 0x800 : 0;
        bcdres_emul |= (regs.eflags & X86_EFLAGS_SF) ? 0x400 : 0;
        bcdres_emul |= (regs.eflags & X86_EFLAGS_CF) ? 0x200 : 0;
        bcdres_emul |= (regs.eflags & X86_EFLAGS_AF) ? 0x100 : 0;
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

    printf("%-40s", "Testing shld $1,%ecx,(%edx)...");
    res[0]      = 0x12345678;
    regs.edx    = (unsigned long)res;
    regs.ecx    = 0x9abcdef0;
    instr[0] = 0x0f; instr[1] = 0xa4; instr[2] = 0x0a; instr[3] = 0x01;
    for ( i = 0; i < 0x20; ++i )
    {
        uint32_t r = res[0];
        const uint32_t m = X86_EFLAGS_ARITH_MASK & ~X86_EFLAGS_AF;
        unsigned long f;

        asm ( "shld $1,%2,%0; pushf; pop %1"
              : "+rm" (r), "=rm" (f) : "r" ((uint32_t)regs.ecx) );
        regs.eflags = f ^ m;
        regs.eip    = (unsigned long)&instr[0];
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) ||
             (regs.eip != (unsigned long)&instr[4]) ||
             (res[0] != r) ||
             ((regs.eflags ^ f) & m) )
            goto fail;
        regs.ecx <<= 1;
    }
    printf("okay\n");

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

    printf("%-40s", "Testing mov %%cr4,%%esi (bad ModRM)...");
    /*
     * Mod = 1, Reg = 4, R/M = 6 would normally encode a memory reference of
     * disp8(%esi), but mov to/from cr/dr are special and behave as if they
     * were encoded with Mod == 3.
     */
    instr[0] = 0x0f; instr[1] = 0x20, instr[2] = 0x66;
    instr[3] = 0; /* Supposed disp8. */
    regs.esi = 0;
    regs.eip = (unsigned long)&instr[0];
    rc = x86_emulate(&ctxt, &emulops);
    /*
     * We don't care precicely what gets read from %cr4 into %esi, just so
     * long as ModRM is treated as a register operand and 0(%esi) isn't
     * followed as a memory reference.
     */
    if ( (rc != X86EMUL_OKAY) ||
         (regs.eip != (unsigned long)&instr[3]) )
        goto fail;
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
             regs.ebx != (unsigned)(((signed)*res >> (regs.edx & 0x1f))) ||
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

    printf("%-40s", "Testing movq 32(%ecx),%xmm1...");
    if ( stack_exec && cpu_has_sse2 )
    {
        decl_insn(movq_from_mem2);

        asm volatile ( "pcmpeqb %%xmm1, %%xmm1\n"
                       put_insn(movq_from_mem2, "movq 32(%0), %%xmm1")
                       :: "c" (NULL) );

        set_insn(movq_from_mem2);
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(movq_from_mem2) )
            goto fail;
        asm ( "pcmpgtb %%xmm0, %%xmm0\n\t"
              "pcmpeqb %%xmm1, %%xmm0\n\t"
              "pmovmskb %%xmm0, %0" : "=r" (rc) );
        if ( rc != 0xffff )
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

    printf("%-40s", "Testing vmovq 32(%edx),%xmm0...");
    if ( stack_exec && cpu_has_avx )
    {
        decl_insn(vmovq_from_mem);

        asm volatile ( "pcmpeqb %%xmm0, %%xmm0\n"
                       put_insn(vmovq_from_mem, "vmovq 32(%0), %%xmm0")
                       :: "d" (NULL) );

        set_insn(vmovq_from_mem);
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(vmovq_from_mem) )
            goto fail;
        asm ( "pcmpgtb %%xmm1, %%xmm1\n\t"
              "pcmpeqb %%xmm0, %%xmm1\n\t"
              "pmovmskb %%xmm1, %0" : "=r" (rc) );
        if ( rc != 0xffff )
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

        asm volatile ( "vpxor %%xmm4, %%xmm4, %%xmm4\n"
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
              "vpmovmskb %%ymm0, %0" : "=r" (rc) );
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

    printf("%-40s", "Testing movd 32(%ecx),%mm4...");
    if ( stack_exec && cpu_has_mmx )
    {
        decl_insn(movd_from_mem);

        asm volatile ( "pcmpgtb %%mm4, %%mm4\n"
                       put_insn(movd_from_mem, "movd 32(%0), %%mm4")
                       :: "c" (NULL) );

        set_insn(movd_from_mem);
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(movd_from_mem) )
            goto fail;
        asm ( "pxor %%mm2,%%mm2\n\t"
              "pcmpeqb %%mm4, %%mm2\n\t"
              "pmovmskb %%mm2, %0" : "=r" (rc) );
        if ( rc != 0xf0 )
            goto fail;
        asm ( "pcmpeqb %%mm4, %%mm3\n\t"
              "pmovmskb %%mm3, %0" : "=r" (rc) );
        if ( rc != 0x0f )
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

    printf("%-40s", "Testing movd 32(%edx),%xmm3...");
    if ( stack_exec && cpu_has_sse2 )
    {
        decl_insn(movd_from_mem2);

        asm volatile ( "pcmpeqb %%xmm3, %%xmm3\n"
                       put_insn(movd_from_mem2, "movd 32(%0), %%xmm3")
                       :: "d" (NULL) );

        set_insn(movd_from_mem2);
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(movd_from_mem2) )
            goto fail;
        asm ( "pxor %%xmm1,%%xmm1\n\t"
              "pcmpeqb %%xmm3, %%xmm1\n\t"
              "pmovmskb %%xmm1, %0" : "=r" (rc) );
        if ( rc != 0xfff0 )
            goto fail;
        asm ( "pcmpeqb %%xmm2, %%xmm2\n\t"
              "pcmpeqb %%xmm3, %%xmm2\n\t"
              "pmovmskb %%xmm2, %0" : "=r" (rc) );
        if ( rc != 0x000f )
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

    printf("%-40s", "Testing vmovd 32(%ecx),%xmm2...");
    if ( stack_exec && cpu_has_avx )
    {
        decl_insn(vmovd_from_mem);

        asm volatile ( "pcmpeqb %%xmm2, %%xmm2\n"
                       put_insn(vmovd_from_mem, "vmovd 32(%0), %%xmm2")
                       :: "c" (NULL) );

        set_insn(vmovd_from_mem);
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(vmovd_from_mem) )
            goto fail;
        asm ( "pxor %%xmm0,%%xmm0\n\t"
              "pcmpeqb %%xmm2, %%xmm0\n\t"
              "pmovmskb %%xmm0, %0" : "=r" (rc) );
        if ( rc != 0xfff0 )
            goto fail;
        asm ( "pcmpeqb %%xmm1, %%xmm1\n\t"
              "pcmpeqb %%xmm2, %%xmm1\n\t"
              "pmovmskb %%xmm1, %0" : "=r" (rc) );
        if ( rc != 0x000f )
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

    printf("%-40s", "Testing movd %ebx,%mm4...");
    if ( stack_exec && cpu_has_mmx )
    {
        decl_insn(movd_from_reg);

        /* See comment next to movd above. */
        asm volatile ( "pcmpgtb %%mm4, %%mm4\n"
                       put_insn(movd_from_reg, "movd %%ebx, %%mm4")
                       :: );

        set_insn(movd_from_reg);
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) || !check_eip(movd_from_reg) )
            goto fail;
        asm ( "pxor %%mm2,%%mm2\n\t"
              "pcmpeqb %%mm4, %%mm2\n\t"
              "pmovmskb %%mm2, %0" : "=r" (rc) );
        if ( rc != 0xf0 )
            goto fail;
        asm ( "pcmpeqb %%mm4, %%mm3\n\t"
              "pmovmskb %%mm3, %0" : "=r" (rc) );
        if ( rc != 0x0f )
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

    printf("%-40s", "Testing movd %ebx,%xmm3...");
    if ( stack_exec && cpu_has_sse2 )
    {
        decl_insn(movd_from_reg2);

        /* See comment next to movd above. */
        asm volatile ( "pcmpgtb %%xmm3, %%xmm3\n"
                       put_insn(movd_from_reg2, "movd %%ebx, %%xmm3")
                       :: );

        set_insn(movd_from_reg2);
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) || !check_eip(movd_from_reg2) )
            goto fail;
        asm ( "pxor %%xmm1,%%xmm1\n\t"
              "pcmpeqb %%xmm3, %%xmm1\n\t"
              "pmovmskb %%xmm1, %0" : "=r" (rc) );
        if ( rc != 0xfff0 )
            goto fail;
        asm ( "pcmpeqb %%xmm2, %%xmm2\n\t"
              "pcmpeqb %%xmm3, %%xmm2\n\t"
              "pmovmskb %%xmm2, %0" : "=r" (rc) );
        if ( rc != 0x000f )
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

    printf("%-40s", "Testing vmovd %ebx,%xmm2...");
    if ( stack_exec && cpu_has_avx )
    {
        decl_insn(vmovd_from_reg);

        /* See comment next to movd above. */
        asm volatile ( "pcmpgtb %%xmm2, %%xmm2\n"
                       put_insn(vmovd_from_reg, "vmovd %%ebx, %%xmm2")
                       :: );

        set_insn(vmovd_from_reg);
        rc = x86_emulate(&ctxt, &emulops);
        if ( (rc != X86EMUL_OKAY) || !check_eip(vmovd_from_reg) )
            goto fail;
        asm ( "pxor %%xmm0,%%xmm0\n\t"
              "pcmpeqb %%xmm2, %%xmm0\n\t"
              "pmovmskb %%xmm0, %0" : "=r" (rc) );
        if ( rc != 0xfff0 )
            goto fail;
        asm ( "pcmpeqb %%xmm1, %%xmm1\n\t"
              "pcmpeqb %%xmm2, %%xmm1\n\t"
              "pmovmskb %%xmm1, %0" : "=r" (rc) );
        if ( rc != 0x000f )
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

    printf("%-40s", "Testing maskmovq (zero mask)...");
    if ( stack_exec && cpu_has_sse )
    {
        decl_insn(maskmovq);

        asm volatile ( "pcmpgtb %mm4, %mm4\n"
                       put_insn(maskmovq, "maskmovq %mm4, %mm4") );

        set_insn(maskmovq);
        regs.edi = 0;
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(maskmovq) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing maskmovdqu (zero mask)...");
    if ( stack_exec && cpu_has_sse2 )
    {
        decl_insn(maskmovdqu);

        asm volatile ( "pcmpgtb %xmm3, %xmm3\n"
                       put_insn(maskmovdqu, "maskmovdqu %xmm3, %xmm3") );

        set_insn(maskmovdqu);
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(maskmovdqu) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing lddqu 4(%edx),%xmm4...");
    if ( stack_exec && cpu_has_sse3 )
    {
        decl_insn(lddqu);

        asm volatile ( "pcmpgtb %%xmm4, %%xmm4\n"
                       put_insn(lddqu, "lddqu 4(%0), %%xmm4")
                       :: "d" (NULL) );

        set_insn(lddqu);
        memset(res, 0x55, 64);
        memset(res + 1, 0xff, 16);
        regs.edx = (unsigned long)res;
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(lddqu) )
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

    printf("%-40s", "Testing vlddqu (%ecx),%ymm4...");
    if ( stack_exec && cpu_has_avx )
    {
        decl_insn(vlddqu);

        asm volatile ( "vpxor %%xmm4, %%xmm4, %%xmm4\n"
                       put_insn(vlddqu, "vlddqu (%0), %%ymm4")
                       :: "c" (NULL) );

        set_insn(vlddqu);
        memset(res + 1, 0xff, 32);
        regs.ecx = (unsigned long)(res + 1);
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(vlddqu) )
            goto fail;
#if 0 /* Don't use AVX2 instructions for now */
        asm ( "vpcmpeqb %%ymm2, %%ymm2, %%ymm2\n\t"
              "vpcmpeqb %%ymm4, %%ymm2, %%ymm0\n\t"
              "vpmovmskb %%ymm0, %0" : "=r" (rc) );
#else
        asm ( "vextractf128 $1, %%ymm4, %%xmm3\n\t"
              "vpcmpeqb %%xmm2, %%xmm2, %%xmm2\n\t"
              "vpcmpeqb %%xmm4, %%xmm2, %%xmm0\n\t"
              "vpcmpeqb %%xmm3, %%xmm2, %%xmm1\n\t"
              "vpmovmskb %%xmm0, %0\n\t"
              "vpmovmskb %%xmm1, %1" : "=r" (rc), "=r" (i) );
        rc |= i << 16;
#endif
        if ( ~rc )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing movntdqa 16(%edx),%xmm4...");
    if ( stack_exec && cpu_has_sse4_1 )
    {
        decl_insn(movntdqa);

        asm volatile ( "pcmpgtb %%xmm4, %%xmm4\n"
                       put_insn(movntdqa, "movntdqa 16(%0), %%xmm4")
                       :: "d" (NULL) );

        set_insn(movntdqa);
        memset(res, 0x55, 64);
        memset(res + 4, 0xff, 16);
        regs.edx = (unsigned long)res;
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(movntdqa) )
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

    printf("%-40s", "Testing vmovntdqa (%ecx),%ymm4...");
    if ( stack_exec && cpu_has_avx2 )
    {
        decl_insn(vmovntdqa);

#if 0 /* Don't use AVX2 instructions for now */
        asm volatile ( "vpxor %%ymm4, %%ymm4, %%ymm4\n"
                       put_insn(vmovntdqa, "vmovntdqa (%0), %%ymm4")
                       :: "c" (NULL) );
#else
        asm volatile ( "vpxor %xmm4, %xmm4, %xmm4\n"
                       put_insn(vmovntdqa,
                                ".byte 0xc4, 0xe2, 0x7d, 0x2a, 0x21") );
#endif

        set_insn(vmovntdqa);
        memset(res, 0x55, 96);
        memset(res + 8, 0xff, 32);
        regs.ecx = (unsigned long)(res + 8);
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(vmovntdqa) )
            goto fail;
#if 0 /* Don't use AVX2 instructions for now */
        asm ( "vpcmpeqb %%ymm2, %%ymm2, %%ymm2\n\t"
              "vpcmpeqb %%ymm4, %%ymm2, %%ymm0\n\t"
              "vpmovmskb %%ymm0, %0" : "=r" (rc) );
#else
        asm ( "vextractf128 $1, %%ymm4, %%xmm3\n\t"
              "vpcmpeqb %%xmm2, %%xmm2, %%xmm2\n\t"
              "vpcmpeqb %%xmm4, %%xmm2, %%xmm0\n\t"
              "vpcmpeqb %%xmm3, %%xmm2, %%xmm1\n\t"
              "vpmovmskb %%xmm0, %0\n\t"
              "vpmovmskb %%xmm1, %1" : "=r" (rc), "=r" (i) );
        rc |= i << 16;
#endif
        if ( ~rc )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing pcmpestri $0x1a,(%ecx),%xmm2...");
    if ( stack_exec && cpu_has_sse4_2 )
    {
        decl_insn(pcmpestri);

        memcpy(res, "abcdefgh\0\1\2\3\4\5\6\7", 16);
        asm volatile ( "movq %0, %%xmm2\n"
                       put_insn(pcmpestri, "pcmpestri $0b00011010, (%1), %%xmm2")
                       :: "m" (res[0]), "c" (NULL) );

        set_insn(pcmpestri);
        regs.eax = regs.edx = 12;
        regs.ecx = (unsigned long)res;
        regs.eflags = X86_EFLAGS_PF | X86_EFLAGS_AF |
                      X86_EFLAGS_IF | X86_EFLAGS_OF;
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(pcmpestri) ||
             regs.ecx != 9 ||
             (regs.eflags & X86_EFLAGS_ARITH_MASK) !=
             (X86_EFLAGS_CF | X86_EFLAGS_ZF | X86_EFLAGS_SF) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing pcmpestrm $0x5a,(%ecx),%xmm2...");
    if ( stack_exec && cpu_has_sse4_2 )
    {
        decl_insn(pcmpestrm);

        asm volatile ( "movq %0, %%xmm2\n"
                       put_insn(pcmpestrm, "pcmpestrm $0b01011010, (%1), %%xmm2")
                       :: "m" (res[0]), "c" (NULL) );

        set_insn(pcmpestrm);
        regs.ecx = (unsigned long)res;
        regs.eflags = X86_EFLAGS_PF | X86_EFLAGS_AF |
                      X86_EFLAGS_IF | X86_EFLAGS_OF;
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(pcmpestrm) )
            goto fail;
        asm ( "pmovmskb %%xmm0, %0" : "=r" (rc) );
        if ( rc != 0x0e00 ||
             (regs.eflags & X86_EFLAGS_ARITH_MASK) !=
             (X86_EFLAGS_CF | X86_EFLAGS_ZF | X86_EFLAGS_SF) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing pcmpistri $0x1a,(%ecx),%xmm2...");
    if ( stack_exec && cpu_has_sse4_2 )
    {
        decl_insn(pcmpistri);

        asm volatile ( "movq %0, %%xmm2\n"
                       put_insn(pcmpistri, "pcmpistri $0b00011010, (%1), %%xmm2")
                       :: "m" (res[0]), "c" (NULL) );

        set_insn(pcmpistri);
        regs.eflags = X86_EFLAGS_CF | X86_EFLAGS_PF | X86_EFLAGS_AF |
                      X86_EFLAGS_IF | X86_EFLAGS_OF;
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(pcmpistri) ||
             regs.ecx != 16 ||
             (regs.eflags & X86_EFLAGS_ARITH_MASK) !=
             (X86_EFLAGS_ZF | X86_EFLAGS_SF) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing pcmpistrm $0x4a,(%ecx),%xmm2...");
    if ( stack_exec && cpu_has_sse4_2 )
    {
        decl_insn(pcmpistrm);

        asm volatile ( "movq %0, %%xmm2\n"
                       put_insn(pcmpistrm, "pcmpistrm $0b01001010, (%1), %%xmm2")
                       :: "m" (res[0]), "c" (NULL) );

        set_insn(pcmpistrm);
        regs.ecx = (unsigned long)res;
        regs.eflags = X86_EFLAGS_PF | X86_EFLAGS_AF | X86_EFLAGS_IF;
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(pcmpistrm) )
            goto fail;
        asm ( "pmovmskb %%xmm0, %0" : "=r" (rc) );
        if ( rc != 0xffff ||
            (regs.eflags & X86_EFLAGS_ARITH_MASK) !=
            (X86_EFLAGS_CF | X86_EFLAGS_ZF | X86_EFLAGS_SF | X86_EFLAGS_OF) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing vpcmpestri $0x7a,(%esi),%xmm2...");
    if ( stack_exec && cpu_has_avx )
    {
        decl_insn(vpcmpestri);

#ifdef __x86_64__
        /*
         * gas up to at least 2.27 doesn't honor explict "rex.w" for
         * VEX/EVEX encoded instructions, and also doesn't provide any
         * other means to control VEX.W.
         */
        asm volatile ( "movq %0, %%xmm2\n"
                       put_insn(vpcmpestri,
                                ".byte 0xC4, 0xE3, 0xF9, 0x61, 0x16, 0x7A")
                       :: "m" (res[0]) );
#else
        asm volatile ( "movq %0, %%xmm2\n"
                       put_insn(vpcmpestri,
                                "vpcmpestri $0b01111010, (%1), %%xmm2")
                       :: "m" (res[0]), "S" (NULL) );
#endif

        set_insn(vpcmpestri);
#ifdef __x86_64__
        regs.rax = ~0U + 1UL;
        regs.rcx = ~0UL;
#else
        regs.eax = 0x7fffffff;
#endif
        regs.esi = (unsigned long)res;
        regs.eflags = X86_EFLAGS_PF | X86_EFLAGS_AF | X86_EFLAGS_SF |
                      X86_EFLAGS_IF | X86_EFLAGS_OF;
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(vpcmpestri) ||
             regs.ecx != 11 ||
             (regs.eflags & X86_EFLAGS_ARITH_MASK) !=
             (X86_EFLAGS_ZF | X86_EFLAGS_CF) )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing extrq $4,$56,%xmm2...");
    if ( stack_exec && cpu_has_sse4a )
    {
        decl_insn(extrq_imm);

        res[0] = 0x44332211;
        res[1] = 0x88776655;
        asm volatile ( "movq %0, %%xmm2\n"
                       put_insn(extrq_imm, "extrq $4, $56, %%xmm2")
                       :: "m" (res[0]) : "memory" );

        set_insn(extrq_imm);
        rc = x86_emulate(&ctxt, &emulops);
        asm ( "movq %%xmm2, %0" : "=m" (res[4]) :: "memory" );
        if ( rc != X86EMUL_OKAY || !check_eip(extrq_imm) ||
             res[4] != 0x54433221 || res[5] != 0x877665 )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing extrq %xmm3,%xmm2...");
    if ( stack_exec && cpu_has_sse4a )
    {
        decl_insn(extrq_reg);

        res[4] = 56 + (4 << 8);
        res[5] = 0;
        asm volatile ( "movq %0, %%xmm2\n"
                       "movq %1, %%xmm3\n"
                       put_insn(extrq_reg, "extrq %%xmm3, %%xmm2")
                       :: "m" (res[0]), "m" (res[4]) : "memory" );

        set_insn(extrq_reg);
        rc = x86_emulate(&ctxt, &emulops);
        asm ( "movq %%xmm2, %0" : "=m" (res[4]) :: "memory" );
        if ( rc != X86EMUL_OKAY || !check_eip(extrq_reg) ||
             res[4] != 0x54433221 || res[5] != 0x877665 )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing insertq $12,$40,%xmm2,%xmm3...");
    if ( stack_exec && cpu_has_sse4a )
    {
        decl_insn(insertq_imm);

        res[4] = 0xccbbaa99;
        res[5] = 0x00ffeedd;
        asm volatile ( "movq %1, %%xmm2\n"
                       "movq %0, %%xmm3\n"
                       put_insn(insertq_imm, "insertq $12, $40, %%xmm2, %%xmm3")
                       :: "m" (res[0]), "m" (res[4]) : "memory" );

        set_insn(insertq_imm);
        rc = x86_emulate(&ctxt, &emulops);
        asm ( "movq %%xmm3, %0" : "=m" (res[4]) :: "memory" );
        if ( rc != X86EMUL_OKAY || !check_eip(insertq_imm) ||
             res[4] != 0xbaa99211 || res[5] != 0x887ddccb )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing insertq %xmm2,%xmm3...");
    if ( stack_exec && cpu_has_sse4a )
    {
        decl_insn(insertq_reg);

        res[4] = 0xccbbaa99;
        res[5] = 0x00ffeedd;
        res[6] = 40 + (12 << 8);
        res[7] = 0;
        asm volatile ( "movdqu %1, %%xmm2\n"
                       "movq %0, %%xmm3\n"
                       put_insn(insertq_reg, "insertq %%xmm2, %%xmm3")
                       :: "m" (res[0]), "m" (res[4]) : "memory" );

        set_insn(insertq_reg);
        rc = x86_emulate(&ctxt, &emulops);
        asm ( "movq %%xmm3, %0" : "=m" (res[4]) :: "memory" );
        if ( rc != X86EMUL_OKAY || !check_eip(insertq_reg) ||
             res[4] != 0xbaa99211 || res[5] != 0x887ddccb )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    /*
     * The following "maskmov" tests are not only making sure the written data
     * is correct, but verify (by placing operands on the mapping boundaries)
     * that elements controlled by clear mask bits aren't being accessed.
     */
    printf("%-40s", "Testing vmaskmovps %xmm1,%xmm2,(%edx)...");
    if ( stack_exec && cpu_has_avx )
    {
        decl_insn(vmaskmovps);

        asm volatile ( "vxorps %%xmm1, %%xmm1, %%xmm1\n\t"
                       "vcmpeqss %%xmm1, %%xmm1, %%xmm2\n\t"
                       put_insn(vmaskmovps, "vmaskmovps %%xmm1, %%xmm2, (%0)")
                       :: "d" (NULL) );

        memset(res + MMAP_SZ / sizeof(*res) - 8, 0xdb, 32);
        set_insn(vmaskmovps);
        regs.edx = (unsigned long)res + MMAP_SZ - 4;
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(vmaskmovps) ||
             res[MMAP_SZ / sizeof(*res) - 1] ||
             memcmp(res + MMAP_SZ / sizeof(*res) - 8,
                    res + MMAP_SZ / sizeof(*res) - 4, 12) )
            goto fail;

        asm volatile ( "vinsertps $0b00110111, %xmm2, %xmm2, %xmm2" );
        memset(res, 0xdb, 32);
        set_insn(vmaskmovps);
        regs.edx = (unsigned long)(res - 3);
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(vmaskmovps) ||
             res[0] || memcmp(res + 1, res + 4, 12) )
            goto fail;

        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing vmaskmovpd %xmm1,%xmm2,(%edx)...");
    if ( stack_exec && cpu_has_avx )
    {
        decl_insn(vmaskmovpd);

        asm volatile ( "vxorpd %%xmm1, %%xmm1, %%xmm1\n\t"
                       "vcmpeqsd %%xmm1, %%xmm1, %%xmm2\n\t"
                       put_insn(vmaskmovpd, "vmaskmovpd %%xmm1, %%xmm2, (%0)")
                       :: "d" (NULL) );

        memset(res + MMAP_SZ / sizeof(*res) - 8, 0xdb, 32);
        set_insn(vmaskmovpd);
        regs.edx = (unsigned long)res + MMAP_SZ - 8;
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(vmaskmovpd) ||
             res[MMAP_SZ / sizeof(*res) - 1] ||
             res[MMAP_SZ / sizeof(*res) - 2] ||
             memcmp(res + MMAP_SZ / sizeof(*res) - 8,
                    res + MMAP_SZ / sizeof(*res) - 4, 8) )
            goto fail;

        asm volatile ( "vmovddup %xmm2, %xmm2\n\t"
                       "vmovsd %xmm1, %xmm2, %xmm2" );
        memset(res, 0xdb, 32);
        set_insn(vmaskmovpd);
        regs.edx = (unsigned long)(res - 2);
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(vmaskmovpd) ||
             res[0] || res[1] || memcmp(res + 2, res + 4, 8) )
            goto fail;

        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing stmxcsr (%edx)...");
    if ( cpu_has_sse )
    {
        decl_insn(stmxcsr);

        asm volatile ( put_insn(stmxcsr, "stmxcsr (%0)") :: "d" (NULL) );

        res[0] = 0x12345678;
        res[1] = 0x87654321;
        asm ( "stmxcsr %0" : "=m" (res[2]) );
        set_insn(stmxcsr);
        regs.edx = (unsigned long)res;
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(stmxcsr) ||
             res[0] != res[2] || res[1] != 0x87654321 )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing ldmxcsr 4(%ecx)...");
    if ( cpu_has_sse )
    {
        decl_insn(ldmxcsr);

        asm volatile ( put_insn(ldmxcsr, "ldmxcsr 4(%0)") :: "c" (NULL) );

        set_insn(ldmxcsr);
        res[1] = mxcsr_mask;
        regs.ecx = (unsigned long)res;
        rc = x86_emulate(&ctxt, &emulops);
        asm ( "stmxcsr %0; ldmxcsr %1" : "=m" (res[0]) : "m" (res[2]) );
        if ( rc != X86EMUL_OKAY || !check_eip(ldmxcsr) ||
             res[0] != mxcsr_mask )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing vstmxcsr (%ecx)...");
    if ( cpu_has_avx )
    {
        decl_insn(vstmxcsr);

        asm volatile ( put_insn(vstmxcsr, "vstmxcsr (%0)") :: "c" (NULL) );

        res[0] = 0x12345678;
        res[1] = 0x87654321;
        set_insn(vstmxcsr);
        regs.ecx = (unsigned long)res;
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(vstmxcsr) ||
             res[0] != res[2] || res[1] != 0x87654321 )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

    printf("%-40s", "Testing vldmxcsr 4(%edx)...");
    if ( cpu_has_avx )
    {
        decl_insn(vldmxcsr);

        asm volatile ( put_insn(vldmxcsr, "vldmxcsr 4(%0)") :: "d" (NULL) );

        set_insn(vldmxcsr);
        res[1] = mxcsr_mask;
        regs.edx = (unsigned long)res;
        rc = x86_emulate(&ctxt, &emulops);
        asm ( "stmxcsr %0; ldmxcsr %1" : "=m" (res[0]) : "m" (res[2]) );
        if ( rc != X86EMUL_OKAY || !check_eip(vldmxcsr) ||
             res[0] != mxcsr_mask )
            goto fail;
        printf("okay\n");
    }
    else
        printf("skipped\n");

#ifdef __x86_64__
    printf("%-40s", "Testing vzeroupper (compat)...");
    if ( cpu_has_avx )
    {
        decl_insn(vzeroupper);

        ctxt.lma = false;
        ctxt.sp_size = ctxt.addr_size = 32;

        asm volatile ( "vxorps %xmm2, %xmm2, %xmm3\n"
                       "vcmpeqps %ymm3, %ymm3, %ymm4\n"
                       "vmovaps %ymm4, %ymm9\n"
                       put_insn(vzeroupper, "vzeroupper") );

        set_insn(vzeroupper);
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != X86EMUL_OKAY || !check_eip(vzeroupper) )
            goto fail;

        /* XMM0...XMM7 should have their high parts cleared. */
        asm ( "vextractf128 $1, %%ymm4, %%xmm0\n\t"
              "vpmovmskb %%xmm4, %0\n\t"
              "vpmovmskb %%xmm0, %1" : "=r" (rc), "=r" (i) );
        if ( rc != 0xffff || i )
            goto fail;

        /* XMM8...XMM15 should have their high parts preserved. */
        asm ( "vextractf128 $1, %%ymm9, %%xmm1\n\t"
              "vpmovmskb %%xmm9, %0\n\t"
              "vpmovmskb %%xmm1, %1" : "=r" (rc), "=r" (i) );
        if ( rc != 0xffff || i != 0xffff )
            goto fail;
        printf("okay\n");

        ctxt.lma = true;
        ctxt.sp_size = ctxt.addr_size = 64;
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
        if ( blobs[j].check_cpu && !blobs[j].check_cpu() )
            continue;

        if ( !blobs[j].size )
        {
            printf("%-39s n/a\n", blobs[j].name);
            continue;
        }

        memcpy(res, blobs[j].code, blobs[j].size);
        ctxt.lma = blobs[j].bitness == 64;
        ctxt.addr_size = ctxt.sp_size = blobs[j].bitness;

        if ( ctxt.addr_size == sizeof(void *) * CHAR_BIT )
        {
            i = printf("Testing %s native execution...", blobs[j].name);
            if ( blobs[j].set_regs )
                blobs[j].set_regs(&regs);
            asm volatile (
#if defined(__i386__)
                "call *%%ecx"
#else
                "call *%%rcx"
#endif
                : "+a" (regs.eax), "+d" (regs.edx) : "c" (res)
#ifdef __x86_64__
                : "rsi", "rdi", "r8", "r9", "r10", "r11"
#endif
            );
            if ( !blobs[j].check_regs(&regs) )
                goto fail;
            printf("%*sokay\n", i < 40 ? 40 - i : 0, "");
        }

        printf("Testing %s %u-bit code sequence",
               blobs[j].name, ctxt.addr_size);
        if ( blobs[j].set_regs )
            blobs[j].set_regs(&regs);
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
        while ( regs.eip >= (unsigned long)res &&
                regs.eip < (unsigned long)res + blobs[j].size )
        {
            if ( (i++ & 8191) == 0 )
                printf(".");
            rc = x86_emulate(&ctxt, &emulops);
            if ( rc != X86EMUL_OKAY )
            {
                printf("failed at %%eip == %08lx (opcode %08x)\n",
                       (unsigned long)regs.eip, ctxt.opcode);
                return 1;
            }
        }
        for ( ; i < 2 * 8192; i += 8192 )
            printf(".");
        if ( (regs.eip != 0x12345678) ||
             (regs.esp != ((unsigned long)res + MMAP_SZ)) ||
             !blobs[j].check_regs(&regs) )
            goto fail;
        printf("okay\n");
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
