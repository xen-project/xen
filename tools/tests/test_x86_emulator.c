
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
typedef uint8_t            u8;
typedef uint16_t           u16;
typedef uint32_t           u32;
typedef uint64_t           u64;
typedef int8_t             s8;
typedef int16_t            s16;
typedef int32_t            s32;
typedef int64_t            s64;
#include <public/xen.h>
#include <asm-x86/x86_emulate.h>
#include <sys/mman.h>

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

static int read(
    unsigned int seg,
    unsigned long offset,
    unsigned long *val,
    unsigned int bytes,
    struct x86_emulate_ctxt *ctxt)
{
    unsigned long addr = offset;
    switch ( bytes )
    {
    case 1: *val = *(u8 *)addr; break;
    case 2: *val = *(u16 *)addr; break;
    case 4: *val = *(u32 *)addr; break;
    case 8: *val = *(unsigned long *)addr; break;
    }
    return X86EMUL_CONTINUE;
}

static int write(
    unsigned int seg,
    unsigned long offset,
    unsigned long val,
    unsigned int bytes,
    struct x86_emulate_ctxt *ctxt)
{
    unsigned long addr = offset;
    switch ( bytes )
    {
    case 1: *(u8 *)addr = (u8)val; break;
    case 2: *(u16 *)addr = (u16)val; break;
    case 4: *(u32 *)addr = (u32)val; break;
    case 8: *(unsigned long *)addr = val; break;
    }
    return X86EMUL_CONTINUE;
}

static int cmpxchg(
    unsigned int seg,
    unsigned long offset,
    unsigned long old,
    unsigned long new,
    unsigned int bytes,
    struct x86_emulate_ctxt *ctxt)
{
    unsigned long addr = offset;
    switch ( bytes )
    {
    case 1: *(u8 *)addr = (u8)new; break;
    case 2: *(u16 *)addr = (u16)new; break;
    case 4: *(u32 *)addr = (u32)new; break;
    case 8: *(unsigned long *)addr = new; break;
    }
    return X86EMUL_CONTINUE;
}

static int cmpxchg8b(
    unsigned int seg,
    unsigned long offset,
    unsigned long old_lo,
    unsigned long old_hi,
    unsigned long new_lo,
    unsigned long new_hi,
    struct x86_emulate_ctxt *ctxt)
{
    unsigned long addr = offset;
    ((unsigned long *)addr)[0] = new_lo;
    ((unsigned long *)addr)[1] = new_hi;
    return X86EMUL_CONTINUE;
}

static struct x86_emulate_ops emulops = {
    .read       = read,
    .insn_fetch = read,
    .write      = write,
    .cmpxchg    = cmpxchg,
    .cmpxchg8b  = cmpxchg8b
};

int main(int argc, char **argv)
{
    struct x86_emulate_ctxt ctxt;
    struct cpu_user_regs regs;
    char *instr;
    unsigned int *res, i;
    int rc;
#ifndef __x86_64__
    unsigned int bcdres_native, bcdres_emul;
#endif

    ctxt.regs = &regs;
    ctxt.addr_size = 32;
    ctxt.sp_size   = 32;

    res = mmap((void *)0x100000, MMAP_SZ, PROT_READ|PROT_WRITE,
               MAP_FIXED|MAP_PRIVATE|MAP_ANONYMOUS, 0, 0);
    if ( res == MAP_FAILED )
    {
        fprintf(stderr, "mmap to low address failed\n");
        exit(1);
    }
    instr = (char *)res + 0x100;

    printf("%-40s", "Testing addl %%ecx,(%%eax)...");
    instr[0] = 0x01; instr[1] = 0x08;
    regs.eflags = 0x200;
    regs.eip    = (unsigned long)&instr[0];
    regs.ecx    = 0x12345678;
    regs.eax    = (unsigned long)res;
    *res        = 0x7FFFFFFF;
    rc = x86_emulate(&ctxt, &emulops);
    if ( (rc != 0) || 
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
    if ( (rc != 0) || 
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
    if ( (rc != 0) || 
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
    if ( (rc != 0) || 
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
    if ( (rc != 0) || 
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
    if ( (rc != 0) || 
         (*res != 0x923456AA) || 
         ((regs.eflags&0x240) != 0x200) ||
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
    if ( (rc != 0) || 
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
    if ( (rc != 0) || 
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
    if ( (rc != 0) || 
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
    if ( (rc != 0) ||
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
    if ( (rc != 0) ||
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
    if ( (rc != 0) ||
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
    if ( (rc != 0) || 
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
    if ( (rc != 0) ||
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
    if ( (rc != 0) ||
         (*res != 0x1234aa82) ||
         (regs.ecx != 0xaa82) ||
         ((regs.eflags&0x240) != 0x200) ||
         (regs.eip != (unsigned long)&instr[3]) )
        goto fail;
    printf("okay\n");

    printf("%-40s", "Testing xadd %%ax,(%%ecx)...");
    instr[0] = 0x66; instr[1] = 0x0f; instr[2] = 0xc1; instr[3] = 0x01;
    regs.eflags = 0x200;
    regs.eip    = (unsigned long)&instr[0];
    regs.ecx    = (unsigned long)res;
    regs.eax    = 0x12345678;
    *res        = 0x11111111;
    rc = x86_emulate(&ctxt, &emulops);
    if ( (rc != 0) ||
         (*res != 0x11116789) ||
         (regs.eax != 0x12341111) ||
         ((regs.eflags&0x240) != 0x200) ||
         (regs.eip != (unsigned long)&instr[4]) )
        goto fail;
    printf("okay\n");

    printf("%-40s", "Testing dec %%ax...");
    instr[0] = 0x66; instr[1] = 0x48;
    regs.eflags = 0x200;
    regs.eip    = (unsigned long)&instr[0];
    regs.eax    = 0x00000000;
    rc = x86_emulate(&ctxt, &emulops);
    if ( (rc != 0) ||
         (regs.eax != 0x0000ffff) ||
         ((regs.eflags&0x240) != 0x200) ||
         (regs.eip != (unsigned long)&instr[2]) )
        goto fail;
    printf("okay\n");

    printf("%-40s", "Testing lea 8(%%ebp),%%eax...");
    instr[0] = 0x8d; instr[1] = 0x45; instr[2] = 0x08;
    regs.eflags = 0x200;
    regs.eip    = (unsigned long)&instr[0];
    regs.eax    = 0x12345678;
    regs.ebp    = 0xaaaaaaaa;
    rc = x86_emulate(&ctxt, &emulops);
    if ( (rc != 0) ||
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
        if ( (rc != 0) || (regs.eax > 255) ||
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

    printf("Testing blowfish code sequence");
    memcpy(res, blowfish_code, sizeof(blowfish_code));
    regs.eax = 2;
    regs.edx = 1;
    regs.eip = (unsigned long)res;
    regs.esp = (unsigned long)res + MMAP_SZ - 4;
    *(uint32_t *)(unsigned long)regs.esp = 0x12345678;
    regs.eflags = 2;
    i = 0;
    while ( (uint32_t)regs.eip != 0x12345678 )
    {
        if ( (i++ & 8191) == 0 )
            printf(".");
        rc = x86_emulate(&ctxt, &emulops);
        if ( rc != 0 )
        {
            printf("failed at %%eip == %08x\n", (unsigned int)regs.eip);
            return 1;
        }
    }
    if ( (regs.esp != ((unsigned long)res + MMAP_SZ)) ||
         (regs.eax != 2) || (regs.edx != 1) )
        goto fail;
    printf("okay\n");

#ifndef __x86_64__
    printf("%-40s", "Testing blowfish native execution...");    
    asm volatile (
        "movl $0x100000,%%ecx; call *%%ecx"
        : "=a" (regs.eax), "=d" (regs.edx)
        : "0" (2), "1" (1) : "ecx" );
    if ( (regs.eax != 2) || (regs.edx != 1) )
        goto fail;
    printf("okay\n");
#endif    

    return 0;

 fail:
    printf("failed!\n");
    return 1;
}
