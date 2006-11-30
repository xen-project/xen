
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

#define PFEC_write_access (1U<<1)

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
    read, write, cmpxchg, cmpxchg8b
};

int main(int argc, char **argv)
{
    struct x86_emulate_ctxt ctxt;
    struct cpu_user_regs regs;
    char instr[20] = { 0x01, 0x08 }; /* add %ecx,(%eax) */
    unsigned int *res;
    int rc;

    ctxt.regs = &regs;
    ctxt.mode = X86EMUL_MODE_PROT32;

    res = mmap((void *)0x100000, 0x1000, PROT_READ|PROT_WRITE,
               MAP_FIXED|MAP_PRIVATE|MAP_ANONYMOUS, 0, 0);
    if ( res == MAP_FAILED )
    {
        fprintf(stderr, "mmap to low address failed\n");
        exit(1);
    }

    printf("%-40s", "Testing addl %%ecx,(%%eax)...");
    instr[0] = 0x01; instr[1] = 0x08;
    regs.eflags = 0x200;
    regs.eip    = (unsigned long)&instr[0];
    regs.ecx    = 0x12345678;
    regs.error_code = PFEC_write_access;
    regs.eax    = (unsigned long)res;
    *res        = 0x7FFFFFFF;
    rc = x86_emulate_memop(&ctxt, &emulops);
    if ( (rc != 0) || 
         (*res != 0x92345677) || 
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
    regs.error_code = 0;
    rc = x86_emulate_memop(&ctxt, &emulops);
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
    regs.error_code = 0;
    rc = x86_emulate_memop(&ctxt, &emulops);
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
    regs.error_code = PFEC_write_access;
    rc = x86_emulate_memop(&ctxt, &emulops);
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
    regs.error_code = PFEC_write_access;
    rc = x86_emulate_memop(&ctxt, &emulops);
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
    regs.error_code = PFEC_write_access;
    rc = x86_emulate_memop(&ctxt, &emulops);
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
    regs.error_code = PFEC_write_access;
    rc = x86_emulate_memop(&ctxt, &emulops);
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
    regs.error_code = 0; /* read fault */
    rc = x86_emulate_memop(&ctxt, &emulops);
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
    regs.error_code = PFEC_write_access;
    rc = x86_emulate_memop(&ctxt, &emulops);
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
    regs.error_code = PFEC_write_access;
    rc = x86_emulate_memop(&ctxt, &emulops);
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
    regs.error_code = PFEC_write_access;
    rc = x86_emulate_memop(&ctxt, &emulops);
    if ( (rc != 0) || 
         (res[0] != 0x9999AAAA) ||
         (res[1] != 0xCCCCFFFF) ||
         ((regs.eflags&0x240) != 0x240) ||
         (regs.eip != (unsigned long)&instr[3]) )
        goto fail;
    printf("okay\n");

    printf("%-40s", "Testing cmpxchg8b (%edi) [failing]...");
    instr[0] = 0x0f; instr[1] = 0xc7; instr[2] = 0x0f;
    regs.eip    = (unsigned long)&instr[0];
    regs.edi    = (unsigned long)res;
    regs.error_code = PFEC_write_access;
    rc = x86_emulate_memop(&ctxt, &emulops);
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
    regs.eip    = (unsigned long)&instr[0];
    regs.ecx    = 0x12345678;
    regs.eax    = (unsigned long)res;
    *res        = 0x82;
    regs.error_code = 0;
    rc = x86_emulate_memop(&ctxt, &emulops);
    if ( (rc != 0) ||
         (*res != 0x82) ||
         (regs.ecx != 0xFFFFFF82) ||
         ((regs.eflags&0x240) != 0x200) ||
         (regs.eip != (unsigned long)&instr[3]) )
        goto fail;
    printf("okay\n");

    printf("%-40s", "Testing movzxwd (%%eax),%%ecx...");
    instr[0] = 0x0f; instr[1] = 0xb7; instr[2] = 0x08;
    regs.eip    = (unsigned long)&instr[0];
    regs.ecx    = 0x12345678;
    regs.eax    = (unsigned long)res;
    *res        = 0x1234aa82;
    regs.error_code = 0;
    rc = x86_emulate_memop(&ctxt, &emulops);
    if ( (rc != 0) ||
         (*res != 0x1234aa82) ||
         (regs.ecx != 0xaa82) ||
         ((regs.eflags&0x240) != 0x200) ||
         (regs.eip != (unsigned long)&instr[3]) )
        goto fail;
    printf("okay\n");

    return 0;

 fail:
    printf("failed!\n");
    return 1;
}
