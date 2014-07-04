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
#include <signal.h>
#include <ctype.h>
#include <string.h>
#include <inttypes.h>
#include <getopt.h>
#include <limits.h>

#include "xenctrl.h"
#include <xen/foreign/x86_32.h>
#include <xen/foreign/x86_64.h>
#include <xen/hvm/save.h>

#define DEFAULT_NR_STACK_PAGES 1
#define DEFAULT_BYTES_PER_LINE 32
#define DEFAULT_LINES 5

/* Note: the order of these matter.
 * NOT_KERNEL_ADDR must be < both KERNEL_DATA_ADDR and KERNEL_TEXT_ADDR.
 * KERNEL_DATA_ADDR must be < KERNEL_TEXT_ADDR. */
typedef enum type_of_addr_ {
    NOT_KERNEL_ADDR,
    KERNEL_DATA_ADDR,
    KERNEL_TEXT_ADDR,
} type_of_addr;

#if defined (__i386__) || defined (__x86_64__)
static const uint64_t cr_reg_mask[5] = { [2] = ~UINT64_C(0) };
static const uint64_t dr_reg_mask[8] = { [0 ... 3] = ~UINT64_C(0) };
typedef unsigned long long guest_word_t;
#define FMT_16B_WORD "%04llx"
#define FMT_32B_WORD "%08llx"
#define FMT_64B_WORD "%016llx"
/* Word-length of the guest's own data structures */
int guest_word_size = sizeof (unsigned long);
/* Word-length of the context record we get from xen */
int ctxt_word_size = sizeof (unsigned long);
int guest_protected_mode = 1;
#elif defined(__arm__)
#define NO_TRANSLATION
typedef uint64_t guest_word_t;
#define FMT_16B_WORD "%04llx"
#define FMT_32B_WORD "%08llx"
#define FMT_64B_WORD "%016llx"
#elif defined(__aarch64__)
#define NO_TRANSLATION
typedef uint64_t guest_word_t;
#define FMT_16B_WORD "%04llx"
#define FMT_32B_WORD "%08llx"
#define FMT_64B_WORD "%016llx"
#endif

#define MAX_BYTES_PER_LINE 128

static struct xenctx {
    xc_interface *xc_handle;
    int domid;
    int frame_ptrs;
    int stack_trace;
    int disp_all;
    int nr_stack_pages;
    int bytes_per_line;
    int lines;
    int decode_as_ascii;
    int tag_stack_dump;
    int tag_call_trace;
    int all_vcpus;
#ifndef NO_TRANSLATION
    guest_word_t mem_addr;
    guest_word_t stk_addr;
    int do_memory;
    int do_stack;
#endif
    int kernel_start_set;
    xc_dominfo_t dominfo;
} xenctx;

struct symbol {
    guest_word_t address;
    char *name;
    struct symbol *next;
} *symbol_table = NULL;

guest_word_t kernel_stext, kernel_etext, kernel_sinittext, kernel_einittext, kernel_hypercallpage;
guest_word_t kernel_text;

#if defined (__i386__) || defined (__arm__)
unsigned long long kernel_start = 0xc0000000;
unsigned long long kernel_end = 0xffffffffULL;
#elif defined (__x86_64__)
unsigned long long kernel_start = 0xffffffff80000000UL;
unsigned long long kernel_end = 0xffffffffffffffffUL;
#elif defined (__aarch64__)
unsigned long long kernel_start = 0xffffff8000000000UL;
unsigned long long kernel_end = 0xffffffffffffffffULL;
#endif

static type_of_addr kernel_addr(guest_word_t addr)
{
    if ( symbol_table == NULL )
    {
        if ( addr > kernel_start )
            return KERNEL_TEXT_ADDR;
        else
            return NOT_KERNEL_ADDR;
    }

    if (addr >= kernel_stext &&
        addr <= kernel_etext)
        return KERNEL_TEXT_ADDR;
    if ( kernel_hypercallpage &&
         (addr >= kernel_hypercallpage &&
          addr <= kernel_hypercallpage + 4096) )
        return KERNEL_TEXT_ADDR;
    if (addr >= kernel_sinittext &&
        addr <= kernel_einittext)
        return KERNEL_TEXT_ADDR;
    if ( xenctx.kernel_start_set )
    {
        if ( addr > kernel_start )
            return KERNEL_TEXT_ADDR;
    } else {
        if ( addr >= kernel_text &&
             addr <= kernel_end )
            return KERNEL_DATA_ADDR;
        if ( addr >= kernel_start &&
             addr <= kernel_end )
            return KERNEL_TEXT_ADDR;
    }
    return NOT_KERNEL_ADDR;
}

#if 0
static void free_symbol(struct symbol *symbol)
{
    if (symbol == NULL)
        return;
    if (symbol->name)
        free(symbol->name);
    free(symbol);
}
#endif

static void insert_symbol(struct symbol *symbol)
{
    static struct symbol *prev = NULL;
    struct symbol *s = symbol_table;

    if (s == NULL) {
        symbol_table = symbol;
        symbol->next = NULL;
        return;
    }

    /* The System.map is usually already sorted... */
    if (prev
        && prev->address <= symbol->address
        && (!prev->next || prev->next->address > symbol->address)) {
        s = prev;
    } else {
        /* ... otherwise do crappy/slow search for the correct place */
        while (s->next && s->next->address <= symbol->address)
            s = s->next;
    }

    symbol->next = s->next;
    s->next = symbol;
    prev = symbol;
}

static struct symbol *lookup_symbol(guest_word_t address)
{
    struct symbol *s = symbol_table;

    if (!s)
        return NULL;

    while (s->next && s->next->address < address)
        s = s->next;

    return s->next && s->next->address <= address ? s->next : s;
}

static void print_symbol(guest_word_t addr, type_of_addr type)
{
    struct symbol *s;

    if ( kernel_addr(addr) < type )
        return;

    s = lookup_symbol(addr);

    if (s==NULL)
        return;

    if (addr==s->address)
        printf(" %s", s->name);
    else
        printf(" %s+%#x", s->name, (unsigned int)(addr - s->address));
}

static void read_symbol_table(const char *symtab)
{
    char type, line[256];
    char *p;
    struct symbol *symbol;
    FILE *f;
    guest_word_t address;

    f = fopen(symtab, "r");
    if(f == NULL) {
        fprintf(stderr, "failed to open symbol table %s\n", symtab);
        exit(-1);
    }

    while(!feof(f)) {
        if(fgets(line,256,f)==NULL)
            break;

        /* need more checks for syntax here... */
        address = strtoull(line, &p, 16);
        if (!isspace((uint8_t)*p++))
            continue;
        type = *p++;
        if (!isalpha((uint8_t)type) && type != '?')
            continue;
        if (!isspace((uint8_t)*p++))
            continue;

        /* in the future we should handle the module name
         * being appended here, this would allow us to use
         * /proc/kallsyms as our symbol table
         */
        if (p[strlen(p)-1] == '\n')
            p[strlen(p)-1] = '\0';

        switch (type) {
        case 'A': /* global absolute */
        case 'a': /* local absolute */
            break;
        case 'U': /* undefined */
        case 'v': /* undefined weak object */
        case 'w': /* undefined weak function */
            continue;
        default:
            symbol = malloc(sizeof(*symbol));
            if (symbol == NULL) {
                fclose(f);
                return;
            }

            symbol->address = address;
            symbol->name = strdup(p);
            if (symbol->name == NULL) {
                free(symbol);
                fclose(f);
                return;
            }

            insert_symbol(symbol);
            break;
        }

        if (strcmp(p, "_stext") == 0)
            kernel_stext = address;
        else if (strcmp(p, "_etext") == 0)
            kernel_etext = address;
        else if ( strcmp(p, "_text") == 0 )
            kernel_text = address;
        else if ( strcmp(p, "_end") == 0 || strcmp(p, "__bss_stop") == 0 )
            kernel_end = address;
        else if (strcmp(p, "_sinittext") == 0)
            kernel_sinittext = address;
        else if (strcmp(p, "_einittext") == 0)
            kernel_einittext = address;
        else if (strcmp(p, "hypercall_page") == 0)
            kernel_hypercallpage = address;
    }

    fclose(f);
}

#if defined(__i386__) || defined(__x86_64__)
#define CR0_PE  0x1
char *flag_values[22][2] =
{/*  clear,     set,       bit# */
    { NULL,     "c"    }, // 0        Carry
    { NULL,     NULL   }, // 1
    { NULL,     "p"    }, // 2        Parity
    { NULL,     NULL   }, // 3
    { NULL,     "a"    }, // 4        Adjust
    { NULL,     NULL   }, // 5
    { "nz",     "z"    }, // 6        Zero
    { NULL,     "s"    }, // 7        Sign
    { NULL,     "tf"   }, // 8        Trap
    { NULL,     "i"    }, // 9        Interrupt (enabled)
    { NULL,     "d=b"  }, // 10       Direction
    { NULL,     "o"    }, // 11       Overflow
    { NULL,     NULL   }, // 12       12+13 == IOPL
    { NULL,     NULL   }, // 13
    { NULL,     "nt"   }, // 14       Nested Task
    { NULL,     NULL   }, // 15
    { NULL,     "rf"   }, // 16       Resume Flag
    { NULL,     "v86"  }, // 17       Virtual 8086 mode
    { NULL,     "ac"   }, // 18       Alignment Check (enabled)
    { NULL,     "vif"  }, // 19       Virtual Interrupt (enabled)
    { NULL,     "vip"  }, // 20       Virtual Interrupt Pending
    { NULL,     "cid"  }  // 21       Cpuid Identification Flag
};

static void print_flags(uint64_t flags)
{
    int i;

    printf("\nflags: %08" PRIx64, flags);
    for (i = 21; i >= 0; i--) {
        char *s = flag_values[i][(flags >> i) & 1];
        if (s != NULL)
            printf(" %s", s);
    }
    printf("\n");
}

static void print_special(void *regs, const char *name, unsigned int mask,
                          const uint64_t reg_is_addr_mask[], int width)
{
    unsigned int i;

    printf("\n");
    for (i = 0; mask; mask >>= 1, ++i)
        if (mask & 1) {
            if ( width == 4 )
            {
                printf("%s%u: %08"PRIx32, name, i, ((uint32_t *) regs)[i]);
                if ( reg_is_addr_mask[i] )
                    print_symbol(reg_is_addr_mask[i] & ((uint32_t *) regs)[i],
                                 KERNEL_DATA_ADDR);
            }
            else
            {
                printf("%s%u: %016"PRIx64, name, i, ((uint64_t *) regs)[i]);
                if ( reg_is_addr_mask[i] )
                    print_symbol(reg_is_addr_mask[i] & ((uint64_t *) regs)[i],
                                 KERNEL_DATA_ADDR);
            }
            printf("\n");
        }
}

static void print_ctx_32(vcpu_guest_context_x86_32_t *ctx)
{
    struct cpu_user_regs_x86_32 *regs = &ctx->user_regs;

    printf("cs:eip: %04x:%08x", regs->cs, regs->eip);
    print_symbol(regs->eip, KERNEL_TEXT_ADDR);
    print_flags(regs->eflags);
    printf("ss:esp: %04x:%08x\n", regs->ss, regs->esp);

    printf("eax: %08x\t", regs->eax);
    printf("ebx: %08x\t", regs->ebx);
    printf("ecx: %08x\t", regs->ecx);
    printf("edx: %08x\n", regs->edx);

    printf("esi: %08x\t", regs->esi);
    printf("edi: %08x\t", regs->edi);
    printf("ebp: %08x\n", regs->ebp);

    printf(" ds:     %04x\t", regs->ds);
    printf(" es:     %04x\t", regs->es);
    printf(" fs:     %04x\t", regs->fs);
    printf(" gs:     %04x\n", regs->gs);

    if (xenctx.disp_all) {
        print_special(ctx->ctrlreg, "cr", 0x1d, cr_reg_mask, 4);
        print_special(ctx->debugreg, "dr", 0xcf, dr_reg_mask, 4);
    }
}

static void print_ctx_32on64(vcpu_guest_context_x86_64_t *ctx)
{
    struct cpu_user_regs_x86_64 *regs = &ctx->user_regs;

    printf("cs:eip: %04x:%08x", regs->cs, (uint32_t)regs->eip);
    print_symbol((uint32_t)regs->eip, KERNEL_TEXT_ADDR);
    print_flags((uint32_t)regs->eflags);
    printf("ss:esp: %04x:%08x\n", regs->ss, (uint32_t)regs->esp);

    printf("eax: %08x\t", (uint32_t)regs->eax);
    printf("ebx: %08x\t", (uint32_t)regs->ebx);
    printf("ecx: %08x\t", (uint32_t)regs->ecx);
    printf("edx: %08x\n", (uint32_t)regs->edx);

    printf("esi: %08x\t", (uint32_t)regs->esi);
    printf("edi: %08x\t", (uint32_t)regs->edi);
    printf("ebp: %08x\n", (uint32_t)regs->ebp);

    printf(" ds:     %04x\t", regs->ds);
    printf(" es:     %04x\t", regs->es);
    printf(" fs:     %04x\t", regs->fs);
    printf(" gs:     %04x\n", regs->gs);

    if (xenctx.disp_all) {
        uint32_t tmp_regs[8];
        int i;

        for (i = 0; i < 5; i++)
            tmp_regs[i] = ctx->ctrlreg[i];
        print_special(tmp_regs, "cr", 0x1d, cr_reg_mask, 4);
        for (i = 0; i < 8; i++)
            tmp_regs[i] = ctx->debugreg[i];
        print_special(tmp_regs, "dr", 0xcf, dr_reg_mask, 4);
    }
}

static void print_ctx_64(vcpu_guest_context_x86_64_t *ctx)
{
    struct cpu_user_regs_x86_64 *regs = &ctx->user_regs;

    printf("rip: %016"PRIx64, regs->rip);
    print_symbol(regs->rip, KERNEL_TEXT_ADDR);
    print_flags(regs->rflags);
    printf("rsp: %016"PRIx64"\n", regs->rsp);

    printf("rax: %016"PRIx64"\t", regs->rax);
    printf("rcx: %016"PRIx64"\t", regs->rcx);
    printf("rdx: %016"PRIx64"\n", regs->rdx);

    printf("rbx: %016"PRIx64"\t", regs->rbx);
    printf("rsi: %016"PRIx64"\t", regs->rsi);
    printf("rdi: %016"PRIx64"\n", regs->rdi);

    printf("rbp: %016"PRIx64"\t", regs->rbp);
    printf(" r8: %016"PRIx64"\t", regs->r8);
    printf(" r9: %016"PRIx64"\n", regs->r9);

    printf("r10: %016"PRIx64"\t", regs->r10);
    printf("r11: %016"PRIx64"\t", regs->r11);
    printf("r12: %016"PRIx64"\n", regs->r12);

    printf("r13: %016"PRIx64"\t", regs->r13);
    printf("r14: %016"PRIx64"\t", regs->r14);
    printf("r15: %016"PRIx64"\n", regs->r15);

    printf(" cs: %04x\t", regs->cs);
    printf(" ss: %04x\t", regs->ss);
    printf(" ds: %04x\t", regs->ds);
    printf(" es: %04x\n", regs->es);

    printf(" fs: %04x @ %016"PRIx64, regs->fs, ctx->fs_base);
    print_symbol(ctx->fs_base, KERNEL_DATA_ADDR);
    printf("\n");
    printf(" gs: %04x @ %016"PRIx64"/%016"PRIx64, regs->gs,
           ctx->gs_base_kernel, ctx->gs_base_user);
    if ( symbol_table )
    {
        print_symbol(ctx->gs_base_kernel, KERNEL_DATA_ADDR);
        printf("/");
        print_symbol(ctx->gs_base_user, KERNEL_DATA_ADDR);
    }
    printf("\n");

    if (xenctx.disp_all) {
        print_special(ctx->ctrlreg, "cr", 0x1d, cr_reg_mask, 8);
        print_special(ctx->debugreg, "dr", 0xcf, dr_reg_mask, 8);
    }
}

static void print_ctx(vcpu_guest_context_any_t *ctx)
{
    if (ctxt_word_size == 4)
        print_ctx_32(&ctx->x32);
    else if (guest_word_size != 8)
        print_ctx_32on64(&ctx->x64);
    else
        print_ctx_64(&ctx->x64);
}

#define NONPROT_MODE_SEGMENT_SHIFT 4

static guest_word_t instr_pointer(vcpu_guest_context_any_t *ctx)
{
    guest_word_t r;
    if (ctxt_word_size == 4)
    {
        r = ctx->x32.user_regs.eip;

        if ( !guest_protected_mode )
            r += ctx->x32.user_regs.cs << NONPROT_MODE_SEGMENT_SHIFT;
    }
    else
    {
        r = ctx->x64.user_regs.rip;

        if ( !guest_protected_mode )
            r += ctx->x64.user_regs.cs << NONPROT_MODE_SEGMENT_SHIFT;
    }

    return r;
}

static guest_word_t stack_pointer(vcpu_guest_context_any_t *ctx)
{
    guest_word_t r;
    if (ctxt_word_size == 4)
    {
        r = ctx->x32.user_regs.esp;

        if ( !guest_protected_mode )
            r += ctx->x32.user_regs.ss << NONPROT_MODE_SEGMENT_SHIFT;
    }
    else
    {
        r = ctx->x64.user_regs.rsp;

        if ( !guest_protected_mode )
            r += ctx->x64.user_regs.ss << NONPROT_MODE_SEGMENT_SHIFT;
    }

    return r;
}

static guest_word_t frame_pointer(vcpu_guest_context_any_t *ctx)
{
    if (ctxt_word_size == 4)
        return ctx->x32.user_regs.ebp;
    else
        return ctx->x64.user_regs.rbp;
}

#elif defined(__arm__) || defined(__aarch64__)

static void print_ctx_32(vcpu_guest_context_t *ctx)
{
    vcpu_guest_core_regs_t *regs = &ctx->user_regs;

    printf("PC:       %08"PRIx32, regs->pc32);
    print_symbol(regs->pc32, KERNEL_TEXT_ADDR);
    printf("\n");
    printf("CPSR:     %08"PRIx32"\n", regs->cpsr);
    printf("USR:               SP:%08"PRIx32" LR:%08"PRIx32"\n",
           regs->sp_usr, regs->lr_usr);
    printf("SVC: SPSR:%08"PRIx32" SP:%08"PRIx32" LR:%08"PRIx32"\n",
           regs->spsr_svc, regs->sp_svc, regs->lr_svc);
    printf("FIQ: SPSR:%08"PRIx32" SP:%08"PRIx32" LR:%08"PRIx32"\n",
           regs->spsr_fiq, regs->sp_fiq, regs->lr_fiq);
    printf("IRQ: SPSR:%08"PRIx32" SP:%08"PRIx32" LR:%08"PRIx32"\n",
           regs->spsr_irq, regs->sp_irq, regs->lr_irq);
    printf("ABT: SPSR:%08"PRIx32" SP:%08"PRIx32" LR:%08"PRIx32"\n",
           regs->spsr_abt, regs->sp_abt, regs->lr_abt);
    printf("UND: SPSR:%08"PRIx32" SP:%08"PRIx32" LR:%08"PRIx32"\n",
           regs->spsr_und, regs->sp_und, regs->lr_und);

    printf("\n");
    printf(" r0_usr: %08"PRIx32"\t", regs->r0_usr);
    printf(" r1_usr: %08"PRIx32"\t", regs->r1_usr);
    printf(" r2_usr: %08"PRIx32"\n", regs->r2_usr);

    printf(" r3_usr: %08"PRIx32"\t", regs->r3_usr);
    printf(" r4_usr: %08"PRIx32"\t", regs->r4_usr);
    printf(" r5_usr: %08"PRIx32"\n", regs->r5_usr);

    printf(" r6_usr: %08"PRIx32"\t", regs->r6_usr);
    printf(" r7_usr: %08"PRIx32"\t", regs->r7_usr);
    printf(" r8_usr: %08"PRIx32"\n", regs->r8_usr);

    printf(" r9_usr: %08"PRIx32"\t", regs->r9_usr);
    printf("r10_usr: %08"PRIx32"\t", regs->r10_usr);
    printf("r11_usr: %08"PRIx32"\n", regs->r11_usr);

    printf("r12_usr: %08"PRIx32"\n", regs->r12_usr);
    printf("\n");

    printf(" r8_fiq: %08"PRIx32"\n", regs->r8_fiq);

    printf(" r9_fiq: %08"PRIx32"\t", regs->r9_fiq);
    printf("r10_fiq: %08"PRIx32"\t", regs->r10_fiq);
    printf("r11_fiq: %08"PRIx32"\n", regs->r11_fiq);

    printf("r12_fiq: %08"PRIx32"\n", regs->r12_fiq);
    printf("\n");
}

#ifdef __aarch64__
static void print_ctx_64(vcpu_guest_context_t *ctx)
{
    vcpu_guest_core_regs_t *regs = &ctx->user_regs;

    printf("PC:       %016"PRIx64, regs->pc64);
    print_symbol(regs->pc64, KERNEL_TEXT_ADDR);
    printf("\n");

    printf("LR:       %016"PRIx64"\n", regs->x30);
    printf("ELR_EL1:  %016"PRIx64"\n", regs->elr_el1);

    printf("CPSR:     %08"PRIx32"\n", regs->cpsr);
    printf("SPSR_EL1: %08"PRIx32"\n", regs->spsr_el1);

    printf("SP_EL0:   %016"PRIx64"\n", regs->sp_el0);
    printf("SP_EL1:   %016"PRIx64"\n", regs->sp_el1);

    printf("\n");
    printf(" x0: %016"PRIx64"\t", regs->x0);
    printf(" x1: %016"PRIx64"\t", regs->x1);
    printf(" x2: %016"PRIx64"\n", regs->x2);

    printf(" x3: %016"PRIx64"\t", regs->x3);
    printf(" x4: %016"PRIx64"\t", regs->x4);
    printf(" x5: %016"PRIx64"\n", regs->x5);

    printf(" x6: %016"PRIx64"\t", regs->x6);
    printf(" x7: %016"PRIx64"\t", regs->x7);
    printf(" x8: %016"PRIx64"\n", regs->x8);

    printf(" x9: %016"PRIx64"\t", regs->x9);
    printf("x10: %016"PRIx64"\t", regs->x10);
    printf("x11: %016"PRIx64"\n", regs->x11);

    printf("x12: %016"PRIx64"\t", regs->x12);
    printf("x13: %016"PRIx64"\t", regs->x13);
    printf("x14: %016"PRIx64"\n", regs->x14);

    printf("x15: %016"PRIx64"\t", regs->x15);
    printf("x16: %016"PRIx64"\t", regs->x16);
    printf("x17: %016"PRIx64"\n", regs->x17);

    printf("x18: %016"PRIx64"\t", regs->x18);
    printf("x19: %016"PRIx64"\t", regs->x19);
    printf("x20: %016"PRIx64"\n", regs->x20);

    printf("x21: %016"PRIx64"\t", regs->x21);
    printf("x22: %016"PRIx64"\t", regs->x22);
    printf("x23: %016"PRIx64"\n", regs->x23);

    printf("x24: %016"PRIx64"\t", regs->x24);
    printf("x25: %016"PRIx64"\t", regs->x25);
    printf("x26: %016"PRIx64"\n", regs->x26);

    printf("x27: %016"PRIx64"\t", regs->x27);
    printf("x28: %016"PRIx64"\t", regs->x28);
    printf("x29: %016"PRIx64"\n", regs->x29);
    printf("\n");
}
#endif /* __aarch64__ */

static void print_ctx(vcpu_guest_context_any_t *ctx_any)
{
    vcpu_guest_context_t *ctx = &ctx_any->c;

#ifdef __aarch64__
    if (ctx->user_regs.cpsr & PSR_MODE_BIT)
        print_ctx_32(ctx);
    else
        print_ctx_64(ctx);
#else
    print_ctx_32(ctx);
#endif

    printf("SCTLR: %08"PRIx32"\n", ctx->sctlr);
    printf("TTBCR: %016"PRIx64"\n", ctx->ttbcr);
    printf("TTBR0: %016"PRIx64"\n", ctx->ttbr0);
    printf("TTBR1: %016"PRIx64"\n", ctx->ttbr1);
}

#endif

#ifndef NO_TRANSLATION
static void *map_page(vcpu_guest_context_any_t *ctx, int vcpu, guest_word_t virt)
{
    static unsigned long previous_mfn = 0;
    static void *mapped = NULL;

    unsigned long mfn = xc_translate_foreign_address(xenctx.xc_handle, xenctx.domid, vcpu, virt);
    unsigned long offset = virt & ~XC_PAGE_MASK;

    if (mapped && mfn == previous_mfn)
        goto out;

    if (mapped)
        munmap(mapped, XC_PAGE_SIZE);

    previous_mfn = mfn;

    mapped = xc_map_foreign_range(xenctx.xc_handle, xenctx.domid, XC_PAGE_SIZE, PROT_READ, mfn);

    if (mapped == NULL) {
        fprintf(stderr, "\nfailed to map page for "FMT_32B_WORD".\n", virt);
        return NULL;
    }

 out:
    return (void *)(mapped + offset);
}

static guest_word_t read_stack_word(guest_word_t *src, int width)
{
    guest_word_t word = 0;
    /* Little-endian only */
    memcpy(&word, src, width);
    return word;
}

static guest_word_t read_mem_word(vcpu_guest_context_any_t *ctx, int vcpu,
                                  guest_word_t virt, int width)
{
    if ( (virt & 7) == 0 )
    {
        guest_word_t *p = map_page(ctx, vcpu, virt);

        if ( p )
            return read_stack_word(p, width);
        else
            return -1;
    }
    else
    {
        guest_word_t word = 0;
        char *src, *dst;
        int i;

        /* Little-endian only */
        dst = (char *)&word;
        for (i = 0; i < width; i++)
        {
            src = map_page(ctx, vcpu, virt + i);
            if ( src )
                *dst++ = *src;
            else
            {
                guest_word_t missing = -1LL;

                /* Return all ones for missing memory */
                memcpy(dst, &missing, width - i);
                return word;
            }
        }
        return word;
    }
}

static void print_stack_word(guest_word_t word, int width)
{
    if (width == 2)
        printf(FMT_16B_WORD, word);
    else if (width == 4)
        printf(FMT_32B_WORD, word);
    else
        printf(FMT_64B_WORD, word);
}

static int print_lines(vcpu_guest_context_any_t *ctx, int vcpu, int width,
                       guest_word_t mem_addr, guest_word_t mem_limit)
{
    guest_word_t mem_start = mem_addr;
    guest_word_t word;
    guest_word_t ascii[MAX_BYTES_PER_LINE/4];
    int i;

    for (i = 1; i < xenctx.lines + 1 && mem_addr < mem_limit; i++)
    {
        int j = 0;
        int k;

        if ( xenctx.tag_stack_dump )
        {
            print_stack_word(mem_addr, width);
            printf(":");
        }
        while ( mem_addr < mem_limit &&
                mem_addr < mem_start + i * xenctx.bytes_per_line )
        {
            void *p = map_page(ctx, vcpu, mem_addr);
            if ( !p )
                return -1;
            word = read_mem_word(ctx, vcpu, mem_addr, width);
            if ( xenctx.decode_as_ascii )
                ascii[j++] = word;
            printf(" ");
            print_stack_word(word, width);
            mem_addr += width;
        }
        if ( xenctx.decode_as_ascii )
        {
            /*
             * Line up ascii output if less than bytes_per_line
             * were printed.
             */
            for (k = j; k < xenctx.bytes_per_line / width; k++)
                printf(" %*s", width * 2, "");
            printf("  ");
            for (k = 0; k < j; k++)
            {
                int l;
                unsigned char *bytep = (unsigned char *)&ascii[k];

                for (l = 0; l < width; l++)
                {
                    if (isprint(*bytep))
                        printf("%c", *bytep);
                    else
                        printf(".");
                    bytep++;
                }
            }
        }
        printf("\n");
    }
    printf("\n");
    return 0;
}

static void print_mem(vcpu_guest_context_any_t *ctx, int vcpu, int width,
                          guest_word_t mem_addr)
{
    printf("Memory (address ");
    print_stack_word(mem_addr, width);
    printf("):\n");
    print_lines(ctx, vcpu, width, mem_addr,
                mem_addr + xenctx.lines * xenctx.bytes_per_line);
}

static int print_code(vcpu_guest_context_any_t *ctx, int vcpu)
{
    guest_word_t instr;
    int i;

    instr = instr_pointer(ctx);
    printf("Code (instr addr %08llx)\n", instr);
    instr -= 21;
    for(i=0; i<32; i++) {
        unsigned char *c = map_page(ctx, vcpu, instr+i);
        if (!c)
            return -1;
        if (instr+i == instr_pointer(ctx))
            printf("<%02x> ", *c);
        else
            printf("%02x ", *c);
    }
    printf("\n\n\n");
    return 0;
}

static void print_stack_addr(guest_word_t addr, int width)
{
    print_stack_word(addr, width);
    printf(": ");
}

static int print_stack(vcpu_guest_context_any_t *ctx, int vcpu, int width,
                       guest_word_t stk_addr_start)
{
    guest_word_t stack = stk_addr_start;
    guest_word_t stack_limit;
    guest_word_t frame;
    guest_word_t word;
    guest_word_t *p;

    if ( width )
        xenctx.bytes_per_line =
            ((xenctx.bytes_per_line + width - 1) / width) * width;
    stack_limit = ((stack_pointer(ctx) + XC_PAGE_SIZE)
                   & ~((guest_word_t) XC_PAGE_SIZE - 1))
                   + (xenctx.nr_stack_pages - 1) * XC_PAGE_SIZE;
    if ( xenctx.lines )
    {
        printf("Stack:\n");
        if ( print_lines(ctx, vcpu, width, stack, stack_limit) )
            return -1;
    }

    if ( !guest_protected_mode )
        return 0;

    if(xenctx.stack_trace)
        printf("Stack Trace:\n");
    else
        printf("Call Trace:\n");
    if ( !xenctx.do_stack )
    {
        printf("%*s  %c [<", width*2, "", xenctx.stack_trace ? '*' : ' ');
        print_stack_word(instr_pointer(ctx), width);
        printf(">]");

        print_symbol(instr_pointer(ctx), KERNEL_TEXT_ADDR);
        printf(" <--\n");
    }
    if (xenctx.frame_ptrs) {
        stack = stack_pointer(ctx);
        frame = frame_pointer(ctx);
        while(frame && stack < stack_limit) {
            if (xenctx.stack_trace) {
                while (stack < frame) {
                    p = map_page(ctx, vcpu, stack);
                    if (!p)
                        return -1;
                    print_stack_addr(stack, width);
                    printf("|   ");
                    print_stack_word(read_stack_word(p, width), width);
                    printf("\n");
                    stack += width;
                }
            } else {
                stack = frame;
            }

            p = map_page(ctx, vcpu, stack);
            if (!p)
                return -1;
            frame = read_stack_word(p, width);
            if (xenctx.stack_trace) {
                print_stack_addr(stack, width);
                printf("|-- ");
                print_stack_word(read_stack_word(p, width), width);
                printf("\n");
            }
            stack += width;

            if (frame) {
                p = map_page(ctx, vcpu, stack);
                if (!p)
                    return -1;
                word = read_stack_word(p, width);
                print_stack_addr(stack, width);
                printf("%c [<", xenctx.stack_trace ? '|' : ' ');
                print_stack_word(word, width);
                printf(">]");
                print_symbol(word, KERNEL_TEXT_ADDR);
                printf("\n");
                stack += width;
            }
        }
    } else {
        stack = stk_addr_start;
        while(stack < stack_limit) {
            p = map_page(ctx, vcpu, stack);
            if (!p)
                return -1;
            word = read_mem_word(ctx, vcpu, stack, width);
            if ( kernel_addr(word) >= KERNEL_TEXT_ADDR )
            {
                print_stack_addr(stack, width);
                printf("  [<");
                print_stack_word(word, width);
                printf(">]");
                print_symbol(word, KERNEL_TEXT_ADDR);
                printf("\n");
            } else if (xenctx.stack_trace) {
                print_stack_addr(stack, width);
                printf("    ");
                print_stack_word(word, width);
                printf("\n");
            }
            stack += width;
        }
    }
    return 0;
}
#endif

static void dump_ctx(int vcpu)
{
    vcpu_guest_context_any_t ctx;

    if (xc_vcpu_getcontext(xenctx.xc_handle, xenctx.domid, vcpu, &ctx) < 0) {
        perror("xc_vcpu_getcontext");
        return;
    }

#if defined(__i386__) || defined(__x86_64__)
    {
        if (xenctx.dominfo.hvm) {
            struct hvm_hw_cpu cpuctx;
            xen_capabilities_info_t xen_caps = "";
            if (xc_domain_hvm_getcontext_partial(
                    xenctx.xc_handle, xenctx.domid, HVM_SAVE_CODE(CPU),
                    vcpu, &cpuctx, sizeof cpuctx) != 0) {
                perror("xc_domain_hvm_getcontext_partial");
                return;
            }
            guest_protected_mode = (cpuctx.cr0 & CR0_PE);
            guest_word_size = (cpuctx.msr_efer & 0x400) ? 8 :
                guest_protected_mode ? 4 : 2;
            /* HVM guest context records are always host-sized */
            if (xc_version(xenctx.xc_handle, XENVER_capabilities, &xen_caps) != 0) {
                perror("xc_version");
                return;
            }
            ctxt_word_size = (strstr(xen_caps, "xen-3.0-x86_64")) ? 8 : 4;
        } else {
            unsigned int gw;
            if ( !xc_domain_get_guest_width(xenctx.xc_handle, xenctx.domid, &gw) )
                ctxt_word_size = guest_word_size = gw;
        }
    }
#endif

#ifndef NO_TRANSLATION
    if ( xenctx.do_memory )
    {
        print_mem(&ctx, vcpu, guest_word_size, xenctx.mem_addr);
        return;
    }
    if ( xenctx.do_stack )
    {
        print_stack(&ctx, vcpu, guest_word_size, xenctx.stk_addr);
        return;
    }
#endif
    print_ctx(&ctx);
#ifndef NO_TRANSLATION
    if (print_code(&ctx, vcpu))
        return;
    if ( !guest_protected_mode ||
         kernel_addr(instr_pointer(&ctx)) >= KERNEL_TEXT_ADDR )
        if ( print_stack(&ctx, vcpu, guest_word_size,
                         stack_pointer(&ctx)) )
            return;
#endif
}

static void dump_all_vcpus(void)
{
    xc_vcpuinfo_t vinfo;
    int vcpu;
    for (vcpu = 0; vcpu <= xenctx.dominfo.max_vcpu_id; vcpu++)
    {
        if ( xc_vcpu_getinfo(xenctx.xc_handle, xenctx.domid, vcpu, &vinfo) )
            continue;
        if ( vinfo.online )
        {
            printf("vcpu%d:\n", vcpu);
            dump_ctx(vcpu);
            printf("\n");
        }
        else
            printf("vcpu%d offline\n\n", vcpu);
    }
}

static void usage(void)
{
    printf("usage:\n\n");

    printf("  xenctx [options] <DOMAIN> [VCPU]\n\n");

    printf("options:\n");
    printf("  -f, --frame-pointers\n");
    printf("                     assume the kernel was compiled with\n");
    printf("                     frame pointers.\n");
    printf("  -s SYMTAB, --symbol-table=SYMTAB\n");
    printf("                     read symbol table from SYMTAB.\n");
    printf("  -S, --stack-trace  print a complete stack trace.\n");
    printf("  -k KADDR, --kernel-start=KADDR\n");
    printf("                     set user/kernel split. (default 0x"FMT_32B_WORD")\n",
        kernel_start);
    printf("  -a, --all          display more registers\n");
    printf("  -C, --all-vcpus    print info for all vcpus\n");
    printf("  -n PAGES, --display-stack-pages=PAGES\n");
    printf("                     Display N pages from the stack pointer. (default %d)\n",
           DEFAULT_NR_STACK_PAGES);
    printf("                     Changes stack limit.  Note: use with caution (easy\n");
    printf("                     to get garbage).\n");
    printf("  -b <bytes>, --bytes-per-line <bytes>\n");
    printf("                     change the number of bytes per line output for Stack.\n");
    printf("                     (default %d) Note: rounded to native size (4 or 8 bytes).\n",
           DEFAULT_BYTES_PER_LINE);
    printf("  -l <lines>, --lines <lines>\n");
    printf("                     change the number of lines output for Stack. (default %d)\n",
           DEFAULT_LINES);
    printf("                     Can be specified as MAX.  Note: Fewer lines will be output\n");
    printf("                     if stack limit reached.\n");
    printf("  -D, --decode-as-ascii\n");
    printf("                     add a decode of Stack dump as ascii.\n");
    printf("  -t, --tag-stack-dump\n");
    printf("                     add address on each line of Stack dump.\n");
#ifndef NO_TRANSLATION
    printf("  -m maddr, --memory=maddr\n");
    printf("                     dump memory at maddr.\n");
    printf("  -d daddr, --dump-as-stack=daddr\n");
    printf("                     dump memory as a stack at daddr.\n");
#endif
}

int main(int argc, char **argv)
{
    int ch;
    int ret;
    const char *prog = argv[0];
    static const char *sopts = "fs:hak:SCn:b:l:Dt"
#ifndef NO_TRANSLATION
        "m:d:"
#endif
        ;
    static const struct option lopts[] = {
        {"stack-trace", 0, NULL, 'S'},
        {"symbol-table", 1, NULL, 's'},
        {"frame-pointers", 0, NULL, 'f'},
        {"kernel-start", 1, NULL, 'k'},
        {"display-stack-pages", 0, NULL, 'n'},
        {"decode-as-ascii", 0, NULL, 'D'},
        {"tag-stack-dump", 0, NULL, 't'},
#ifndef NO_TRANSLATION
        {"memory", 1, NULL, 'm'},
        {"dump-as-stack", 1, NULL, 'd'},
#endif
        {"bytes-per-line", 1, NULL, 'b'},
        {"lines", 1, NULL, 'l'},
        {"all", 0, NULL, 'a'},
        {"all-vcpus", 0, NULL, 'C'},
        {"help", 0, NULL, 'h'},
        {0, 0, 0, 0}
    };
    const char *symbol_table = NULL;

    int vcpu = 0;
    int do_default = 1;

    xenctx.bytes_per_line = DEFAULT_BYTES_PER_LINE;
    xenctx.lines = DEFAULT_LINES;
    xenctx.nr_stack_pages = DEFAULT_NR_STACK_PAGES;

    while ((ch = getopt_long(argc, argv, sopts, lopts, NULL)) != -1) {
        switch(ch) {
        case 'f':
            xenctx.frame_ptrs = 1;
            break;
        case 's':
            symbol_table = optarg;
            break;
        case 'S':
            xenctx.stack_trace = 1;
            break;
        case 'a':
            xenctx.disp_all = 1;
            break;
        case 'n':
            xenctx.nr_stack_pages = strtol(optarg, NULL, 0);
            if ( xenctx.nr_stack_pages < 1)
            {
                fprintf(stderr,
                        "%s: Unsupported value(%d) for --display-stack-pages '%s'. Needs to be >= 1\n",
                        prog, xenctx.nr_stack_pages, optarg);
                exit(-1);
            }
            break;
        case 'D':
            xenctx.decode_as_ascii = 1;
            break;
        case 't':
            xenctx.tag_stack_dump = 1;
            break;
        case 'b':
            xenctx.bytes_per_line = strtol(optarg, NULL, 0);
            if ( xenctx.bytes_per_line < 4 ||
                 xenctx.bytes_per_line > MAX_BYTES_PER_LINE )
            {
                fprintf(stderr,
                        "%s: Unsupported value for --bytes-per-line '%s'. Needs to be 4 <= %d <= %d\n",
                        prog, optarg, xenctx.bytes_per_line,
                        MAX_BYTES_PER_LINE);
                exit(-1);
            }
            break;
        case 'l':
            if ( !strcmp(optarg, "all") || !strcmp(optarg, "ALL") ||
                 !strcmp(optarg, "max") || !strcmp(optarg, "MAX") )
                xenctx.lines = INT_MAX - 1;
            else
                xenctx.lines = strtol(optarg, NULL, 0);
            if ( xenctx.lines < 0 || xenctx.lines == INT_MAX)
            {
                fprintf(stderr,
                        "%s: Unsupported value(%d) for --lines '%s'. Needs to be >= 0, < %d\n",
                        prog, xenctx.lines, optarg, INT_MAX);
                exit(-1);
            }
            break;
        case 'C':
            xenctx.all_vcpus = 1;
            do_default = 0;
            break;
        case 'k':
            kernel_start = strtoull(optarg, NULL, 0);
            xenctx.kernel_start_set = 1;
            break;
#ifndef NO_TRANSLATION
        case 'm':
            xenctx.mem_addr = strtoull(optarg, NULL, 0);
            xenctx.do_memory = 1;
            do_default = 0;
            break;
        case 'd':
            xenctx.stk_addr = strtoull(optarg, NULL, 0);
            xenctx.do_stack = 1;
            do_default = 0;
            break;
#endif
        case 'h':
            usage();
            exit(-1);
        case '?':
            fprintf(stderr, "%s --help for more options\n", prog);
            exit(-1);
        }
    }

    argv += optind; argc -= optind;

    if (argc < 1 || argc > 2) {
        printf("usage: xenctx [options] <domid> <optional vcpu>\n");
        exit(-1);
    }

#ifndef NO_TRANSLATION
    if ( xenctx.frame_ptrs && xenctx.do_stack )
    {
        fprintf(stderr,
                "%s: both --frame-pointers and --dump-as-stack is not supported\n",
                prog);
        exit(-1);
    }
#endif

    xenctx.domid = atoi(argv[0]);
    if (xenctx.domid==0) {
            fprintf(stderr, "cannot trace dom0\n");
            exit(-1);
    }

    if ( argc == 2 )
    {
        if ( xenctx.all_vcpus )
        {
            fprintf(stderr,
                    "%s: both --all-vcpus and [VCPU] is not supported\n",
                    prog);
            exit(-1);
        }
        vcpu = atoi(argv[1]);
    }

    if (symbol_table)
        read_symbol_table(symbol_table);

    xenctx.xc_handle = xc_interface_open(0,0,0); /* for accessing control interface */
    if (xenctx.xc_handle == NULL) {
        perror("xc_interface_open");
        exit(-1);
    }

    ret = xc_domain_getinfo(xenctx.xc_handle, xenctx.domid, 1, &xenctx.dominfo);
    if (ret < 0) {
        perror("xc_domain_getinfo");
        exit(-1);
    }

    ret = xc_domain_pause(xenctx.xc_handle, xenctx.domid);
    if (ret < 0) {
        perror("xc_domain_pause");
        exit(-1);
    }

#ifndef NO_TRANSLATION
    if ( xenctx.do_memory )
    {
        dump_ctx(vcpu);
        if ( xenctx.do_stack || xenctx.all_vcpus )
            printf("\n");
    }
    xenctx.do_memory = 0;
    if ( xenctx.do_stack )
    {
        dump_ctx(vcpu);
        if ( xenctx.all_vcpus )
            printf("\n");
    }
    xenctx.do_stack = 0;
#endif
    if (xenctx.all_vcpus)
        dump_all_vcpus();
    if ( do_default )
        dump_ctx(vcpu);

    ret = xc_domain_unpause(xenctx.xc_handle, xenctx.domid);
    if (ret < 0) {
        perror("xc_domain_unpause");
        exit(-1);
    }

    ret = xc_interface_close(xenctx.xc_handle);
    if (ret < 0) {
        perror("xc_interface_close");
        exit(-1);
    }

    return 0;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
