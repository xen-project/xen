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
#include <string.h>
#include <inttypes.h>
#include <getopt.h>

#include "xenctrl.h"
#include <xen/foreign/x86_32.h>
#include <xen/foreign/x86_64.h>
#include <xen/hvm/save.h>

int xc_handle = 0;
int domid = 0;
int frame_ptrs = 0;
int stack_trace = 0;
int disp_all = 0;

#if defined (__i386__) || defined (__x86_64__)
typedef unsigned long long guest_word_t;
#define FMT_32B_WORD "%08llx"
#define FMT_64B_WORD "%016llx"
/* Word-length of the guest's own data structures */
int guest_word_size = sizeof (unsigned long);
/* Word-length of the context record we get from xen */
int ctxt_word_size = sizeof (unsigned long);
int guest_protected_mode = 1;
#elif defined (__ia64__)
/* On ia64, we can't translate virtual address to physical address.  */
#define NO_TRANSLATION
typedef size_t guest_word_t;

/* Which registers should be displayed.  */
int disp_cr_regs;
int disp_ar_regs;
int disp_br_regs;
int disp_bank_regs;
int disp_tlb;
#endif

struct symbol {
    guest_word_t address;
    char type;
    char *name;
    struct symbol *next;
} *symbol_table = NULL;

guest_word_t kernel_stext, kernel_etext, kernel_sinittext, kernel_einittext, kernel_hypercallpage;

#if defined (__i386__) 
unsigned long long kernel_start = 0xc0000000;
#else
unsigned long long kernel_start = 0xffffffff80000000UL;
#endif

static int is_kernel_text(guest_word_t addr)
{
    if (symbol_table == NULL)
        return (addr > kernel_start);

    if (addr >= kernel_stext &&
        addr <= kernel_etext)
        return 1;
    if (addr >= kernel_hypercallpage &&
        addr <= kernel_hypercallpage + 4096)
        return 1;
    if (addr >= kernel_sinittext &&
        addr <= kernel_einittext)
        return 1;
    return 0;
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
        && prev->address < symbol->address
        && (!prev->next || prev->next->address > symbol->address)) {
        s = prev;
    } else {
        /* ... otherwise do crappy/slow search for the correct place */
        while(s && s->next && s->next->address < symbol->address)
            s = s->next;
    }

    symbol->next = s->next;
    s->next = symbol;
    prev = symbol;
}

static struct symbol *lookup_symbol(guest_word_t address)
{
    struct symbol *s = symbol_table;

    while(s && s->next && s->next->address < address)
        s = s->next;

    if (s && s->address < address)
        return s;

    return NULL;
}

static void print_symbol(guest_word_t addr)
{
    struct symbol *s;

    if (!is_kernel_text(addr))
        return;

    s = lookup_symbol(addr);

    if (s==NULL)
        return;

    if (addr==s->address)
        printf("%s ", s->name);
    else
        printf("%s+%#x ", s->name, (unsigned int)(addr - s->address));
}

static void read_symbol_table(const char *symtab)
{
    char line[256];
    char *p;
    struct symbol *symbol;
    FILE *f;

    f = fopen(symtab, "r");
    if(f == NULL) {
        fprintf(stderr, "failed to open symbol table %s\n", symtab);
        exit(-1);
    }

    while(!feof(f)) {
        if(fgets(line,256,f)==NULL)
            break;

        symbol = malloc(sizeof(*symbol));

        /* need more checks for syntax here... */
        symbol->address = strtoull(line, &p, 16);
        p++;
        symbol->type = *p++;
        p++;

        /* in the future we should handle the module name
         * being appended here, this would allow us to use
         * /proc/kallsyms as our symbol table
         */
        if (p[strlen(p)-1] == '\n')
            p[strlen(p)-1] = '\0';
        symbol->name = strdup(p);

        insert_symbol(symbol);

        if (strcmp(symbol->name, "_stext") == 0)
            kernel_stext = symbol->address;
        else if (strcmp(symbol->name, "_etext") == 0)
            kernel_etext = symbol->address;
        else if (strcmp(symbol->name, "_sinittext") == 0)
            kernel_sinittext = symbol->address;
        else if (strcmp(symbol->name, "_einittext") == 0)
            kernel_einittext = symbol->address;
        else if (strcmp(symbol->name, "hypercall_page") == 0)
            kernel_hypercallpage = symbol->address;
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

static void print_special(void *regs, const char *name, unsigned int mask, int width)
{
    unsigned int i;

    printf("\n");
    for (i = 0; mask; mask >>= 1, ++i)
        if (mask & 1) {
            if (width == 4)
                printf("%s%u: %08"PRIx32"\n", name, i, ((uint32_t *) regs)[i]);
            else
                printf("%s%u: %08"PRIx64"\n", name, i, ((uint64_t *) regs)[i]);
        }
}

static void print_ctx_32(vcpu_guest_context_x86_32_t *ctx)
{
    struct cpu_user_regs_x86_32 *regs = &ctx->user_regs;

    printf("cs:eip: %04x:%08x ", regs->cs, regs->eip);
    print_symbol(regs->eip);
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

    if (disp_all) {
        print_special(ctx->ctrlreg, "cr", 0x1d, 4);
        print_special(ctx->debugreg, "dr", 0xcf, 4);
    }
}

static void print_ctx_32on64(vcpu_guest_context_x86_64_t *ctx)
{
    struct cpu_user_regs_x86_64 *regs = &ctx->user_regs;

    printf("cs:eip: %04x:%08x ", regs->cs, (uint32_t)regs->eip);
    print_symbol((uint32_t)regs->eip);
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

    if (disp_all) {
        print_special(ctx->ctrlreg, "cr", 0x1d, 4);
        print_special(ctx->debugreg, "dr", 0xcf, 4);
    }
}

static void print_ctx_64(vcpu_guest_context_x86_64_t *ctx)
{
    struct cpu_user_regs_x86_64 *regs = &ctx->user_regs;

    printf("rip: %016"PRIx64" ", regs->rip);
    print_symbol(regs->rip);
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

    printf(" fs: %04x @ %016"PRIx64"\n", regs->fs, ctx->fs_base);
    printf(" gs: %04x @ %016"PRIx64"/%016"PRIx64"\n", regs->gs,
           ctx->gs_base_kernel, ctx->gs_base_user);

    if (disp_all) {
        print_special(ctx->ctrlreg, "cr", 0x1d, 8);
        print_special(ctx->debugreg, "dr", 0xcf, 8);
    }
}

static void print_ctx(vcpu_guest_context_any_t *ctx)
{
    if (ctxt_word_size == 4) 
        print_ctx_32(&ctx->x32);
    else if (guest_word_size == 4)
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
        r = ctx->x64.user_regs.rip;

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
        r = ctx->x64.user_regs.rsp;
    
    return r;
}

static guest_word_t frame_pointer(vcpu_guest_context_any_t *ctx)
{
    if (ctxt_word_size == 4) 
        return ctx->x32.user_regs.ebp;
    else 
        return ctx->x64.user_regs.rbp;
}

#elif defined(__ia64__)

#define PTE_ED_SHIFT              52
#define PTE_ED_MASK                1
#define PTE_PPN_SHIFT             12
#define PTE_PPN_MASK    0x3fffffffff
#define PTE_AR_SHIFT               9
#define PTE_AR_MASK                7
#define PTE_PL_SHIFT               7
#define PTE_PL_MASK                3
#define PTE_D_SHIFT                6
#define PTE_D_MASK                 1
#define PTE_A_SHIFT                5
#define PTE_A_MASK                 1
#define PTE_MA_SHIFT               2
#define PTE_MA_MASK                7
#define PTE_P_SHIFT                0
#define PTE_P_MASK                 1
#define ITIR_KEY_SHIFT             8
#define ITIR_KEY_MASK       0xffffff
#define ITIR_PS_SHIFT              2
#define ITIR_PS_MASK            0x3f
#define ITIR_PS_MIN               12
#define ITIR_PS_MAX               28
#define RR_RID_SHIFT               8
#define RR_RID_MASK         0xffffff
#define PSR_BN           (1UL << 44)
#define CFM_SOF_MASK            0x3f

static void print_tr(int i, const struct ia64_tr_entry *tr)
{
    int ps_val, ma_val;
    unsigned long pa;

    static const char ps[][5] = {"  4K", "  8K", " 16K", "    ",
                                 " 64K", "    ", "256K", "    ",
                                 "  1M", "    ", "  4M", "    ",
                                 " 16M", "    ", " 64M", "    ",
                                 "256M"};
    static const char ma[][4] = {"WB ", "   ", "   ", "   ",
                                 "UC ", "UCE", "WC ", "Nat"};

    ps_val =  tr->itir >> ITIR_PS_SHIFT & ITIR_PS_MASK;
    ma_val =  tr->pte  >> PTE_MA_SHIFT  & PTE_MA_MASK;
    pa     = (tr->pte  >> PTE_PPN_SHIFT & PTE_PPN_MASK) << PTE_PPN_SHIFT;
    pa     = (pa >> ps_val) << ps_val;
    printf(" [%d]  %ld %06lx %016lx %013lx %02x %s %ld  %ld  %ld  %ld "
           "%ld %d %s %06lx\n", i,
           tr->pte  >> PTE_P_SHIFT    & PTE_P_MASK,
           tr->rid  >> RR_RID_SHIFT   & RR_RID_MASK,
           tr->vadr, pa, ps_val,
           ((ps_val >= ITIR_PS_MIN && ps_val <= ITIR_PS_MAX) ?
            ps[ps_val - ITIR_PS_MIN] : "    "),
           tr->pte  >> PTE_ED_SHIFT   & PTE_ED_MASK,
           tr->pte  >> PTE_PL_SHIFT   & PTE_PL_MASK,
           tr->pte  >> PTE_AR_SHIFT   & PTE_AR_MASK,
           tr->pte  >> PTE_A_SHIFT    & PTE_A_MASK,
           tr->pte  >> PTE_D_SHIFT    & PTE_D_MASK,
           ma_val, ma[ma_val],
           tr->itir >> ITIR_KEY_SHIFT & ITIR_KEY_MASK);
}

void print_ctx(vcpu_guest_context_any_t *ctx)
{
    struct vcpu_guest_context_regs *regs = &ctx->c.regs;
    struct vcpu_tr_regs *tr = &ctx->c.regs.tr;
    int i;
    unsigned int rbs_size, cfm_sof;

    printf(" ip:  %016lx  ", regs->ip);
    print_symbol(regs->ip);
    printf("\n");
    printf(" psr:  %016lx  ", regs->psr);
    printf(" cfm:  %016lx  ", regs->cfm);
    printf(" pr:   %016lx\n", regs->pr);

    if (disp_br_regs) {
        printf(" b0:   %016lx  ", regs->b[0]);
        printf(" b1:   %016lx  ", regs->b[1]);
        printf(" b2:   %016lx\n", regs->b[2]);
        printf(" b3:   %016lx  ", regs->b[3]);
        printf(" b4:   %016lx  ", regs->b[4]);
        printf(" b5:   %016lx\n", regs->b[5]);
        printf(" b6:   %016lx  ", regs->b[6]);
        printf(" b7:   %016lx\n", regs->b[7]);
    } else {
        printf(" b0:   %016lx\n", regs->b[0]);
    }

    if (disp_cr_regs) {
        printf ("\n"
                "                                CR:\n");
        printf(" dcr:  %016lx  ", regs->cr.dcr);
        printf(" itm:  %016lx  ", regs->cr.itm);
        printf(" iva:  %016lx\n", regs->cr.iva);
        printf(" pta:  %016lx  ", regs->cr.pta);
        printf(" ipsr: %016lx  ", regs->cr.ipsr);
        printf(" isr:  %016lx\n", regs->cr.isr);
        printf(" iip:  %016lx  ", regs->cr.iip);
        printf(" ifa:  %016lx  ", regs->cr.ifa);
        printf(" itir: %016lx\n", regs->cr.itir);
        printf(" iipa: %016lx  ", regs->cr.iipa);
        printf(" ifs:  %016lx  ", regs->cr.ifs);
        printf(" iim:  %016lx\n", regs->cr.iim);
        printf(" iha:  %016lx  ", regs->cr.iha);
        printf(" lid:  %016lx  ", regs->cr.lid);
        printf(" ivr:  %016lx\n", regs->cr.ivr);
        printf(" tpr:  %016lx  ", regs->cr.tpr);
        printf(" eoi:  %016lx  ", regs->cr.eoi);
        printf(" irr0: %016lx\n", regs->cr.irr[0]);
        printf(" irr1: %016lx  ", regs->cr.irr[1]);
        printf(" irr2: %016lx  ", regs->cr.irr[2]);
        printf(" irr3: %016lx\n", regs->cr.irr[3]);
        printf(" itv:  %016lx  ", regs->cr.itv);
        printf(" pmv:  %016lx  ", regs->cr.pmv);
        printf(" cmcv: %016lx\n", regs->cr.cmcv);
        printf(" lrr0: %016lx  ", regs->cr.lrr0);
        printf(" lrr1: %016lx  ", regs->cr.lrr1);
        printf(" ev_cb:%016lx\n", ctx->c.event_callback_ip);

    }
    if (disp_ar_regs) {
        printf ("\n"
                "                                AR:\n");
        printf(" kr0:  %016lx  ", regs->ar.kr[0]);
        printf(" kr1:  %016lx  ", regs->ar.kr[1]);
        printf(" kr2:  %016lx\n", regs->ar.kr[2]);
        printf(" kr3:  %016lx  ", regs->ar.kr[3]);
        printf(" kr4:  %016lx  ", regs->ar.kr[4]);
        printf(" kr5:  %016lx\n", regs->ar.kr[5]);
        printf(" kr6:  %016lx  ", regs->ar.kr[6]);
        printf(" kr7:  %016lx  ", regs->ar.kr[7]);
        printf(" rsc:  %016lx\n", regs->ar.rsc);
        printf(" bsp:  %016lx  ", regs->ar.bsp);
        printf(" bsps: %016lx  ", regs->ar.bspstore);
        printf(" rnat: %016lx\n", regs->ar.rnat);
        printf(" csd:  %016lx  ", regs->ar.csd);
        printf(" ccv:  %016lx  ", regs->ar.ccv);
        printf(" unat: %016lx\n", regs->ar.unat);
        printf(" fpsr: %016lx  ", regs->ar.fpsr);
        printf(" itc:  %016lx\n", regs->ar.itc);
        printf(" pfs:  %016lx  ", regs->ar.pfs);
        printf(" lc:   %016lx  ", regs->ar.lc);
        printf(" ec:   %016lx\n", regs->ar.ec);
    }
    printf("\n");
    printf(" r1:  %016lx  ", regs->r[1]);
    printf(" r2:  %016lx  ", regs->r[2]);
    printf(" r3:  %016lx\n", regs->r[3]);
    printf(" r4:  %016lx  ", regs->r[4]);
    printf(" r5:  %016lx  ", regs->r[5]);
    printf(" r6:  %016lx\n", regs->r[6]);
    printf(" r7:  %016lx  ", regs->r[7]);
    printf(" r8:  %016lx  ", regs->r[8]);
    printf(" r9:  %016lx\n", regs->r[9]);
    printf(" r10: %016lx  ", regs->r[10]);
    printf(" r11: %016lx  ", regs->r[11]);
    printf(" sp:  %016lx\n", regs->r[12]);
    printf(" tp:  %016lx  ", regs->r[13]);
    printf(" r14: %016lx  ", regs->r[14]);
    printf(" r15: %016lx\n", regs->r[15]);
    if (disp_bank_regs) {
        printf("      Bank %d (current)                         Bank %d\n",
               (regs->psr & PSR_BN) ? 1 : 0, (regs->psr & PSR_BN) ? 0 : 1);
        printf ("16:%016lx ", regs->r[16]);
        printf ("17:%016lx ", regs->r[17]);
        printf ("16:%016lx ", regs->bank[0]);
        printf ("17:%016lx\n", regs->bank[1]);
        printf ("18:%016lx ", regs->r[18]);
        printf ("19:%016lx ", regs->r[19]);
        printf ("18:%016lx ", regs->bank[2]);
        printf ("19:%016lx\n", regs->bank[3]);
        printf ("20:%016lx ", regs->r[20]);
        printf ("21:%016lx ", regs->r[21]);
        printf ("20:%016lx ", regs->bank[4]);
        printf ("21:%016lx\n", regs->bank[5]);
        printf ("22:%016lx ", regs->r[22]);
        printf ("23:%016lx ", regs->r[23]);
        printf ("22:%016lx ", regs->bank[6]);
        printf ("23:%016lx\n", regs->bank[7]);
        printf ("24:%016lx ", regs->r[24]);
        printf ("25:%016lx ", regs->r[25]);
        printf ("24:%016lx ", regs->bank[8]);
        printf ("25:%016lx\n", regs->bank[9]);
        printf ("26:%016lx ", regs->r[26]);
        printf ("27:%016lx ", regs->r[27]);
        printf ("26:%016lx ", regs->bank[10]);
        printf ("27:%016lx\n", regs->bank[11]);
        printf ("28:%016lx ", regs->r[28]);
        printf ("29:%016lx ", regs->r[29]);
        printf ("28:%016lx ", regs->bank[12]);
        printf ("29:%016lx\n", regs->bank[13]);
        printf ("30:%016lx ", regs->r[30]);
        printf ("31:%016lx ", regs->r[31]);
        printf ("30:%016lx ", regs->bank[14]);
        printf ("31:%016lx\n", regs->bank[15]);
    } else {
        printf(" r16: %016lx  ", regs->r[16]);
        printf(" r17: %016lx  ", regs->r[17]);
        printf(" r18: %016lx\n", regs->r[18]);
        printf(" r19: %016lx  ", regs->r[19]);
        printf(" r20: %016lx  ", regs->r[20]);
        printf(" r21: %016lx\n", regs->r[21]);
        printf(" r22: %016lx  ", regs->r[22]);
        printf(" r23: %016lx  ", regs->r[23]);
        printf(" r24: %016lx\n", regs->r[24]);
        printf(" r25: %016lx  ", regs->r[25]);
        printf(" r26: %016lx  ", regs->r[26]);
        printf(" r27: %016lx\n", regs->r[27]);
        printf(" r28: %016lx  ", regs->r[28]);
        printf(" r29: %016lx  ", regs->r[29]);
        printf(" r30: %016lx\n", regs->r[30]);
        printf(" r31: %016lx\n", regs->r[31]);
    }

    printf("\n");
    rbs_size = (regs->ar.bsp - regs->ar.bspstore) / 8;
    cfm_sof = (regs->cfm & CFM_SOF_MASK);
    for (i = 0; i < cfm_sof; i++) {
        int off = cfm_sof - i;
        unsigned int rbs_off =
            (((62 - ((rbs_size + regs->rbs_voff) % 63) + off)) / 63) + off;
        if (rbs_off > rbs_size)
            break;
        printf(" r%02d: %016lx%s", 32 + i,
               regs->rbs[rbs_size - rbs_off],
               (i % 3) != 2 ? "  " : "\n");
    }
    if ((i % 3) != 0)
        printf ("\n");

    if (disp_tlb) {
        printf("\n itr: P rid    va               pa            ps      ed pl "
               "ar a d ma    key\n");
        for (i = 0; i < 8; i++)
            print_tr(i, &tr->itrs[i]);
        printf("\n dtr: P rid    va               pa            ps      ed pl "
               "ar a d ma    key\n");
        for (i = 0; i < 8; i++)
            print_tr(i, &tr->dtrs[i]);
    }
}
#endif

#ifndef NO_TRANSLATION
static void *map_page(vcpu_guest_context_any_t *ctx, int vcpu, guest_word_t virt)
{
    static unsigned long previous_mfn = 0;
    static void *mapped = NULL;

    unsigned long mfn = xc_translate_foreign_address(xc_handle, domid, vcpu, virt);
    unsigned long offset = virt & ~XC_PAGE_MASK;

    if (mapped && mfn == previous_mfn)
        goto out;

    if (mapped)
        munmap(mapped, XC_PAGE_SIZE);

    previous_mfn = mfn;

    mapped = xc_map_foreign_range(xc_handle, domid, XC_PAGE_SIZE, PROT_READ, mfn);

    if (mapped == NULL) {
        fprintf(stderr, "failed to map page.\n");
        exit(-1);
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

static void print_stack_word(guest_word_t word, int width)
{
    if (width == 4)
        printf(FMT_32B_WORD, word);
    else
        printf(FMT_64B_WORD, word);
}

static void print_code(vcpu_guest_context_any_t *ctx, int vcpu)
{
    guest_word_t instr;
    int i;

    instr = instr_pointer(ctx);
    printf("Code (instr addr %08llx)\n", instr);
    instr -= 21;
    for(i=0; i<32; i++) {
        unsigned char *c = map_page(ctx, vcpu, instr+i);
        if (instr+i == instr_pointer(ctx))
            printf("<%02x> ", *c);
        else
            printf("%02x ", *c);
    }
    printf("\n");

    printf("\n");
}

static void print_stack(vcpu_guest_context_any_t *ctx, int vcpu, int width)
{
    guest_word_t stack = stack_pointer(ctx);
    guest_word_t stack_limit;
    guest_word_t frame;
    guest_word_t word;
    guest_word_t *p;
    int i;

    stack_limit = ((stack_pointer(ctx) + XC_PAGE_SIZE)
                   & ~((guest_word_t) XC_PAGE_SIZE - 1)); 
    printf("\n");
    printf("Stack:\n");
    for (i=1; i<5 && stack < stack_limit; i++) {
        while(stack < stack_limit && stack < stack_pointer(ctx) + i*32) {
            p = map_page(ctx, vcpu, stack);
            word = read_stack_word(p, width);
            printf(" ");
            print_stack_word(word, width);
            stack += width;
        }
        printf("\n");
    }
    printf("\n");

    if(stack_trace)
        printf("Stack Trace:\n");
    else
        printf("Call Trace:\n");
    printf("%c [<", stack_trace ? '*' : ' ');
    print_stack_word(instr_pointer(ctx), width);
    printf(">] ");

    print_symbol(instr_pointer(ctx));
    printf(" <--\n");
    if (frame_ptrs) {
        stack = stack_pointer(ctx);
        frame = frame_pointer(ctx);
        while(frame && stack < stack_limit) {
            if (stack_trace) {
                while (stack < frame) {
                    p = map_page(ctx, vcpu, stack);
                    printf("|   ");
                    print_stack_word(read_stack_word(p, width), width);
                    printf("   \n");
                    stack += width;
                }
            } else {
                stack = frame;
            }

            p = map_page(ctx, vcpu, stack);
            frame = read_stack_word(p, width);
            if (stack_trace) {
                printf("|-- ");
                print_stack_word(read_stack_word(p, width), width);
                printf("\n");
            }
            stack += width;

            if (frame) {
                p = map_page(ctx, vcpu, stack);
                word = read_stack_word(p, width);
                printf("%c [<", stack_trace ? '|' : ' ');
                print_stack_word(word, width);
                printf(">] ");
                print_symbol(word);
                printf("\n");
                stack += width;
            }
        }
    } else {
        stack = stack_pointer(ctx);
        while(stack < stack_limit) {
            p = map_page(ctx, vcpu, stack);
            word = read_stack_word(p, width);
            if (is_kernel_text(word)) {
                printf("  [<");
                print_stack_word(word, width);
                printf(">] ");
                print_symbol(word);
                printf("\n");
            } else if (stack_trace) {
                printf("    ");
                print_stack_word(word, width);
                printf("\n");
            }
            stack += width;
        }
    }
}
#endif

static void dump_ctx(int vcpu)
{
    int ret;
    vcpu_guest_context_any_t ctx;
    xc_dominfo_t dominfo;

    xc_handle = xc_interface_open(); /* for accessing control interface */

    ret = xc_domain_getinfo(xc_handle, domid, 1, &dominfo);
    if (ret < 0) {
        perror("xc_domain_getinfo");
        exit(-1);
    }
    
    ret = xc_domain_pause(xc_handle, domid);
    if (ret < 0) {
        perror("xc_domain_pause");
        exit(-1);
    }

    ret = xc_vcpu_getcontext(xc_handle, domid, vcpu, &ctx);
    if (ret < 0) {
        if (!dominfo.paused)
            xc_domain_unpause(xc_handle, domid);
        perror("xc_vcpu_getcontext");
        exit(-1);
    }

#if defined(__i386__) || defined(__x86_64__)
    {
        if (dominfo.hvm) {
            struct hvm_hw_cpu cpuctx;
            xen_capabilities_info_t xen_caps = "";
            if (xc_domain_hvm_getcontext_partial(
                    xc_handle, domid, HVM_SAVE_CODE(CPU), 
                    vcpu, &cpuctx, sizeof cpuctx) != 0) {
                perror("xc_domain_hvm_getcontext_partial");
                exit(-1);
            }
            guest_word_size = (cpuctx.msr_efer & 0x400) ? 8 : 4;
            guest_protected_mode = (cpuctx.cr0 & CR0_PE);
            /* HVM guest context records are always host-sized */
            if (xc_version(xc_handle, XENVER_capabilities, &xen_caps) != 0) {
                perror("xc_version");
                exit(-1);
            }
            ctxt_word_size = (strstr(xen_caps, "xen-3.0-x86_64")) ? 8 : 4;
        } else {
            struct xen_domctl domctl;
            memset(&domctl, 0, sizeof domctl);
            domctl.domain = domid;
            domctl.cmd = XEN_DOMCTL_get_address_size;
            if (xc_domctl(xc_handle, &domctl) == 0)
                ctxt_word_size = guest_word_size = domctl.u.address_size.size / 8;
        }
    }
#endif

    print_ctx(&ctx);
#ifndef NO_TRANSLATION
    print_code(&ctx, vcpu);
    if (is_kernel_text(instr_pointer(&ctx)))
        print_stack(&ctx, vcpu, guest_word_size);
#endif

    if (!dominfo.paused) {
        ret = xc_domain_unpause(xc_handle, domid);
        if (ret < 0) {
            perror("xc_domain_unpause");
            exit(-1);
        }
    }

    xc_interface_close(xc_handle);
    if (ret < 0) {
        perror("xc_interface_close");
        exit(-1);
    }
}

static void usage(void)
{
    printf("usage:\n\n");

    printf("  xenctx [options] <DOMAIN> [VCPU]\n\n");

    printf("options:\n");
    printf("  -f, --frame-pointers\n");
    printf("                    assume the kernel was compiled with\n");
    printf("                    frame pointers.\n");
    printf("  -s SYMTAB, --symbol-table=SYMTAB\n");
    printf("                    read symbol table from SYMTAB.\n");
    printf("  --stack-trace     print a complete stack trace.\n");
    printf("  -k, --kernel-start\n");
    printf("                    set user/kernel split. (default 0xc0000000)\n");
#ifdef __ia64__
    printf("  -r LIST, --regs=LIST  display more registers.\n");
    printf("  -a --all          same as --regs=tlb,cr,ar,br,bk\n");
#else
    printf("  -a --all          display more registers\n");
#endif
}

int main(int argc, char **argv)
{
    int ch;
    static const char *sopts = "fs:hak:"
#ifdef __ia64__
        "r:"
#endif
        ;
    static const struct option lopts[] = {
        {"stack-trace", 0, NULL, 'S'},
        {"symbol-table", 1, NULL, 's'},
        {"frame-pointers", 0, NULL, 'f'},
        {"kernel-start", 1, NULL, 'k'},
#ifdef __ia64__
        {"regs", 1, NULL, 'r'},
#endif
        {"all", 0, NULL, 'a'},
        {"help", 0, NULL, 'h'},
        {0, 0, 0, 0}
    };
    const char *symbol_table = NULL;

    int vcpu = 0;

    while ((ch = getopt_long(argc, argv, sopts, lopts, NULL)) != -1) {
        switch(ch) {
        case 'f':
            frame_ptrs = 1;
            break;
        case 's':
            symbol_table = optarg;
            break;
        case 'S':
            stack_trace = 1;
            break;
#ifdef __ia64__
        case 'r':
            {
                char *r;

                r = strtok(optarg, ",");
                while (r) {
                    if (strcmp (r, "cr") == 0)
                        disp_cr_regs = 1;
                    else if (strcmp (r, "ar") == 0)
                        disp_ar_regs = 1;
                    else if (strcmp (r, "br") == 0)
                        disp_br_regs = 1;
                    else if (strcmp (r, "bk") == 0)
                        disp_bank_regs = 1;
                    else if (strcmp (r, "tlb") == 0)
                        disp_tlb = 1;
                    else {
                        fprintf(stderr,"unknown register set %s\n", r);
                        exit(-1);
                    }
                    r = strtok(NULL, "'");
                }
            }
            break;
        case 'a':
            disp_cr_regs = 1;
            disp_ar_regs = 1;
            disp_br_regs = 1;
            disp_bank_regs = 1;
            disp_tlb = 1;
            break;
#else
        case 'a':
            disp_all = 1;
            break;
#endif
        case 'k':
            kernel_start = strtoull(optarg, NULL, 0);
            break;
        case 'h':
            usage();
            exit(-1);
        case '?':
            fprintf(stderr, "%s --help for more options\n", argv[0]);
            exit(-1);
        }
    }

    argv += optind; argc -= optind;

    if (argc < 1 || argc > 2) {
        printf("usage: xenctx [options] <domid> <optional vcpu>\n");
        exit(-1);
    }

    domid = atoi(argv[0]);
    if (domid==0) {
            fprintf(stderr, "cannot trace dom0\n");
            exit(-1);
    }

    if (argc == 2)
        vcpu = atoi(argv[1]);

    if (symbol_table)
        read_symbol_table(symbol_table);

    dump_ctx(vcpu);

    return 0;
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
