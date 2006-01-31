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
#include <string.h>
#include <getopt.h>

#include "xenctrl.h"

int xc_handle = 0;
int domid = 0;
int frame_ptrs = 0;
int stack_trace = 0;

#if defined (__i386__)
#define FMT_SIZE_T		"%08x"
#define STACK_POINTER(regs)	(regs->esp)
#define FRAME_POINTER(regs)	(regs->ebp)
#define INSTR_POINTER(regs)	(regs->eip)
#define STACK_ROWS		4
#define STACK_COLS		8
#elif defined (__x86_64__)
#define FMT_SIZE_T		"%016lx"
#define STACK_POINTER(regs)	(regs->rsp)
#define FRAME_POINTER(regs)	(regs->rbp)
#define INSTR_POINTER(regs)	(regs->rip)
#define STACK_ROWS		4
#define STACK_COLS		4
#endif

struct symbol {
    size_t address;
    char type;
    char *name;
    struct symbol *next;
} *symbol_table = NULL;

size_t kernel_stext, kernel_etext, kernel_sinittext, kernel_einittext, kernel_hypercallpage;

int is_kernel_text(size_t addr)
{
#if defined (__i386__)
    if (symbol_table == NULL)
        return (addr > 0xc000000);
#elif defined (__x86_64__)
    if (symbol_table == NULL)
        return (addr > 0xffffffff80000000UL);
#endif

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

void free_symbol(struct symbol *symbol)
{
    if (symbol == NULL)
        return;
    if (symbol->name)
        free(symbol->name);
    free(symbol);
}

void insert_symbol(struct symbol *symbol)
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

struct symbol *lookup_symbol(size_t address)
{
    struct symbol *s = symbol_table;

    while(s && s->next && s->next->address < address)
        s = s->next;

    if (s && s->address < address)
        return s;

    return NULL;
}

void print_symbol(size_t addr)
{
    struct symbol *s;

    if (!is_kernel_text(addr))
        return;

    s = lookup_symbol(addr);

    if (s==NULL)
        return;

    if (addr==s->address)
        printf("%s", s->name);
    else
        printf("%s+%#x", s->name, (unsigned int)(addr - s->address));
}

void read_symbol_table(const char *symtab)
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

#ifdef __i386__
void print_ctx(vcpu_guest_context_t *ctx1)
{
    struct cpu_user_regs *regs = &ctx1->user_regs;

    printf("eip: %08x ", regs->eip);
    print_symbol(regs->eip);
    printf("\n");

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

    printf("rip: %08lx ", regs->rip);
    print_symbol(regs->rip);
    printf("\n");
    printf("rsp: %08lx\n", regs->rsp);

    printf("rax: %08lx\t", regs->rax);
    printf("rbx: %08lx\t", regs->rbx);
    printf("rcx: %08lx\t", regs->rcx);
    printf("rdx: %08lx\n", regs->rdx);

    printf("rsi: %08lx\t", regs->rsi);
    printf("rdi: %08lx\t", regs->rdi);
    printf("rbp: %08lx\n", regs->rbp);

    printf(" r8: %08lx\t", regs->r8);
    printf(" r9: %08lx\t", regs->r9);
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

void *map_page(vcpu_guest_context_t *ctx, int vcpu, size_t virt)
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

void print_stack(vcpu_guest_context_t *ctx, int vcpu)
{
    struct cpu_user_regs *regs = &ctx->user_regs;
    size_t stack = STACK_POINTER(regs);
    size_t stack_limit = (STACK_POINTER(regs) & XC_PAGE_MASK) + XC_PAGE_SIZE;
    size_t frame;
    size_t instr;
    size_t *p;
    int i;

    printf("\n");
    printf("Stack:\n");
    for (i=1; i<STACK_ROWS+1 && stack < stack_limit; i++) {
        while(stack < stack_limit && stack < STACK_POINTER(regs) + i*STACK_COLS*sizeof(stack)) {
            p = map_page(ctx, vcpu, stack);
            printf(" " FMT_SIZE_T, *p);
            stack += sizeof(stack);
        }
        printf("\n");
    }
    printf("\n");

    printf("Code:\n");
    instr = INSTR_POINTER(regs) - 21;
    for(i=0; i<32; i++) {
        unsigned char *c = map_page(ctx, vcpu, instr+i);
        if (instr+i == INSTR_POINTER(regs))
            printf("<%02x> ", *c);
        else
            printf("%02x ", *c);
    }
    printf("\n");

    printf("\n");

    if(stack_trace)
        printf("Stack Trace:\n");
    else
        printf("Call Trace:\n");
    printf("%c [<" FMT_SIZE_T ">] ", stack_trace ? '*' : ' ', INSTR_POINTER(regs));

    print_symbol(INSTR_POINTER(regs));
    printf(" <--\n");
    if (frame_ptrs) {
        stack = STACK_POINTER(regs);
        frame = FRAME_POINTER(regs);
        while(frame && stack < stack_limit) {
            if (stack_trace) {
                while (stack < frame) {
                    p = map_page(ctx, vcpu, stack);
                    printf("|   " FMT_SIZE_T "   ", *p);
                    printf("\n");
                    stack += sizeof(*p);
                }
            } else {
                stack = frame;
            }

            p = map_page(ctx, vcpu, stack);
            frame = *p;
            if (stack_trace)
                printf("|-- " FMT_SIZE_T "\n", *p);
            stack += sizeof(*p);

            if (frame) {
                p = map_page(ctx, vcpu, stack);
                printf("%c [<" FMT_SIZE_T ">] ", stack_trace ? '|' : ' ', *p);
                print_symbol(*p);
                printf("\n");
                stack += sizeof(*p);
            }
        }
    } else {
        stack = STACK_POINTER(regs);
        while(stack < stack_limit) {
            p = map_page(ctx, vcpu, stack);
            if (is_kernel_text(*p)) {
                printf("  [<" FMT_SIZE_T ">] ", *p);
                print_symbol(*p);
                printf("\n");
            } else if (stack_trace) {
                printf("    " FMT_SIZE_T "\n", *p);
            }
            stack += sizeof(*p);
        }
    }
}

void dump_ctx(int vcpu)
{
    int ret;
    vcpu_guest_context_t ctx;

    xc_handle = xc_interface_open(); /* for accessing control interface */

    ret = xc_domain_pause(xc_handle, domid);
    if (ret < 0) {
        perror("xc_domain_pause");
        exit(-1);
    }

    ret = xc_vcpu_getcontext(xc_handle, domid, vcpu, &ctx);
    if (ret < 0) {
        xc_domain_unpause(xc_handle, domid);
        perror("xc_vcpu_getcontext");
        exit(-1);
    }

    print_ctx(&ctx);
    if (is_kernel_text(ctx.user_regs.eip))
        print_stack(&ctx, vcpu);

    ret = xc_domain_unpause(xc_handle, domid);
    if (ret < 0) {
        perror("xc_domain_unpause");
        exit(-1);
    }

    xc_interface_close(xc_handle);
    if (ret < 0) {
        perror("xc_interface_close");
        exit(-1);
    }
}

void usage(void)
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
}

int main(int argc, char **argv)
{
    int ch;
    const char *sopts = "fs:h";
    const struct option lopts[] = {
        {"stack-trace", 0, NULL, 'S'},
        {"symbol-table", 1, NULL, 's'},
        {"frame-pointers", 0, NULL, 'f'},
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
