
#include <xen/init.h>
#include <xen/list.h>
#include <xen/perfc.h>
#include <xen/rcupdate.h>
#include <xen/sort.h>
#include <xen/spinlock.h>
#include <asm/uaccess.h>
#include <xen/domain_page.h>
#include <xen/virtual_region.h>
#include <xen/livepatch.h>
#include <xen/warning.h>

#define EX_FIELD(ptr, field) ((unsigned long)&(ptr)->field + (ptr)->field)

static inline unsigned long ex_addr(const struct exception_table_entry *x)
{
	return EX_FIELD(x, addr);
}

static inline unsigned long ex_cont(const struct exception_table_entry *x)
{
	return EX_FIELD(x, cont);
}

static int init_or_livepatch cf_check cmp_ex(const void *a, const void *b)
{
	const struct exception_table_entry *l = a, *r = b;
	unsigned long lip = ex_addr(l);
	unsigned long rip = ex_addr(r);

	/* avoid overflow */
	if (lip > rip)
		return 1;
	if (lip < rip)
		return -1;
	return 0;
}

static void init_or_livepatch cf_check swap_ex(void *a, void *b, size_t size)
{
	struct exception_table_entry *l = a, *r = b, tmp;
	long delta = b - a;

	tmp = *l;
	l->addr = r->addr + delta;
	l->cont = r->cont + delta;
	r->addr = tmp.addr - delta;
	r->cont = tmp.cont - delta;
}

void init_or_livepatch sort_exception_table(struct exception_table_entry *start,
                                 const struct exception_table_entry *stop)
{
    sort(start, stop - start,
         sizeof(struct exception_table_entry), cmp_ex, swap_ex);
}

void __init sort_exception_tables(void)
{
    sort_exception_table(__start___ex_table, __stop___ex_table);
    sort_exception_table(__start___pre_ex_table, __stop___pre_ex_table);
}

static unsigned long
search_one_extable(const struct exception_table_entry *first,
                   const struct exception_table_entry *end,
                   unsigned long value)
{
    const struct exception_table_entry *last = end - 1;
    const struct exception_table_entry *mid;
    long diff;

    while ( first <= last )
    {
        mid = (last - first) / 2 + first;
        diff = ex_addr(mid) - value;
        if (diff == 0)
            return ex_cont(mid);
        else if (diff < 0)
            first = mid+1;
        else
            last = mid-1;
    }
    return 0;
}

unsigned long
search_exception_table(const struct cpu_user_regs *regs, unsigned long *stub_ra)
{
    const struct virtual_region *region = find_text_region(regs->rip);
    unsigned long stub = this_cpu(stubs.addr);

    if ( region && region->ex )
    {
        *stub_ra = 0;
        return search_one_extable(region->ex, region->ex_end, regs->rip);
    }

    /*
     * Emulation stubs (which are per-CPU) are constructed with a RET at the
     * end, and are CALLed by the invoking code.
     *
     * An exception in the stubs may occur anywhere, so we first match any
     * %rip in the correct stub, with a sanity check on %rsp too.  But, an
     * entry in ex_table[] needs to be compile-time constant, so we register
     * the fixup address using the invoking CALL's return address.
     *
     * To recover, we:
     * 1) Emulate a pseudo-RET to get out of the stub.  We POP the return
     *    address off the stack(s), use it to look up the fixup address, and
     *    JMP there, then
     * 2) Emulate a PUSH of 'token' onto the data stack to pass information
     *    about the exception back to the invoking code.
     */
    if ( regs->rip >= stub + STUB_BUF_SIZE / 2 &&
         regs->rip < stub + STUB_BUF_SIZE &&
         regs->rsp > (unsigned long)regs &&
         regs->rsp < (unsigned long)get_cpu_info() )
    {
        unsigned long retaddr = *(unsigned long *)regs->rsp, fixup;

        region = find_text_region(retaddr);
        fixup = region && region->ex
                ? search_one_extable(region->ex, region->ex_end, retaddr)
                : 0;
        if ( fixup )
        {
            /*
             * Put trap number and error code on the stack (in place of the
             * original return address) for recovery code to pick up.
             */
            union stub_exception_token token = {
                .fields.ec = regs->error_code,
                .fields.trapnr = regs->entry_vector,
            };

            *(unsigned long *)regs->rsp = token.raw;
            *stub_ra = retaddr;
            return fixup;
        }
    }

    return 0;
}

#ifdef CONFIG_SELF_TESTS
#include <asm/setup.h>
#include <asm/traps.h>

int __init cf_check stub_selftest(void)
{
    static const struct {
        uint8_t opc[8];
        uint64_t rax;
        union stub_exception_token res;
    } tests[] __initconst = {
#define endbr64 0xf3, 0x0f, 0x1e, 0xfa
        { .opc = { endbr64, 0x0f, 0xb9, 0xc3, 0xc3 }, /* ud1 */
          .res.fields.trapnr = X86_EXC_UD },
        { .opc = { endbr64, 0x90, 0x02, 0x00, 0xc3 }, /* nop; add (%rax),%al */
          .rax = 0x0123456789abcdef,
          .res.fields.trapnr = X86_EXC_GP },
        { .opc = { endbr64, 0x02, 0x04, 0x04, 0xc3 }, /* add (%rsp,%rax),%al */
          .rax = 0xfedcba9876543210UL,
          .res.fields.trapnr = X86_EXC_SS },
        { .opc = { endbr64, 0xcc, 0xc3, 0xc3, 0xc3 }, /* int3 */
          .res.fields.trapnr = X86_EXC_BP },
#undef endbr64
    };
    unsigned long addr = this_cpu(stubs.addr) + STUB_BUF_SIZE / 2;
    unsigned int i;
    bool fail = false;

    printk("%s stub recovery selftests...\n",
           system_state < SYS_STATE_active ? "Running" : "Re-running");

    for ( i = 0; i < ARRAY_SIZE(tests); ++i )
    {
        uint8_t *ptr = map_domain_page(_mfn(this_cpu(stubs.mfn))) +
                       (addr & ~PAGE_MASK);
        union stub_exception_token res = { .raw = ~0 };

        memset(ptr, 0xcc, STUB_BUF_SIZE / 2);
        memcpy(ptr, tests[i].opc, ARRAY_SIZE(tests[i].opc));
        unmap_domain_page(ptr);

        asm volatile ( "INDIRECT_CALL %[stb]\n"
                       ".Lret%=:\n\t"
                       ".pushsection .fixup,\"ax\"\n"
                       ".Lfix%=:\n\t"
                       "pop %[exn]\n\t"
                       "jmp .Lret%=\n\t"
                       ".popsection\n\t"
                       _ASM_EXTABLE(.Lret%=, .Lfix%=)
                       : [exn] "+m" (res) ASM_CALL_CONSTRAINT
                       : [stb] "r" (addr), "a" (tests[i].rax));

        if ( res.raw != tests[i].res.raw )
        {
            printk("Selftest %u failed: Opc %*ph "
                   "expected %s[%04x], got %s[%04x]\n",
                   i, (int)ARRAY_SIZE(tests[i].opc), tests[i].opc,
                   vector_name(tests[i].res.fields.trapnr), tests[i].res.fields.ec,
                   vector_name(res.fields.trapnr), res.fields.ec);

            fail = true;
        }
    }

    if ( fail )
        warning_add("SELFTEST FAILURE: CORRECT BEHAVIOR CANNOT BE GUARANTEED\n");

    return 0;
}
__initcall(stub_selftest);
#endif /* CONFIG_SELF_TESTS */

unsigned long asmlinkage search_pre_exception_table(struct cpu_user_regs *regs)
{
    unsigned long addr = regs->rip;
    unsigned long fixup = search_one_extable(
        __start___pre_ex_table, __stop___pre_ex_table, addr);
    if ( fixup )
    {
        dprintk(XENLOG_INFO, "Pre-exception: %p -> %p\n", _p(addr), _p(fixup));
        perfc_incr(exception_fixed);
    }
    return fixup;
}
