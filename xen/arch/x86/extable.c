
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

#define EX_FIELD(ptr, field) ((unsigned long)&(ptr)->field + (ptr)->field)

static inline unsigned long ex_addr(const struct exception_table_entry *x)
{
	return EX_FIELD(x, addr);
}

static inline unsigned long ex_cont(const struct exception_table_entry *x)
{
	return EX_FIELD(x, cont);
}

static int init_or_livepatch cmp_ex(const void *a, const void *b)
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

#ifndef swap_ex
static void init_or_livepatch swap_ex(void *a, void *b, int size)
{
	struct exception_table_entry *l = a, *r = b, tmp;
	long delta = b - a;

	tmp = *l;
	l->addr = r->addr + delta;
	l->cont = r->cont + delta;
	r->addr = tmp.addr - delta;
	r->cont = tmp.cont - delta;
}
#endif

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
                   const struct exception_table_entry *last,
                   unsigned long value)
{
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
search_exception_table(const struct cpu_user_regs *regs)
{
    const struct virtual_region *region = find_text_region(regs->rip);
    unsigned long stub = this_cpu(stubs.addr);

    if ( region && region->ex )
        return search_one_extable(region->ex, region->ex_end - 1, regs->rip);

    if ( regs->rip >= stub + STUB_BUF_SIZE / 2 &&
         regs->rip < stub + STUB_BUF_SIZE &&
         regs->rsp > (unsigned long)regs &&
         regs->rsp < (unsigned long)get_cpu_info() )
    {
        unsigned long retptr = *(unsigned long *)regs->rsp;

        region = find_text_region(retptr);
        retptr = region && region->ex
                 ? search_one_extable(region->ex, region->ex_end - 1, retptr)
                 : 0;
        if ( retptr )
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
            return retptr;
        }
    }

    return 0;
}

#ifndef NDEBUG
static int __init stub_selftest(void)
{
    static const struct {
        uint8_t opc[4];
        uint64_t rax;
        union stub_exception_token res;
    } tests[] __initconst = {
        { .opc = { 0x0f, 0xb9, 0xc3, 0xc3 }, /* ud1 */
          .res.fields.trapnr = TRAP_invalid_op },
        { .opc = { 0x90, 0x02, 0x00, 0xc3 }, /* nop; add (%rax),%al */
          .rax = 0x0123456789abcdef,
          .res.fields.trapnr = TRAP_gp_fault },
        { .opc = { 0x02, 0x04, 0x04, 0xc3 }, /* add (%rsp,%rax),%al */
          .rax = 0xfedcba9876543210,
          .res.fields.trapnr = TRAP_stack_error },
        { .opc = { 0xcc, 0xc3, 0xc3, 0xc3 }, /* int3 */
          .res.fields.trapnr = TRAP_int3 },
    };
    unsigned long addr = this_cpu(stubs.addr) + STUB_BUF_SIZE / 2;
    unsigned int i;

    printk("Running stub recovery selftests...\n");

    for ( i = 0; i < ARRAY_SIZE(tests); ++i )
    {
        uint8_t *ptr = map_domain_page(_mfn(this_cpu(stubs.mfn))) +
                       (addr & ~PAGE_MASK);
        unsigned long res = ~0;

        memset(ptr, 0xcc, STUB_BUF_SIZE / 2);
        memcpy(ptr, tests[i].opc, ARRAY_SIZE(tests[i].opc));
        unmap_domain_page(ptr);

        asm volatile ( "call *%[stb]\n"
                       ".Lret%=:\n\t"
                       ".pushsection .fixup,\"ax\"\n"
                       ".Lfix%=:\n\t"
                       "pop %[exn]\n\t"
                       "jmp .Lret%=\n\t"
                       ".popsection\n\t"
                       _ASM_EXTABLE(.Lret%=, .Lfix%=)
                       : [exn] "+m" (res)
                       : [stb] "rm" (addr), "a" (tests[i].rax));
        ASSERT(res == tests[i].res.raw);
    }

    return 0;
}
__initcall(stub_selftest);
#endif

unsigned long
search_pre_exception_table(struct cpu_user_regs *regs)
{
    unsigned long addr = regs->rip;
    unsigned long fixup = search_one_extable(
        __start___pre_ex_table, __stop___pre_ex_table-1, addr);
    if ( fixup )
    {
        dprintk(XENLOG_INFO, "Pre-exception: %p -> %p\n", _p(addr), _p(fixup));
        perfc_incr(exception_fixed);
    }
    return fixup;
}
