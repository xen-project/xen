
#include <xen/config.h>
#include <xen/init.h>
#include <xen/perfc.h>
#include <xen/sort.h>
#include <xen/spinlock.h>
#include <asm/uaccess.h>

#define EX_FIELD(ptr, field) ((unsigned long)&(ptr)->field + (ptr)->field)

static inline unsigned long ex_addr(const struct exception_table_entry *x)
{
	return EX_FIELD(x, addr);
}

static inline unsigned long ex_cont(const struct exception_table_entry *x)
{
	return EX_FIELD(x, cont);
}

static int __init cmp_ex(const void *a, const void *b)
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
static void __init swap_ex(void *a, void *b, int size)
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

void __init sort_exception_tables(void)
{
    sort(__start___ex_table, __stop___ex_table - __start___ex_table,
         sizeof(struct exception_table_entry), cmp_ex, swap_ex);
    sort(__start___pre_ex_table,
         __stop___pre_ex_table - __start___pre_ex_table,
         sizeof(struct exception_table_entry), cmp_ex, swap_ex);
}

static inline unsigned long
search_one_table(const struct exception_table_entry *first,
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
search_exception_table(unsigned long addr)
{
    return search_one_table(
        __start___ex_table, __stop___ex_table-1, addr);
}

unsigned long
search_pre_exception_table(struct cpu_user_regs *regs)
{
    unsigned long addr = (unsigned long)regs->eip;
    unsigned long fixup = search_one_table(
        __start___pre_ex_table, __stop___pre_ex_table-1, addr);
    if ( fixup )
    {
        dprintk(XENLOG_INFO, "Pre-exception: %p -> %p\n", _p(addr), _p(fixup));
        perfc_incr(exception_fixed);
    }
    return fixup;
}
