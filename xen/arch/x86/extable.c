
#include <xen/config.h>
#include <xen/spinlock.h>
#include <asm/uaccess.h>

extern const struct exception_table_entry __start___ex_table[];
extern const struct exception_table_entry __stop___ex_table[];

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
        diff = mid->insn - value;
        if (diff == 0)
            return mid->fixup;
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
    return search_one_table(__start___ex_table, __stop___ex_table-1, addr);
}
