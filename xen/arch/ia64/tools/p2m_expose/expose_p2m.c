/******************************************************************************
 * arch/ia64/xen/expose_p2m.c
 *
 * Copyright (c) 2006 Isaku Yamahata <yamahata at valinux co jp>
 *                    VA Linux Systems Japan K.K.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include <linux/module.h>
#include <linux/init.h>
#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/hypercall.h>
#include <asm/hypervisor.h>

#define printd(fmt, ...)	printk("%s:%d " fmt, __func__, __LINE__, \
				       ##__VA_ARGS__)

// copied from arch/ia64/mm/tlb.c. it isn't exported.
void
local_flush_tlb_all (void)
{
        unsigned long i, j, flags, count0, count1, stride0, stride1, addr;

        addr    = local_cpu_data->ptce_base;
        count0  = local_cpu_data->ptce_count[0];
        count1  = local_cpu_data->ptce_count[1];
        stride0 = local_cpu_data->ptce_stride[0];
        stride1 = local_cpu_data->ptce_stride[1];

        local_irq_save(flags);
        for (i = 0; i < count0; ++i) {
                for (j = 0; j < count1; ++j) {
                        ia64_ptce(addr);
                        addr += stride1;
                }
                addr += stride0;
        }
        local_irq_restore(flags);
        ia64_srlz_i();                  /* srlz.i implies srlz.d */
}

static void
do_p2m(unsigned long (*conv)(unsigned long),
       const char* msg, const char* prefix, 
       unsigned long start_gpfn, unsigned end_gpfn, unsigned long stride)
{
	struct timeval before_tv;
	struct timeval after_tv;
	unsigned long gpfn;
	unsigned long mfn;
	unsigned long count;
	s64 nsec;

	count = 0;
	do_gettimeofday(&before_tv);
	for (gpfn = start_gpfn; gpfn < end_gpfn; gpfn += stride) {
		mfn = (*conv)(gpfn);
		count++;
	}
	do_gettimeofday(&after_tv);
	nsec = timeval_to_ns(&after_tv) - timeval_to_ns(&before_tv);
	printk("%s stride %4ld %s: %9ld / %6ld = %5ld nsec\n",
	       msg, stride, prefix,
	       nsec, count, nsec/count);
}


static void
do_with_hypercall(const char* msg,
		  unsigned long start_gpfn, unsigned long end_gpfn,
		  unsigned long stride)
{
	do_p2m(&HYPERVISOR_phystomach, msg, "hypercall",
	       start_gpfn, end_gpfn, stride);
}

static void
do_with_table(const char* msg,
	    unsigned long start_gpfn, unsigned long end_gpfn,
	    unsigned long stride)
{
	do_p2m(&p2m_phystomach, msg, "p2m table",
	       start_gpfn, end_gpfn, stride);
}

static int __init
expose_p2m_init(void)
{
	unsigned long gpfn;
	unsigned long mfn;
	unsigned long p2m_mfn;

	int error_count = 0;

	const int strides[] = {
		PTRS_PER_PTE, PTRS_PER_PTE/2, PTRS_PER_PTE/3, PTRS_PER_PTE/4,
		L1_CACHE_BYTES/sizeof(pte_t), 1
	};
	int i;
	

#if 0
	printd("about to call p2m_expose_init()\n");
	if (p2m_expose_init() < 0) {
		printd("p2m_expose_init() failed\n");
		return -EINVAL;
	}
	printd("p2m_expose_init() success\n");
#else
	if (!p2m_initialized) {
		printd("p2m exposure isn't initialized\n");
		return -EINVAL;
	}
#endif

	printd("p2m expose test begins\n");
	for (gpfn = p2m_min_low_pfn; gpfn < p2m_max_low_pfn; gpfn++) {
		mfn = HYPERVISOR_phystomach(gpfn);
		p2m_mfn = p2m_phystomach(gpfn);
		if (mfn != p2m_mfn) {
			printd("gpfn 0x%016lx "
			       "mfn 0x%016lx p2m_mfn 0x%016lx\n",
			       gpfn, mfn, p2m_mfn);
			printd("mpaddr 0x%016lx "
			       "maddr 0x%016lx p2m_maddr 0x%016lx\n",
			       gpfn << PAGE_SHIFT,
			       mfn << PAGE_SHIFT, p2m_mfn << PAGE_SHIFT);

			error_count++;
			if (error_count > 16) {
				printk("too many errors\n");
				return -EINVAL;
			}
		}
	}
	printd("p2m expose test done!\n");

	printk("type     "
	       "stride      "
	       "type     : "
	       "     nsec /  count = "
	       "nsec per conv\n");
	for (i = 0; i < sizeof(strides)/sizeof(strides[0]); i++) {
		int stride = strides[i];
		local_flush_tlb_all();
		do_with_hypercall("cold tlb",
				  p2m_min_low_pfn, p2m_max_low_pfn, stride);
		do_with_hypercall("warm tlb",
				  p2m_min_low_pfn, p2m_max_low_pfn, stride);

		local_flush_tlb_all();
		do_with_table("cold tlb",
			      p2m_min_low_pfn, p2m_max_low_pfn, stride);
		do_with_table("warm tlb",
			      p2m_min_low_pfn, p2m_max_low_pfn, stride);
	}

	return -EINVAL;
}

static void __exit
expose_p2m_cleanup(void)
{
}

module_init(expose_p2m_init);
module_exit(expose_p2m_cleanup);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Isaku Yamahata <yamahata@valinux.co.jp>");
