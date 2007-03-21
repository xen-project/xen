#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/ctype.h>
#include <linux/module.h>
#include <linux/seq_file.h>
#include <asm/uaccess.h>
#include <linux/mutex.h>

#include <asm/mtrr.h>
#include "mtrr.h"

static DEFINE_MUTEX(mtrr_mutex);

void generic_get_mtrr(unsigned int reg, unsigned long *base,
		      unsigned int *size, mtrr_type * type)
{
	struct xen_platform_op op;

	op.cmd = XENPF_read_memtype;
	op.u.read_memtype.reg = reg;
	(void)HYPERVISOR_platform_op(&op);

	*size = op.u.read_memtype.nr_mfns;
	*base = op.u.read_memtype.mfn;
	*type = op.u.read_memtype.type;
}

struct mtrr_ops generic_mtrr_ops = {
	.use_intel_if      = 1,
	.get               = generic_get_mtrr,
};

struct mtrr_ops *mtrr_if = &generic_mtrr_ops;
unsigned int num_var_ranges;
unsigned int *usage_table;

static void __init set_num_var_ranges(void)
{
	struct xen_platform_op op;

	for (num_var_ranges = 0; ; num_var_ranges++) {
		op.cmd = XENPF_read_memtype;
		op.u.read_memtype.reg = num_var_ranges;
		if (HYPERVISOR_platform_op(&op) != 0)
			break;
	}
}

static void __init init_table(void)
{
	int i, max;

	max = num_var_ranges;
	if ((usage_table = kmalloc(max * sizeof *usage_table, GFP_KERNEL))
	    == NULL) {
		printk(KERN_ERR "mtrr: could not allocate\n");
		return;
	}
	for (i = 0; i < max; i++)
		usage_table[i] = 0;
}

int mtrr_add_page(unsigned long base, unsigned long size, 
		  unsigned int type, char increment)
{
	int error;
	struct xen_platform_op op;

	mutex_lock(&mtrr_mutex);

	op.cmd = XENPF_add_memtype;
	op.u.add_memtype.mfn     = base;
	op.u.add_memtype.nr_mfns = size;
	op.u.add_memtype.type    = type;
	error = HYPERVISOR_platform_op(&op);
	if (error) {
		mutex_unlock(&mtrr_mutex);
		BUG_ON(error > 0);
		return error;
	}

	if (increment)
		++usage_table[op.u.add_memtype.reg];

	mutex_unlock(&mtrr_mutex);

	return op.u.add_memtype.reg;
}

static int mtrr_check(unsigned long base, unsigned long size)
{
	if ((base & (PAGE_SIZE - 1)) || (size & (PAGE_SIZE - 1))) {
		printk(KERN_WARNING
			"mtrr: size and base must be multiples of 4 kiB\n");
		printk(KERN_DEBUG
			"mtrr: size: 0x%lx  base: 0x%lx\n", size, base);
		dump_stack();
		return -1;
	}
	return 0;
}

int
mtrr_add(unsigned long base, unsigned long size, unsigned int type,
	 char increment)
{
	if (mtrr_check(base, size))
		return -EINVAL;
	return mtrr_add_page(base >> PAGE_SHIFT, size >> PAGE_SHIFT, type,
			     increment);
}

int mtrr_del_page(int reg, unsigned long base, unsigned long size)
{
	unsigned i;
	mtrr_type ltype;
	unsigned long lbase;
	unsigned int lsize;
	int error = -EINVAL;
	struct xen_platform_op op;

	mutex_lock(&mtrr_mutex);

	if (reg < 0) {
		/*  Search for existing MTRR  */
		for (i = 0; i < num_var_ranges; ++i) {
			mtrr_if->get(i, &lbase, &lsize, &ltype);
			if (lbase == base && lsize == size) {
				reg = i;
				break;
			}
		}
		if (reg < 0) {
			printk(KERN_DEBUG "mtrr: no MTRR for %lx000,%lx000 found\n", base,
			       size);
			goto out;
		}
	}
	if (usage_table[reg] < 1) {
		printk(KERN_WARNING "mtrr: reg: %d has count=0\n", reg);
		goto out;
	}
	if (--usage_table[reg] < 1) {
		op.cmd = XENPF_del_memtype;
		op.u.del_memtype.handle = 0;
		op.u.del_memtype.reg    = reg;
		error = HYPERVISOR_platform_op(&op);
		if (error) {
			BUG_ON(error > 0);
			goto out;
		}
	}
	error = reg;
 out:
	mutex_unlock(&mtrr_mutex);
	return error;
}

int
mtrr_del(int reg, unsigned long base, unsigned long size)
{
	if (mtrr_check(base, size))
		return -EINVAL;
	return mtrr_del_page(reg, base >> PAGE_SHIFT, size >> PAGE_SHIFT);
}

EXPORT_SYMBOL(mtrr_add);
EXPORT_SYMBOL(mtrr_del);

void __init mtrr_bp_init(void)
{
}

void mtrr_ap_init(void)
{
}

static int __init mtrr_init(void)
{
	struct cpuinfo_x86 *c = &boot_cpu_data;

	if (!is_initial_xendomain())
		return -ENODEV;

	if ((!cpu_has(c, X86_FEATURE_MTRR)) &&
	    (!cpu_has(c, X86_FEATURE_K6_MTRR)) &&
	    (!cpu_has(c, X86_FEATURE_CYRIX_ARR)) &&
	    (!cpu_has(c, X86_FEATURE_CENTAUR_MCR)))
		return -ENODEV;

	set_num_var_ranges();
	init_table();

	return 0;
}

subsys_initcall(mtrr_init);
