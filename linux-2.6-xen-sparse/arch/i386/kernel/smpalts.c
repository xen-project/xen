#include <linux/kernel.h>
#include <asm/system.h>
#include <asm/smp_alt.h>
#include <asm/processor.h>
#include <asm/string.h>

struct smp_replacement_record {
	unsigned char targ_size;
	unsigned char smp1_size;
	unsigned char smp2_size;
	unsigned char up_size;
	unsigned char feature;
	unsigned char data[0];
};

struct smp_alternative_record {
	void *targ_start;
	struct smp_replacement_record *repl;
};

extern struct smp_alternative_record __start_smp_alternatives_table,
  __stop_smp_alternatives_table;
extern unsigned long __init_begin, __init_end;

void prepare_for_smp(void)
{
	struct smp_alternative_record *r;
	printk(KERN_INFO "Enabling SMP...\n");
	for (r = &__start_smp_alternatives_table;
	     r != &__stop_smp_alternatives_table;
	     r++) {
		BUG_ON(r->repl->targ_size < r->repl->smp1_size);
		BUG_ON(r->repl->targ_size < r->repl->smp2_size);
		BUG_ON(r->repl->targ_size < r->repl->up_size);
               if (system_state == SYSTEM_RUNNING &&
                   r->targ_start >= (void *)&__init_begin &&
                   r->targ_start < (void *)&__init_end)
                       continue;
		if (r->repl->feature != (unsigned char)-1 &&
		    boot_cpu_has(r->repl->feature)) {
			memcpy(r->targ_start,
			       r->repl->data + r->repl->smp1_size,
			       r->repl->smp2_size);
			memset(r->targ_start + r->repl->smp2_size,
			       0x90,
			       r->repl->targ_size - r->repl->smp2_size);
		} else {
			memcpy(r->targ_start,
			       r->repl->data,
			       r->repl->smp1_size);
			memset(r->targ_start + r->repl->smp1_size,
			       0x90,
			       r->repl->targ_size - r->repl->smp1_size);
		}
	}
	/* Paranoia */
	asm volatile ("jmp 1f\n1:");
	mb();
}

void unprepare_for_smp(void)
{
	struct smp_alternative_record *r;
	printk(KERN_INFO "Disabling SMP...\n");
	for (r = &__start_smp_alternatives_table;
	     r != &__stop_smp_alternatives_table;
	     r++) {
		BUG_ON(r->repl->targ_size < r->repl->smp1_size);
		BUG_ON(r->repl->targ_size < r->repl->smp2_size);
		BUG_ON(r->repl->targ_size < r->repl->up_size);
               if (system_state == SYSTEM_RUNNING &&
                   r->targ_start >= (void *)&__init_begin &&
                   r->targ_start < (void *)&__init_end)
                       continue;
		memcpy(r->targ_start,
		       r->repl->data + r->repl->smp1_size + r->repl->smp2_size,
		       r->repl->up_size);
		memset(r->targ_start + r->repl->up_size,
		       0x90,
		       r->repl->targ_size - r->repl->up_size);
	}
	/* Paranoia */
	asm volatile ("jmp 1f\n1:");
	mb();
}
