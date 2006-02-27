#ifndef __ARCH_DESC_H
#define __ARCH_DESC_H

#include <asm/ldt.h>
#include <asm/segment.h>

#define CPU_16BIT_STACK_SIZE 1024

#ifndef __ASSEMBLY__

#include <linux/preempt.h>
#include <linux/smp.h>

#include <asm/mmu.h>

extern struct desc_struct cpu_gdt_table[GDT_ENTRIES];

DECLARE_PER_CPU(unsigned char, cpu_16bit_stack[CPU_16BIT_STACK_SIZE]);

struct Xgt_desc_struct {
	unsigned short size;
	unsigned long address __attribute__((packed));
	unsigned short pad;
} __attribute__ ((packed));

extern struct Xgt_desc_struct idt_descr;
DECLARE_PER_CPU(struct Xgt_desc_struct, cpu_gdt_descr);


static inline struct desc_struct *get_cpu_gdt_table(unsigned int cpu)
{
	return (struct desc_struct *)per_cpu(cpu_gdt_descr, cpu).address;
}

#define load_TR_desc() __asm__ __volatile__("ltr %w0"::"q" (GDT_ENTRY_TSS*8))
#define load_LDT_desc() __asm__ __volatile__("lldt %w0"::"q" (GDT_ENTRY_LDT*8))

#define load_gdt(dtr) __asm__ __volatile("lgdt %0"::"m" (*dtr))
#define load_idt(dtr) __asm__ __volatile("lidt %0"::"m" (*dtr))
#define load_tr(tr) __asm__ __volatile("ltr %0"::"mr" (tr))
#define load_ldt(ldt) __asm__ __volatile("lldt %0"::"mr" (ldt))

#define store_gdt(dtr) __asm__ ("sgdt %0":"=m" (*dtr))
#define store_idt(dtr) __asm__ ("sidt %0":"=m" (*dtr))
#define store_tr(tr) __asm__ ("str %0":"=mr" (tr))
#define store_ldt(ldt) __asm__ ("sldt %0":"=mr" (ldt))

/*
 * This is the ldt that every process will get unless we need
 * something other than this.
 */
extern struct desc_struct default_ldt[];
extern void set_intr_gate(unsigned int irq, void * addr);

#define _set_tssldt_desc(n,addr,limit,type) \
__asm__ __volatile__ ("movw %w3,0(%2)\n\t" \
	"movw %w1,2(%2)\n\t" \
	"rorl $16,%1\n\t" \
	"movb %b1,4(%2)\n\t" \
	"movb %4,5(%2)\n\t" \
	"movb $0,6(%2)\n\t" \
	"movb %h1,7(%2)\n\t" \
	"rorl $16,%1" \
	: "=m"(*(n)) : "q" (addr), "r"(n), "ir"(limit), "i"(type))

#ifndef CONFIG_X86_NO_TSS
static inline void __set_tss_desc(unsigned int cpu, unsigned int entry, void *addr)
{
	_set_tssldt_desc(&get_cpu_gdt_table(cpu)[entry], (int)addr,
		offsetof(struct tss_struct, __cacheline_filler) - 1, 0x89);
}

#define set_tss_desc(cpu,addr) __set_tss_desc(cpu, GDT_ENTRY_TSS, addr)
#endif

static inline void set_ldt_desc(unsigned int cpu, void *addr, unsigned int size)
{
	_set_tssldt_desc(&get_cpu_gdt_table(cpu)[GDT_ENTRY_LDT], (int)addr, ((size << 3)-1), 0x82);
}

#define LDT_entry_a(info) \
	((((info)->base_addr & 0x0000ffff) << 16) | ((info)->limit & 0x0ffff))

#define LDT_entry_b(info) \
	(((info)->base_addr & 0xff000000) | \
	(((info)->base_addr & 0x00ff0000) >> 16) | \
	((info)->limit & 0xf0000) | \
	(((info)->read_exec_only ^ 1) << 9) | \
	((info)->contents << 10) | \
	(((info)->seg_not_present ^ 1) << 15) | \
	((info)->seg_32bit << 22) | \
	((info)->limit_in_pages << 23) | \
	((info)->useable << 20) | \
	0x7000)

#define LDT_empty(info) (\
	(info)->base_addr	== 0	&& \
	(info)->limit		== 0	&& \
	(info)->contents	== 0	&& \
	(info)->read_exec_only	== 1	&& \
	(info)->seg_32bit	== 0	&& \
	(info)->limit_in_pages	== 0	&& \
	(info)->seg_not_present	== 1	&& \
	(info)->useable		== 0	)

extern int write_ldt_entry(void *ldt, int entry, __u32 entry_a, __u32 entry_b);

#if TLS_SIZE != 24
# error update this code.
#endif

static inline void load_TLS(struct thread_struct *t, unsigned int cpu)
{
#define C(i) HYPERVISOR_update_descriptor(virt_to_machine(&get_cpu_gdt_table(cpu)[GDT_ENTRY_TLS_MIN + i]), *(u64 *)&t->tls_array[i])
	C(0); C(1); C(2);
#undef C
}

static inline void clear_LDT(void)
{
	int cpu = get_cpu();

	/*
	 * NB. We load the default_ldt for lcall7/27 handling on demand, as
	 * it slows down context switching. Noone uses it anyway.
	 */
	cpu = cpu;		/* XXX avoid compiler warning */
	xen_set_ldt(0UL, 0);
	put_cpu();
}

/*
 * load one particular LDT into the current CPU
 */
static inline void load_LDT_nolock(mm_context_t *pc, int cpu)
{
	void *segments = pc->ldt;
	int count = pc->size;

	if (likely(!count))
		segments = NULL;

	xen_set_ldt((unsigned long)segments, count);
}

static inline void load_LDT(mm_context_t *pc)
{
	int cpu = get_cpu();
	load_LDT_nolock(pc, cpu);
	put_cpu();
}

static inline unsigned long get_desc_base(unsigned long *desc)
{
	unsigned long base;
	base = ((desc[0] >> 16)  & 0x0000ffff) |
		((desc[1] << 16) & 0x00ff0000) |
		(desc[1] & 0xff000000);
	return base;
}

#endif /* !__ASSEMBLY__ */

#endif
