/*
 * Initialize MMU support.
 *
 * Copyright (C) 1998-2003 Hewlett-Packard Co
 *	David Mosberger-Tang <davidm@hpl.hp.com>
 */
#include <linux/config.h>
#include <linux/kernel.h>
#include <linux/init.h>

#ifdef XEN
#include <xen/sched.h>
#endif
#include <linux/bootmem.h>
#include <linux/efi.h>
#include <linux/elf.h>
#include <linux/mm.h>
#include <linux/mmzone.h>
#include <linux/module.h>
#ifndef XEN
#include <linux/personality.h>
#endif
#include <linux/reboot.h>
#include <linux/slab.h>
#include <linux/swap.h>
#ifndef XEN
#include <linux/proc_fs.h>
#endif

#ifndef XEN
#include <asm/a.out.h>
#endif
#include <asm/bitops.h>
#include <asm/dma.h>
#ifndef XEN
#include <asm/ia32.h>
#endif
#include <asm/io.h>
#include <asm/machvec.h>
#include <asm/numa.h>
#include <asm/patch.h>
#include <asm/pgalloc.h>
#include <asm/sal.h>
#include <asm/sections.h>
#include <asm/system.h>
#include <asm/tlb.h>
#include <asm/uaccess.h>
#include <asm/unistd.h>
#include <asm/mca.h>

#ifndef XEN
DEFINE_PER_CPU(struct mmu_gather, mmu_gathers);
#endif

extern void ia64_tlb_init (void);

unsigned long MAX_DMA_ADDRESS = PAGE_OFFSET + 0x100000000UL;

#ifdef CONFIG_VIRTUAL_MEM_MAP
unsigned long vmalloc_end = VMALLOC_END_INIT;
EXPORT_SYMBOL(vmalloc_end);
struct page *vmem_map;
EXPORT_SYMBOL(vmem_map);
#endif

static int pgt_cache_water[2] = { 25, 50 };

struct page *zero_page_memmap_ptr;		/* map entry for zero page */
EXPORT_SYMBOL(zero_page_memmap_ptr);

#ifdef XEN
void *high_memory;
EXPORT_SYMBOL(high_memory);

/////////////////////////////////////////////
// following from linux-2.6.7/mm/mmap.c
/* description of effects of mapping type and prot in current implementation.
 * this is due to the limited x86 page protection hardware.  The expected
 * behavior is in parens:
 *
 * map_type	prot
 *		PROT_NONE	PROT_READ	PROT_WRITE	PROT_EXEC
 * MAP_SHARED	r: (no) no	r: (yes) yes	r: (no) yes	r: (no) yes
 *		w: (no) no	w: (no) no	w: (yes) yes	w: (no) no
 *		x: (no) no	x: (no) yes	x: (no) yes	x: (yes) yes
 *		
 * MAP_PRIVATE	r: (no) no	r: (yes) yes	r: (no) yes	r: (no) yes
 *		w: (no) no	w: (no) no	w: (copy) copy	w: (no) no
 *		x: (no) no	x: (no) yes	x: (no) yes	x: (yes) yes
 *
 */
pgprot_t protection_map[16] = {
	__P000, __P001, __P010, __P011, __P100, __P101, __P110, __P111,
	__S000, __S001, __S010, __S011, __S100, __S101, __S110, __S111
};

void insert_vm_struct(struct mm_struct * mm, struct vm_area_struct * vma)
{
	printf("insert_vm_struct: called, not implemented yet\n");
}

/////////////////////////////////////////////
//following from linux/mm/memory.c

/*
 * Allocate page middle directory.
 *
 * We've already handled the fast-path in-line, and we own the
 * page table lock.
 *
 * On a two-level page table, this ends up actually being entirely
 * optimized away.
 */
pmd_t fastcall *__pmd_alloc(struct mm_struct *mm, pgd_t *pgd, unsigned long address)
{
	pmd_t *new;

	spin_unlock(&mm->page_table_lock);
	new = pmd_alloc_one(mm, address);
	spin_lock(&mm->page_table_lock);
	if (!new)
		return NULL;

	/*
	 * Because we dropped the lock, we should re-check the
	 * entry, as somebody else could have populated it..
	 */
	if (pgd_present(*pgd)) {
		pmd_free(new);
		goto out;
	}
	pgd_populate(mm, pgd, new);
out:
	return pmd_offset(pgd, address);
}

pte_t fastcall * pte_alloc_map(struct mm_struct *mm, pmd_t *pmd, unsigned long address)
{
	if (!pmd_present(*pmd)) {
		struct page *new;

		spin_unlock(&mm->page_table_lock);
		new = pte_alloc_one(mm, address);
		spin_lock(&mm->page_table_lock);
		if (!new)
			return NULL;

		/*
		 * Because we dropped the lock, we should re-check the
		 * entry, as somebody else could have populated it..
		 */
		if (pmd_present(*pmd)) {
			pte_free(new);
			goto out;
		}
		inc_page_state(nr_page_table_pages);
		pmd_populate(mm, pmd, new);
	}
out:
	return pte_offset_map(pmd, address);
}
/////////////////////////////////////////////
#endif /* XEN */

void
check_pgt_cache (void)
{
	int low, high;

	low = pgt_cache_water[0];
	high = pgt_cache_water[1];

	if (pgtable_cache_size > (u64) high) {
		do {
			if (pgd_quicklist)
				free_page((unsigned long)pgd_alloc_one_fast(0));
			if (pmd_quicklist)
				free_page((unsigned long)pmd_alloc_one_fast(0, 0));
		} while (pgtable_cache_size > (u64) low);
	}
}

void
update_mmu_cache (struct vm_area_struct *vma, unsigned long vaddr, pte_t pte)
{
	unsigned long addr;
	struct page *page;

	if (!pte_exec(pte))
		return;				/* not an executable page... */

	page = pte_page(pte);
	/* don't use VADDR: it may not be mapped on this CPU (or may have just been flushed): */
	addr = (unsigned long) page_address(page);

	if (test_bit(PG_arch_1, &page->flags))
		return;				/* i-cache is already coherent with d-cache */

	flush_icache_range(addr, addr + PAGE_SIZE);
	set_bit(PG_arch_1, &page->flags);	/* mark page as clean */
}

inline void
ia64_set_rbs_bot (void)
{
#ifdef XEN
	unsigned stack_size = MAX_USER_STACK_SIZE;
#else
	unsigned long stack_size = current->rlim[RLIMIT_STACK].rlim_max & -16;
#endif

	if (stack_size > MAX_USER_STACK_SIZE)
		stack_size = MAX_USER_STACK_SIZE;
	current->thread.rbs_bot = STACK_TOP - stack_size;
}

/*
 * This performs some platform-dependent address space initialization.
 * On IA-64, we want to setup the VM area for the register backing
 * store (which grows upwards) and install the gateway page which is
 * used for signal trampolines, etc.
 */
void
ia64_init_addr_space (void)
{
#ifdef XEN
printf("ia64_init_addr_space: called, not implemented\n");
#else
	struct vm_area_struct *vma;

	ia64_set_rbs_bot();

	/*
	 * If we're out of memory and kmem_cache_alloc() returns NULL, we simply ignore
	 * the problem.  When the process attempts to write to the register backing store
	 * for the first time, it will get a SEGFAULT in this case.
	 */
	vma = kmem_cache_alloc(vm_area_cachep, SLAB_KERNEL);
	if (vma) {
		memset(vma, 0, sizeof(*vma));
		vma->vm_mm = current->mm;
		vma->vm_start = current->thread.rbs_bot & PAGE_MASK;
		vma->vm_end = vma->vm_start + PAGE_SIZE;
		vma->vm_page_prot = protection_map[VM_DATA_DEFAULT_FLAGS & 0x7];
		vma->vm_flags = VM_READ|VM_WRITE|VM_MAYREAD|VM_MAYWRITE|VM_GROWSUP;
		insert_vm_struct(current->mm, vma);
	}

	/* map NaT-page at address zero to speed up speculative dereferencing of NULL: */
	if (!(current->personality & MMAP_PAGE_ZERO)) {
		vma = kmem_cache_alloc(vm_area_cachep, SLAB_KERNEL);
		if (vma) {
			memset(vma, 0, sizeof(*vma));
			vma->vm_mm = current->mm;
			vma->vm_end = PAGE_SIZE;
			vma->vm_page_prot = __pgprot(pgprot_val(PAGE_READONLY) | _PAGE_MA_NAT);
			vma->vm_flags = VM_READ | VM_MAYREAD | VM_IO | VM_RESERVED;
			insert_vm_struct(current->mm, vma);
		}
	}
#endif
}

void
free_initmem (void)
{
	unsigned long addr, eaddr;

	addr = (unsigned long) ia64_imva(__init_begin);
	eaddr = (unsigned long) ia64_imva(__init_end);
	while (addr < eaddr) {
		ClearPageReserved(virt_to_page(addr));
		set_page_count(virt_to_page(addr), 1);
		free_page(addr);
		++totalram_pages;
		addr += PAGE_SIZE;
	}
	printk(KERN_INFO "Freeing unused kernel memory: %ldkB freed\n",
	       (__init_end - __init_begin) >> 10);
}

void
free_initrd_mem (unsigned long start, unsigned long end)
{
	struct page *page;
	/*
	 * EFI uses 4KB pages while the kernel can use 4KB  or bigger.
	 * Thus EFI and the kernel may have different page sizes. It is
	 * therefore possible to have the initrd share the same page as
	 * the end of the kernel (given current setup).
	 *
	 * To avoid freeing/using the wrong page (kernel sized) we:
	 *	- align up the beginning of initrd
	 *	- align down the end of initrd
	 *
	 *  |             |
	 *  |=============| a000
	 *  |             |
	 *  |             |
	 *  |             | 9000
	 *  |/////////////|
	 *  |/////////////|
	 *  |=============| 8000
	 *  |///INITRD////|
	 *  |/////////////|
	 *  |/////////////| 7000
	 *  |             |
	 *  |KKKKKKKKKKKKK|
	 *  |=============| 6000
	 *  |KKKKKKKKKKKKK|
	 *  |KKKKKKKKKKKKK|
	 *  K=kernel using 8KB pages
	 *
	 * In this example, we must free page 8000 ONLY. So we must align up
	 * initrd_start and keep initrd_end as is.
	 */
	start = PAGE_ALIGN(start);
	end = end & PAGE_MASK;

	if (start < end)
		printk(KERN_INFO "Freeing initrd memory: %ldkB freed\n", (end - start) >> 10);

	for (; start < end; start += PAGE_SIZE) {
		if (!virt_addr_valid(start))
			continue;
		page = virt_to_page(start);
		ClearPageReserved(page);
		set_page_count(page, 1);
		free_page(start);
		++totalram_pages;
	}
}

/*
 * This installs a clean page in the kernel's page table.
 */
struct page *
put_kernel_page (struct page *page, unsigned long address, pgprot_t pgprot)
{
	pgd_t *pgd;
	pmd_t *pmd;
	pte_t *pte;

	if (!PageReserved(page))
		printk(KERN_ERR "put_kernel_page: page at 0x%p not in reserved memory\n",
		       page_address(page));

	pgd = pgd_offset_k(address);		/* note: this is NOT pgd_offset()! */

	spin_lock(&init_mm.page_table_lock);
	{
		pmd = pmd_alloc(&init_mm, pgd, address);
		if (!pmd)
			goto out;
		pte = pte_alloc_map(&init_mm, pmd, address);
		if (!pte)
			goto out;
		if (!pte_none(*pte)) {
			pte_unmap(pte);
			goto out;
		}
		set_pte(pte, mk_pte(page, pgprot));
		pte_unmap(pte);
	}
  out:	spin_unlock(&init_mm.page_table_lock);
	/* no need for flush_tlb */
	return page;
}

static void
setup_gate (void)
{
#ifndef XEN
	struct page *page;

	/*
	 * Map the gate page twice: once read-only to export the ELF headers etc. and once
	 * execute-only page to enable privilege-promotion via "epc":
	 */
	page = virt_to_page(ia64_imva(__start_gate_section));
	put_kernel_page(page, GATE_ADDR, PAGE_READONLY);
#ifdef HAVE_BUGGY_SEGREL
	page = virt_to_page(ia64_imva(__start_gate_section + PAGE_SIZE));
	put_kernel_page(page, GATE_ADDR + PAGE_SIZE, PAGE_GATE);
#else
	put_kernel_page(page, GATE_ADDR + PERCPU_PAGE_SIZE, PAGE_GATE);
#endif
	ia64_patch_gate();
#endif
}

void __devinit
ia64_mmu_init (void *my_cpu_data)
{
	unsigned long psr, pta, impl_va_bits;
	extern void __devinit tlb_init (void);
	int cpu;

#ifdef CONFIG_DISABLE_VHPT
#	define VHPT_ENABLE_BIT	0
#else
#	define VHPT_ENABLE_BIT	1
#endif

	/* Pin mapping for percpu area into TLB */
	psr = ia64_clear_ic();
	ia64_itr(0x2, IA64_TR_PERCPU_DATA, PERCPU_ADDR,
		 pte_val(pfn_pte(__pa(my_cpu_data) >> PAGE_SHIFT, PAGE_KERNEL)),
		 PERCPU_PAGE_SHIFT);

	ia64_set_psr(psr);
	ia64_srlz_i();

	/*
	 * Check if the virtually mapped linear page table (VMLPT) overlaps with a mapped
	 * address space.  The IA-64 architecture guarantees that at least 50 bits of
	 * virtual address space are implemented but if we pick a large enough page size
	 * (e.g., 64KB), the mapped address space is big enough that it will overlap with
	 * VMLPT.  I assume that once we run on machines big enough to warrant 64KB pages,
	 * IMPL_VA_MSB will be significantly bigger, so this is unlikely to become a
	 * problem in practice.  Alternatively, we could truncate the top of the mapped
	 * address space to not permit mappings that would overlap with the VMLPT.
	 * --davidm 00/12/06
	 */
#	define pte_bits			3
#	define mapped_space_bits	(3*(PAGE_SHIFT - pte_bits) + PAGE_SHIFT)
	/*
	 * The virtual page table has to cover the entire implemented address space within
	 * a region even though not all of this space may be mappable.  The reason for
	 * this is that the Access bit and Dirty bit fault handlers perform
	 * non-speculative accesses to the virtual page table, so the address range of the
	 * virtual page table itself needs to be covered by virtual page table.
	 */
#	define vmlpt_bits		(impl_va_bits - PAGE_SHIFT + pte_bits)
#	define POW2(n)			(1ULL << (n))

	impl_va_bits = ffz(~(local_cpu_data->unimpl_va_mask | (7UL << 61)));

	if (impl_va_bits < 51 || impl_va_bits > 61)
		panic("CPU has bogus IMPL_VA_MSB value of %lu!\n", impl_va_bits - 1);

#ifdef XEN
	vhpt_init();
	alloc_dom0();
#else
	/* place the VMLPT at the end of each page-table mapped region: */
	pta = POW2(61) - POW2(vmlpt_bits);

	if (POW2(mapped_space_bits) >= pta)
		panic("mm/init: overlap between virtually mapped linear page table and "
		      "mapped kernel space!");
	/*
	 * Set the (virtually mapped linear) page table address.  Bit
	 * 8 selects between the short and long format, bits 2-7 the
	 * size of the table, and bit 0 whether the VHPT walker is
	 * enabled.
	 */
	ia64_set_pta(pta | (0 << 8) | (vmlpt_bits << 2) | VHPT_ENABLE_BIT);
#endif

	ia64_tlb_init();

#ifdef	CONFIG_HUGETLB_PAGE
	ia64_set_rr(HPAGE_REGION_BASE, HPAGE_SHIFT << 2);
	ia64_srlz_d();
#endif

	cpu = smp_processor_id();

#ifndef XEN
	/* mca handler uses cr.lid as key to pick the right entry */
	ia64_mca_tlb_list[cpu].cr_lid = ia64_getreg(_IA64_REG_CR_LID);

	/* insert this percpu data information into our list for MCA recovery purposes */
	ia64_mca_tlb_list[cpu].percpu_paddr = pte_val(mk_pte_phys(__pa(my_cpu_data), PAGE_KERNEL));
	/* Also save per-cpu tlb flush recipe for use in physical mode mca handler */
	ia64_mca_tlb_list[cpu].ptce_base = local_cpu_data->ptce_base;
	ia64_mca_tlb_list[cpu].ptce_count[0] = local_cpu_data->ptce_count[0];
	ia64_mca_tlb_list[cpu].ptce_count[1] = local_cpu_data->ptce_count[1];
	ia64_mca_tlb_list[cpu].ptce_stride[0] = local_cpu_data->ptce_stride[0];
	ia64_mca_tlb_list[cpu].ptce_stride[1] = local_cpu_data->ptce_stride[1];
#endif
}

#ifdef CONFIG_VIRTUAL_MEM_MAP

int
create_mem_map_page_table (u64 start, u64 end, void *arg)
{
	unsigned long address, start_page, end_page;
	struct page *map_start, *map_end;
	int node;
	pgd_t *pgd;
	pmd_t *pmd;
	pte_t *pte;

	map_start = vmem_map + (__pa(start) >> PAGE_SHIFT);
	map_end   = vmem_map + (__pa(end) >> PAGE_SHIFT);

	start_page = (unsigned long) map_start & PAGE_MASK;
	end_page = PAGE_ALIGN((unsigned long) map_end);
	node = paddr_to_nid(__pa(start));

	for (address = start_page; address < end_page; address += PAGE_SIZE) {
		pgd = pgd_offset_k(address);
		if (pgd_none(*pgd))
			pgd_populate(&init_mm, pgd, alloc_bootmem_pages_node(NODE_DATA(node), PAGE_SIZE));
		pmd = pmd_offset(pgd, address);

		if (pmd_none(*pmd))
			pmd_populate_kernel(&init_mm, pmd, alloc_bootmem_pages_node(NODE_DATA(node), PAGE_SIZE));
		pte = pte_offset_kernel(pmd, address);

		if (pte_none(*pte))
			set_pte(pte, pfn_pte(__pa(alloc_bootmem_pages_node(NODE_DATA(node), PAGE_SIZE)) >> PAGE_SHIFT,
					     PAGE_KERNEL));
	}
	return 0;
}

struct memmap_init_callback_data {
	struct page *start;
	struct page *end;
	int nid;
	unsigned long zone;
};

static int
virtual_memmap_init (u64 start, u64 end, void *arg)
{
	struct memmap_init_callback_data *args;
	struct page *map_start, *map_end;

	args = (struct memmap_init_callback_data *) arg;

	map_start = vmem_map + (__pa(start) >> PAGE_SHIFT);
	map_end   = vmem_map + (__pa(end) >> PAGE_SHIFT);

	if (map_start < args->start)
		map_start = args->start;
	if (map_end > args->end)
		map_end = args->end;

	/*
	 * We have to initialize "out of bounds" struct page elements that fit completely
	 * on the same pages that were allocated for the "in bounds" elements because they
	 * may be referenced later (and found to be "reserved").
	 */
	map_start -= ((unsigned long) map_start & (PAGE_SIZE - 1)) / sizeof(struct page);
	map_end += ((PAGE_ALIGN((unsigned long) map_end) - (unsigned long) map_end)
		    / sizeof(struct page));

	if (map_start < map_end)
		memmap_init_zone(map_start, (unsigned long) (map_end - map_start),
				 args->nid, args->zone, page_to_pfn(map_start));
	return 0;
}

void
memmap_init (struct page *start, unsigned long size, int nid,
	     unsigned long zone, unsigned long start_pfn)
{
	if (!vmem_map)
		memmap_init_zone(start, size, nid, zone, start_pfn);
	else {
		struct memmap_init_callback_data args;

		args.start = start;
		args.end = start + size;
		args.nid = nid;
		args.zone = zone;

		efi_memmap_walk(virtual_memmap_init, &args);
	}
}

int
ia64_pfn_valid (unsigned long pfn)
{
	char byte;
	struct page *pg = pfn_to_page(pfn);

	return     (__get_user(byte, (char *) pg) == 0)
		&& ((((u64)pg & PAGE_MASK) == (((u64)(pg + 1) - 1) & PAGE_MASK))
			|| (__get_user(byte, (char *) (pg + 1) - 1) == 0));
}
EXPORT_SYMBOL(ia64_pfn_valid);

int
find_largest_hole (u64 start, u64 end, void *arg)
{
	u64 *max_gap = arg;

	static u64 last_end = PAGE_OFFSET;

	/* NOTE: this algorithm assumes efi memmap table is ordered */

#ifdef XEN
//printf("find_largest_hole: start=%lx,end=%lx,max_gap=%lx\n",start,end,*(unsigned long *)arg);
#endif
	if (*max_gap < (start - last_end))
		*max_gap = start - last_end;
	last_end = end;
#ifdef XEN
//printf("find_largest_hole2: max_gap=%lx,last_end=%lx\n",*max_gap,last_end);
#endif
	return 0;
}
#endif /* CONFIG_VIRTUAL_MEM_MAP */

static int
count_reserved_pages (u64 start, u64 end, void *arg)
{
	unsigned long num_reserved = 0;
	unsigned long *count = arg;

	for (; start < end; start += PAGE_SIZE)
		if (PageReserved(virt_to_page(start)))
			++num_reserved;
	*count += num_reserved;
	return 0;
}

/*
 * Boot command-line option "nolwsys" can be used to disable the use of any light-weight
 * system call handler.  When this option is in effect, all fsyscalls will end up bubbling
 * down into the kernel and calling the normal (heavy-weight) syscall handler.  This is
 * useful for performance testing, but conceivably could also come in handy for debugging
 * purposes.
 */

static int nolwsys;

static int __init
nolwsys_setup (char *s)
{
	nolwsys = 1;
	return 1;
}

__setup("nolwsys", nolwsys_setup);

void
mem_init (void)
{
	long reserved_pages, codesize, datasize, initsize;
	unsigned long num_pgt_pages;
	pg_data_t *pgdat;
	int i;
#ifndef XEN
	static struct kcore_list kcore_mem, kcore_vmem, kcore_kernel;
#endif

#ifdef CONFIG_PCI
	/*
	 * This needs to be called _after_ the command line has been parsed but _before_
	 * any drivers that may need the PCI DMA interface are initialized or bootmem has
	 * been freed.
	 */
	platform_dma_init();
#endif

#ifndef CONFIG_DISCONTIGMEM
	if (!mem_map)
		BUG();
	max_mapnr = max_low_pfn;
#endif

	high_memory = __va(max_low_pfn * PAGE_SIZE);

#ifndef XEN
	kclist_add(&kcore_mem, __va(0), max_low_pfn * PAGE_SIZE);
	kclist_add(&kcore_vmem, (void *)VMALLOC_START, VMALLOC_END-VMALLOC_START);
	kclist_add(&kcore_kernel, _stext, _end - _stext);
#endif

	for_each_pgdat(pgdat)
		totalram_pages += free_all_bootmem_node(pgdat);

	reserved_pages = 0;
	efi_memmap_walk(count_reserved_pages, &reserved_pages);

	codesize =  (unsigned long) _etext - (unsigned long) _stext;
	datasize =  (unsigned long) _edata - (unsigned long) _etext;
	initsize =  (unsigned long) __init_end - (unsigned long) __init_begin;

	printk(KERN_INFO "Memory: %luk/%luk available (%luk code, %luk reserved, "
	       "%luk data, %luk init)\n", (unsigned long) nr_free_pages() << (PAGE_SHIFT - 10),
	       num_physpages << (PAGE_SHIFT - 10), codesize >> 10,
	       reserved_pages << (PAGE_SHIFT - 10), datasize >> 10, initsize >> 10);

	/*
	 * Allow for enough (cached) page table pages so that we can map the entire memory
	 * at least once.  Each task also needs a couple of page tables pages, so add in a
	 * fudge factor for that (don't use "threads-max" here; that would be wrong!).
	 * Don't allow the cache to be more than 10% of total memory, though.
	 */
#	define NUM_TASKS	500	/* typical number of tasks */
	num_pgt_pages = nr_free_pages() / PTRS_PER_PGD + NUM_TASKS;
	if (num_pgt_pages > nr_free_pages() / 10)
		num_pgt_pages = nr_free_pages() / 10;
	if (num_pgt_pages > (u64) pgt_cache_water[1])
		pgt_cache_water[1] = num_pgt_pages;

#ifndef XEN
	/*
	 * For fsyscall entrpoints with no light-weight handler, use the ordinary
	 * (heavy-weight) handler, but mark it by setting bit 0, so the fsyscall entry
	 * code can tell them apart.
	 */
	for (i = 0; i < NR_syscalls; ++i) {
		extern unsigned long fsyscall_table[NR_syscalls];
		extern unsigned long sys_call_table[NR_syscalls];

		if (!fsyscall_table[i] || nolwsys)
			fsyscall_table[i] = sys_call_table[i] | 1;
	}
#endif
	setup_gate();	/* setup gate pages before we free up boot memory... */

#ifdef CONFIG_IA32_SUPPORT
	ia32_boot_gdt_init();
#endif
}
