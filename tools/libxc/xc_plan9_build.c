/******************************************************************************
 * xc_plan9_build.c
 * derived from xc_linux_build.c
 */

#include "xc_private.h"

#include <zlib.h>

#define DEBUG 1
#ifdef DEBUG
#define DPRINTF(x) printf x; fflush(stdout);
#else
#define DPRINTF(x)
#endif

#include "plan9a.out.h"

/* really TOS which means stack starts at 0x2000, and uses page 1*/
#define STACKPAGE 2
struct Exec header, origheader;

typedef struct page {
	char data[PAGE_SIZE];
} PAGE;


int
memcpy_toguest(int xc_handle, u32 dom, void *v, int size,
	       unsigned long *page_array, unsigned int to_page)
{
	int ret;
	unsigned char *cp = v;
	unsigned int whichpage;
	unsigned char *vaddr;

//  DPRINTF(("memcpy_to_guest: to_page 0x%x, count %d\n", to_page, size));
	for (ret = 0, whichpage = to_page; size > 0;
	     whichpage++, size -= PAGE_SIZE, cp += PAGE_SIZE) {

		//     DPRINTF (("map_pfn_writeable(%p, 0x%lx)\n", pm_handle,
//                page_array[whichpage]));
		vaddr = xc_map_foreign_range(xc_handle, dom, PAGE_SIZE,
					     PROT_READ | PROT_WRITE,
					     page_array[whichpage]);
		//    DPRINTF (("vaddr is %p\n", vaddr));
		if (vaddr == NULL) {
			ret = -1;
			ERROR("Couldn't map guest memory");
			goto out;
		}
		//   DPRINTF (("copy %p to %p, count 0x%x\n", cp, vaddr, 4096));
		memcpy(vaddr, cp, 4096);
		munmap(vaddr, PAGE_SIZE);
		//  DPRINTF (("Did %ud'th pages\n", whichpage));
	}
      out:
	return ret;
}

int
blah(char *b)
{
	fprintf(stderr, "Error in xc_plan9_build!\n");
	perror(b);
	return errno;
}

/* swap bytes. For plan 9 headers */
void
swabby(unsigned long *s, char *name)
{
	unsigned long it;
	it = ((*s & 0xff000000) >> 24) | ((*s & 0xff0000) >> 8) |
	    ((*s & 0xff00) << 8) | ((*s & 0xff) << 24);
	DPRINTF(("Item %s is 0x%lx\n", name, it));
	*s = it;
}

void
plan9header(Exec * header)
{
	/* header is big-endian */
	swabby((unsigned long *)&header->magic, "magic");
	swabby((unsigned long *)&header->text, "text");
	swabby((unsigned long *)&header->data, "data");
	swabby((unsigned long *)&header->bss, "bss");
	swabby((unsigned long *)&header->syms, "syms");
	swabby((unsigned long *)&header->entry, "entry");
	swabby((unsigned long *)&header->spsz, "spsz");
	swabby((unsigned long *)&header->pcsz, "pcsz");

}

static int
 loadp9image(gzFile kernel_gfd, int xc_handle, u32 dom,
	     unsigned long *page_array,
	     unsigned long tot_pages, unsigned long *virt_load_addr,
	     unsigned long *ksize, unsigned long *symtab_addr,
	     unsigned long *symtab_len,
	     unsigned long *first_data_page, unsigned long *pdb_page, 
	     const char *cmdline);

#define P9ROUND (P9SIZE / 8)

#define L1_PROT (_PAGE_PRESENT|_PAGE_RW|_PAGE_ACCESSED)
#define L2_PROT (_PAGE_PRESENT|_PAGE_RW|_PAGE_ACCESSED|_PAGE_DIRTY|_PAGE_USER)

static int
setup_guest(int xc_handle,
	      u32 dom,
	      gzFile kernel_gfd,
	      unsigned long tot_pages,
	      unsigned long *virt_startinfo_addr,
	      unsigned long *virt_load_addr,
	      vcpu_guest_context_t * ctxt,
	      const char *cmdline,
	      unsigned long shared_info_frame, 
	      unsigned int control_evtchn,
	      int flags)
{
	l1_pgentry_t *vl1e = NULL;
	l2_pgentry_t *vl2tab = NULL, *vl2e = NULL;
	unsigned long *cpage_array = NULL;
	unsigned long *pte_array = NULL;
	unsigned long l2tab;
	unsigned long l1tab;
	unsigned long count;
	unsigned long symtab_addr = 0, symtab_len = 0;
	start_info_t *start_info;
	shared_info_t *shared_info;
	unsigned long ksize;
	mmu_t *mmu = NULL;
	int i;
	unsigned long first_page_after_kernel = 0, 
	  first_data_page = 0, 
	  page_array_page;
	unsigned long cpu0pdb, cpu0pte, cpu0ptelast;
	unsigned long /*last_pfn, */ tot_pte_pages;

	DPRINTF(("tot pages is %ld\n", tot_pages));
	if ((cpage_array = malloc(tot_pages * sizeof (unsigned long))) == NULL) {
		PERROR("Could not allocate cpage array");
		goto error_out;
	}

	if (xc_get_pfn_list(xc_handle, dom, cpage_array, tot_pages) != tot_pages) {
		PERROR("Could not get the page frame list");
		goto error_out;
	}

	for (i = 0; i < 64; i++)
		DPRINTF(("First %d page is 0x%lx\n", i, cpage_array[i]));

	tot_pte_pages = tot_pages >> 10;
	DPRINTF(("Page range is 0 to 0x%lx, which requires 0x%lx pte pages\n",
		 tot_pte_pages, tot_pte_pages));

	if (loadp9image(kernel_gfd, xc_handle, dom, cpage_array, tot_pages,
			virt_load_addr, &ksize, &symtab_addr, &symtab_len,
			&first_data_page, &first_page_after_kernel, cmdline))
		goto error_out;
	DPRINTF(("First data page is 0x%lx\n", first_data_page));
	DPRINTF(("First page after kernel is 0x%lx\n",
		 first_page_after_kernel));

	/*
	   NEED TO INCREMENT first page after kernel by:
	   + 1 (pdb)
	   + tot_pte_pages (pte)
	   + tot_pte_pages (page_array)
	 */
	/* SO, have to copy the first kernel pages pfns right into the 
	 * page_array, then do identity maps for the rest. 
	 */
	DPRINTF(("mapped kernel pages\n"));

	/* now loop over all ptes and store into the page_array, so as
	 * to get the identity map. 
	 */
	if ((pte_array =
	     malloc(tot_pte_pages * 1024 * sizeof (unsigned long))) == NULL) {
		PERROR("Could not allocate pte array");
		goto error_out;
	}

	/* plan 9 on startup expects a "l2" (xen parlance) at 0x2000, 
	 * this "l2" should have one PTE pointer for a va of 0x80000000. 
	 * and an l1 (PTEs to you) at 0x3000. (physical). 
	 * the PTEs should map the first 4M of memory. 
	 */
	/* get a physical address for the L2. This means take the PFN and 
	 * shift left.
	 */
	/* this terminology is plan 9 terminology. 
	 * pdb is essentially the Xen L2. 'Page Directory Block'? 
	 * I need to ask JMK.
	 * cpupte is the pte array. 
	 * Plan 9 counts on these being set up for cpu0. 
	 * SO: cpu0pdb (Xen L2)
	 * and cpupte  (Xen L1)
	 */
	/* cpu0pdb is right after kernel */
	cpu0pdb = first_page_after_kernel;
	/* cpu0pte comes right after cpu0pdb */
	cpu0pte = cpu0pdb + 1;
	/* number of the past cpu0pte page */
	cpu0ptelast = cpu0pte + tot_pte_pages - 1;
	/* first page of the page array (mfn) */
	page_array_page = cpu0ptelast + 1;

	DPRINTF(("cpu0pdb 0x%lx, cpu0pte 0x%lx cpu0ptelast 0x%lx\n", cpu0pdb,
		 cpu0pte, cpu0ptelast));
	l2tab = cpage_array[cpu0pdb] << PAGE_SHIFT;
	DPRINTF(("l2tab 0x%lx\n", l2tab));
	ctxt->pt_base = l2tab;

	/* get a physical address for the L1. This means take the PFN and 
	 * shift left.
	 */
	l1tab = cpage_array[cpu0pte] << PAGE_SHIFT;
	DPRINTF(("l1tab 0x%lx\n", l1tab));
	if ((mmu = init_mmu_updates(xc_handle, dom)) == NULL)
		goto error_out;
	DPRINTF(("now map in l2tab\n"));

	/* Initialise the page tables. */
	/* mmap in the l2tab */
	if ((vl2tab = xc_map_foreign_range(xc_handle, dom,
					   PAGE_SIZE, PROT_READ | PROT_WRITE,
					   l2tab >> PAGE_SHIFT)) == NULL)
		goto error_out;
	DPRINTF(("vl2tab 0x%p\n", vl2tab));
	/* now we have the cpu0pdb for the kernel, starting at 0x2000, 
	 * so we can plug in the physical pointer to the 0x3000 pte
	 */
	/* zero it */
	memset(vl2tab, 0, PAGE_SIZE);
	/* get a pointer in the l2tab for the virt_load_addr */
	DPRINTF(("&vl2tab[l2_table_offset(*virt_load_addr)] is 0x%p[0x%lx]\n",
		 &vl2tab[l2_table_offset(*virt_load_addr)],
		 l2_table_offset(*virt_load_addr)));

	vl2e = &vl2tab[l2_table_offset(*virt_load_addr)];

	/* OK, for all the available PTE, set the PTE pointer up */
	DPRINTF(("For i  = %ld to %ld ...\n", cpu0pte, cpu0ptelast));
	for (i = cpu0pte; i <= cpu0ptelast; i++) {
		DPRINTF(("Index %d Set %p to 0x%lx\n", i, vl2e,
			 (cpage_array[i] << PAGE_SHIFT) | L2_PROT));
		*vl2e++ = (cpage_array[i] << PAGE_SHIFT) | L2_PROT;
	}

	/* unmap it ... */
	munmap(vl2tab, PAGE_SIZE);

	/* for the pages from virt_load_pointer to the end of this 
	 * set of PTEs, map in the PFN for that VA
	 */
	for (vl1e = (l1_pgentry_t *) pte_array, count = 0;
	     count < tot_pte_pages * 1024; count++, vl1e++) {

		*vl1e = cpage_array[count];
		if (!cpage_array[count])
			continue;
		/* set in the PFN for this entry */
		*vl1e = (cpage_array[count] << PAGE_SHIFT) | L1_PROT;
/*
      DPRINTF (("vl1e # %d 0x%lx gets 0x%lx\n",
		count, vl1e, *vl1e));
*/
		if ((count >= cpu0pdb) && (count <= cpu0ptelast)) {
			//DPRINTF(("   Fix up page %d as it is in pte ville: ", count));
			*vl1e &= ~_PAGE_RW;
			DPRINTF(("0x%lx\n", *vl1e));
		}
		if ((count >= (0x100000 >> 12))
		    && (count < (first_data_page >> 12))) {
			//DPRINTF(("   Fix up page %d as it is in text ", count));
			*vl1e &= ~_PAGE_RW;
			//DPRINTF (("0x%lx\n", *vl1e));
		}
	}
	/* special thing. Pre-map the shared info page */
	vl1e = &pte_array[2];
	*vl1e = (shared_info_frame << PAGE_SHIFT) | L1_PROT;
	DPRINTF(("v1l1 %p, has value 0x%lx\n", vl1e, *(unsigned long *) vl1e));
	/* another special thing. VA 80005000 has to point to 80006000 */
	/* this is a Plan 9 thing -- the 'mach' pointer */
	/* 80005000 is the mach pointer per-cpu, and the actual
	 * mach pointers are 80006000, 80007000 etc. 
	 */
	vl1e = &pte_array[5];
	*vl1e = (cpage_array[6] << PAGE_SHIFT) | L1_PROT;

	/* OK, it's all set up, copy it in */
	memcpy_toguest(xc_handle, dom, pte_array,
		       (tot_pte_pages * 1024 * sizeof (unsigned long) /**/),
		       cpage_array, cpu0pte);

	/* We really need to have the vl1tab unmapped or the add_mmu_update
	 * below will fail bigtime. 
	 */
	/* Xen guys: remember my errors on domain exit? Something I'm doing
	 * wrong in here? We never did find out ...
	 */
	/* get rid of the entries we can not use ... */
	memcpy_toguest(xc_handle, dom, cpage_array,
		       (tot_pte_pages * 1024 * sizeof (unsigned long) /**/),
		       cpage_array, page_array_page);
	/* last chance to dump all of memory */
	// dumpit(xc_handle, dom, 0 /*0x100000>>12*/, tot_pages, cpage_array) ;
	/*
	 * Pin down l2tab addr as page dir page - causes hypervisor to provide
	 * correct protection for the page
	 */
	if (pin_table(xc_handle, MMUEXT_PIN_L2_TABLE, l2tab>>PAGE_SHIFT, dom))
		goto error_out;

	for (count = 0; count < tot_pages; count++) {
/*
      DPRINTF (("add_mmu_update(0x%x, 0x%x, 0x%x, %d)\n", xc_handle, mmu,
							   (cpage_array[count]
							    << PAGE_SHIFT) |
							   MMU_MACHPHYS_UPDATE,
							   count));
*/
		if (add_mmu_update(xc_handle, mmu,
				   (cpage_array[count] << PAGE_SHIFT) |
				   MMU_MACHPHYS_UPDATE, count))
			goto error_out;
		//DPRINTF(("Do the next one\n"));
	}
/*
 */

	//dumpit(pm_handle, 3, 4, page_array);
	/* put the virt_startinfo_addr at KZERO */
	/* just hard-code for now */
	*virt_startinfo_addr = 0x80000000;

	DPRINTF(("virt_startinfo_addr = 0x%lx\n", *virt_startinfo_addr));
	start_info = xc_map_foreign_range(xc_handle, dom,
					  PAGE_SIZE, PROT_READ | PROT_WRITE,
					  cpage_array[0]);
	DPRINTF(("startinfo = 0x%p\n", start_info));
	DPRINTF(("shared_info_frame is %lx\n", shared_info_frame));
	memset(start_info, 0, sizeof (*start_info));
	start_info->pt_base = 0x80000000 | cpu0pdb << PAGE_SHIFT;
	start_info->mfn_list = 0x80000000 | (page_array_page) << PAGE_SHIFT;
	DPRINTF(("mfn_list 0x%lx\n", start_info->mfn_list));
	start_info->mod_start = 0;
	start_info->mod_len = 0;
	start_info->nr_pages = tot_pte_pages * 1024;
	start_info->nr_pt_frames = tot_pte_pages + 1;
	start_info->shared_info = shared_info_frame;
	start_info->flags = 0;
	DPRINTF((" control event channel is %d\n", control_evtchn));
	start_info->domain_controller_evtchn = control_evtchn;
	strncpy((char *)start_info->cmd_line, cmdline, MAX_CMDLINE);
	start_info->cmd_line[MAX_CMDLINE - 1] = '\0';
	munmap(start_info, PAGE_SIZE);

	DPRINTF(("done setting up start_info\n"));
	DPRINTF(("shared_info_frame = 0x%lx\n", shared_info_frame));
	/* shared_info page starts its life empty. */

	shared_info = xc_map_foreign_range(xc_handle, dom,
					   PAGE_SIZE, PROT_READ | PROT_WRITE,
					   shared_info_frame);
	memset(shared_info, 0, PAGE_SIZE);
	/* Mask all upcalls... */
	DPRINTF(("mask all upcalls\n"));
	for (i = 0; i < MAX_VIRT_CPUS; i++)
		shared_info->vcpu_data[i].evtchn_upcall_mask = 1;
	munmap(shared_info, PAGE_SIZE);

	/* Send the page update requests down to the hypervisor. */
	DPRINTF(("send page update reqs down.\n"));
	if (finish_mmu_updates(xc_handle, mmu))
		goto error_out;

	//DPRINTF (("call dumpit.\n"));
	//dumpit(pm_handle, 0x100000>>12, tot_pages, page_array) ;
	//dumpit (pm_handle, 2, 0x100, page_array);
	free(mmu);

	/* we don't bother freeing anything at this point -- 
	 * we're exiting and it is pointless
	 */
	return 0;

      error_out:
	/* oh well we still free some things -- I oughtta nuke this */
	if (mmu != NULL)
		free(mmu);
	;
	return -1;
}

int
xc_plan9_build(int xc_handle,
	       u32 domid,
	       const char *image_name,
	       const char *cmdline,
	       unsigned int control_evtchn, unsigned long flags)
{
	dom0_op_t launch_op, op;
	unsigned long load_addr = 0;
	long tot_pages;
	int kernel_fd = -1;
	gzFile kernel_gfd = NULL;
	int rc, i;
	vcpu_guest_context_t st_ctxt, *ctxt = &st_ctxt;
	unsigned long virt_startinfo_addr;

	if ((tot_pages = xc_get_tot_pages(xc_handle, domid)) < 0) {
		PERROR("Could not find total pages for domain");
		return 1;
	}
	DPRINTF(("xc_get_tot_pages returns %ld pages\n", tot_pages));

	kernel_fd = open(image_name, O_RDONLY);
	if (kernel_fd < 0) {
		PERROR("Could not open kernel image");
		return 1;
	}

	if ((kernel_gfd = gzdopen(kernel_fd, "rb")) == NULL) {
		PERROR("Could not allocate decompression state for state file");
		close(kernel_fd);
		return 1;
	}

	DPRINTF(("xc_get_tot_pages returns %ld pages\n", tot_pages));
	if (mlock(&st_ctxt, sizeof (st_ctxt))) {
		PERROR("Unable to mlock ctxt");
		return 1;
	}

	op.cmd = DOM0_GETDOMAININFO;
	op.u.getdomaininfo.domain = (domid_t) domid;
        op.u.getdomaininfo.exec_domain = 0;
	op.u.getdomaininfo.ctxt = ctxt;
	if ((do_dom0_op(xc_handle, &op) < 0) ||
	    ((u32) op.u.getdomaininfo.domain != domid)) {
		PERROR("Could not get info on domain");
		goto error_out;
	}
	DPRINTF(("xc_get_tot_pages returns %ld pages\n", tot_pages));

	if (!(op.u.getdomaininfo.flags & DOMFLAGS_PAUSED)
	    || (op.u.getdomaininfo.ctxt->pt_base != 0)) {
		ERROR("Domain is already constructed");
		goto error_out;
	}

	DPRINTF(("xc_get_tot_pages returns %ld pages\n", tot_pages));
	if (setup_guest(xc_handle, domid, kernel_gfd, tot_pages,
			  &virt_startinfo_addr,
			  &load_addr, &st_ctxt, cmdline,
			  op.u.getdomaininfo.shared_info_frame,
			  control_evtchn, flags) < 0) {
		ERROR("Error constructing guest OS");
		goto error_out;
	}

	/* leave the leak in here for now
	   if ( kernel_fd >= 0 )
	   close(kernel_fd);
	   if( kernel_gfd )
	   gzclose(kernel_gfd);
	 */
	ctxt->flags = 0;

	/*
	 * Initial register values:
	 *  DS,ES,FS,GS = FLAT_KERNEL_DS
	 *       CS:EIP = FLAT_KERNEL_CS:start_pc
	 *       SS:ESP = FLAT_KERNEL_DS:start_stack
	 *          ESI = start_info
	 *  [EAX,EBX,ECX,EDX,EDI,EBP are zero]
	 *       EFLAGS = IF | 2 (bit 1 is reserved and should always be 1)
	 */
	ctxt->user_regs.ds = FLAT_KERNEL_DS;
	ctxt->user_regs.es = FLAT_KERNEL_DS;
	ctxt->user_regs.fs = FLAT_KERNEL_DS;
	ctxt->user_regs.gs = FLAT_KERNEL_DS;
	ctxt->user_regs.ss = FLAT_KERNEL_DS;
	ctxt->user_regs.cs = FLAT_KERNEL_CS;
	ctxt->user_regs.eip = load_addr;
	ctxt->user_regs.eip = 0x80100020;
	/* put stack at top of second page */
	ctxt->user_regs.esp = 0x80000000 + (STACKPAGE << PAGE_SHIFT);

	/* why is this set? */
	ctxt->user_regs.esi = ctxt->user_regs.esp;
	ctxt->user_regs.eflags = 1 << 9; /* Interrupt Enable */

	/* FPU is set up to default initial state. */
	memset(&ctxt->fpu_ctxt, 0, sizeof(ctxt->fpu_ctxt));

	/* Virtual IDT is empty at start-of-day. */
	for (i = 0; i < 256; i++) {
		ctxt->trap_ctxt[i].vector = i;
		ctxt->trap_ctxt[i].cs = FLAT_KERNEL_CS;
	}

#if defined(__i386__)
	ctxt->fast_trap_idx = 0;
#endif

	/* No LDT. */
	ctxt->ldt_ents = 0;

	/* Use the default Xen-provided GDT. */
	ctxt->gdt_ents = 0;

	/* Ring 1 stack is the initial stack. */
	/* put stack at top of second page */
	ctxt->kernel_ss = FLAT_KERNEL_DS;
	ctxt->kernel_sp = ctxt->user_regs.esp;

	/* No debugging. */
	memset(ctxt->debugreg, 0, sizeof (ctxt->debugreg));

	/* No callback handlers. */
#if defined(__i386__)
	ctxt->event_callback_cs     = FLAT_KERNEL_CS;
	ctxt->event_callback_eip    = 0;
	ctxt->failsafe_callback_cs  = FLAT_KERNEL_CS;
	ctxt->failsafe_callback_eip = 0;
#elif defined(__x86_64__)
	ctxt->event_callback_eip    = 0;
	ctxt->failsafe_callback_eip = 0;
	ctxt->syscall_callback_eip  = 0;
#endif

	memset(&launch_op, 0, sizeof (launch_op));

	launch_op.u.setdomaininfo.domain = (domid_t) domid;
	launch_op.u.setdomaininfo.exec_domain = 0;
	//  launch_op.u.setdomaininfo.num_vifs = 1;
	launch_op.u.setdomaininfo.ctxt = ctxt;
	launch_op.cmd = DOM0_SETDOMAININFO;
	rc = do_dom0_op(xc_handle, &launch_op);

	fprintf(stderr, "RC is %d\n", rc);
	return rc;

      error_out:
	if (kernel_fd >= 0)
		close(kernel_fd);
	if (kernel_gfd)
		gzclose(kernel_gfd);

	return -1;
}

/* 
 * Plan 9 memory layout (initial)
 * ----------------
 * | info from xen| @0
 * ---------------|<--- boot args (start at 0x1200 + 64)
 * | stack        |
 * ----------------<--- page 2
 * | empty        |
 * ---------------<---- page 5 MACHADDR (always points to machp[cpuno]
 * | aliased      |
 * ---------------<----- page 6 CPU0MACH
 * | CPU0MACH     |
 * ----------------
 * | empty        |
 * ---------------- *virt_load_addr = ehdr.e_entry (0x80100000)
 * | kernel       |
 * |              |
 * ---------------- <----- page aligned boundary.
 * | data         |
 * |              | 
 * ----------------
 * | bss          |
 * ----------------<---  end of kernel (page aligned)
 * | PMD cpu0pdb  |
 * ----------------<--- page +1
 * | PTE cpu0pte  |
 * ----------------<--- page (tot_pte_pages)/1024
 * | page_array   |
 * ---------------- <--- page (tot_pte_pages)/1024
 * | empty to TOM |
 * ----------------
 */

static int
loadp9image(gzFile kernel_gfd, int xc_handle, u32 dom,
	    unsigned long *page_array,
	    unsigned long tot_pages, unsigned long *virt_load_addr,
	    unsigned long *ksize, unsigned long *symtab_addr,
	    unsigned long *symtab_len,
	    unsigned long *first_data_page, unsigned long *pdb_page, 
	    const char *cmdline)
{
	unsigned long datapage;
	Exec ehdr;

	char *p;
	unsigned long maxva;
	int curpos, ret;
	PAGE *image = 0;
	unsigned long image_tot_pages = 0;
	unsigned long textround;
	static PAGE args;

	ret = -1;

	p = NULL;
	maxva = 0;

	if (gzread(kernel_gfd, &ehdr, sizeof (Exec)) != sizeof (Exec)) {
		PERROR("Error reading kernel image P9 header.");
		goto out;
	}

	plan9header(&ehdr);
	curpos = sizeof (Exec);

	if (ehdr.magic != I_MAGIC) {
		PERROR("Image does not have an P9 header.");
		goto out;
	}

	textround = ((ehdr.text + 0x20 + 4095) >> 12) << 12;
	*first_data_page = 0x100000 + textround;
	DPRINTF(("ehrd.text is 0x%lx, textround is 0x%lx\n",
		 ehdr.text, textround));

	image_tot_pages =
	    (textround + ehdr.data + ehdr.bss + PAGE_SIZE - 1) >> PAGE_SHIFT;
	DPRINTF(("tot pages is %ld\n", image_tot_pages));

	*virt_load_addr = 0x80100000;

	if ((*virt_load_addr & (PAGE_SIZE - 1)) != 0) {
		ERROR("We can only deal with page-aligned load addresses");
		goto out;
	}

	if ((*virt_load_addr + (image_tot_pages << PAGE_SHIFT)) >
	    HYPERVISOR_VIRT_START) {
		ERROR("Cannot map all domain memory without hitting Xen space");
		goto out;
	}

	/* just malloc an image that is image_tot_pages  in size. Then read in 
	 * the image -- text, data, -- to page-rounded alignments. 
	 * then copy into xen .
	 * this gets BSS zeroed for free
	 */
	DPRINTF(("Allocate %ld bytes\n", image_tot_pages * sizeof (*image)));
	image = calloc(image_tot_pages, sizeof (*image));
	if (!image)
		return blah("alloc data");
	/* text starts at 0x20, after the header, just like Unix long ago */
	if (gzread(kernel_gfd, &image[0].data[sizeof (Exec)], ehdr.text) <
	    ehdr.text)
		return blah("read text");
	DPRINTF(("READ TEXT %ld bytes\n", ehdr.text));
	datapage = ((ehdr.text + sizeof (Exec)) / PAGE_SIZE) + 1;
	if (gzread(kernel_gfd, image[datapage].data, ehdr.data) < ehdr.data)
		return blah("read data");
	DPRINTF(("READ DATA %ld bytes\n", ehdr.data));

	/* nice contig stuff */
	/* oops need to start at 0x100000 */

	ret = memcpy_toguest(xc_handle, dom,
			     image, image_tot_pages * 4096, page_array, 0x100);
	DPRINTF(("done copying kernel to guest memory\n"));

	/* now do the bootargs */
	/* in plan 9, the x=y bootargs start at 0x1200 + 64 in real memory */
	/* we'll copy to page 1, so we offset into the page struct at 
	 * 0x200 + 64 
	 */
	memset(&args, 0, sizeof(args));
	memcpy(&args.data[0x200 + 64], cmdline, strlen(cmdline));
	printf("Copied :%s: to page for args\n", cmdline);
	ret = memcpy_toguest(xc_handle, dom, &args, sizeof(args), page_array,1);
	//dumpit(xc_handle, dom, 0 /*0x100000>>12*/, 4, page_array) ;
      out:
	if (image)
		free(image);
	*pdb_page = image_tot_pages + (0x100000 >> PAGE_SHIFT);
	return ret;
}
