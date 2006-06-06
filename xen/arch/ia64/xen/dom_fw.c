/*
 *  Xen domain firmware emulation support
 *  Copyright (C) 2004 Hewlett-Packard Co.
 *       Dan Magenheimer (dan.magenheimer@hp.com)
 *
 * Copyright (c) 2006 Isaku Yamahata <yamahata at valinux co jp>
 *                    VA Linux Systems Japan K.K.
 *                    dom0 vp model support
 */

#include <xen/config.h>
#include <asm/system.h>
#include <asm/pgalloc.h>

#include <linux/efi.h>
#include <linux/sort.h>
#include <asm/io.h>
#include <asm/pal.h>
#include <asm/sal.h>
#include <asm/meminit.h>
#include <asm/fpswa.h>
#include <xen/compile.h>
#include <xen/acpi.h>

#include <asm/dom_fw.h>

static struct ia64_boot_param *dom_fw_init(struct domain *, const char *,int,char *,int);
extern struct domain *dom0;
extern unsigned long dom0_start;

extern unsigned long running_on_sim;


unsigned long dom_fw_base_mpa = -1;
unsigned long imva_fw_base = -1;

// return domain (meta)physical address for a given imva
// this function is a call-back from dom_fw_init
static unsigned long
dom_pa(unsigned long imva)
{
	if (dom_fw_base_mpa == -1 || imva_fw_base == -1) {
		printf("dom_pa: uninitialized! (spinning...)\n");
		while(1);
	}
	if (imva - imva_fw_base > PAGE_SIZE) {
		printf("dom_pa: bad offset! imva=0x%lx, imva_fw_base=0x%lx (spinning...)\n",
			imva, imva_fw_base);
		while(1);
	}
	return dom_fw_base_mpa + (imva - imva_fw_base);
}

// allocate a page for fw
// build_physmap_table() which is called by new_thread()
// does for domU.
#define ASSIGN_NEW_DOMAIN_PAGE_IF_DOM0(d, mpaddr)   \
    do {                                            \
        if ((d) == dom0) {                          \
            assign_new_domain0_page((d), (mpaddr)); \
        }                                           \
    } while (0)

// builds a hypercall bundle at domain physical address
static void dom_fpswa_hypercall_patch(struct domain *d)
{
	unsigned long *entry_imva, *patch_imva;
	unsigned long entry_paddr = FW_HYPERCALL_FPSWA_ENTRY_PADDR;
	unsigned long patch_paddr = FW_HYPERCALL_FPSWA_PATCH_PADDR;

#ifndef CONFIG_XEN_IA64_DOM0_VP
	if (d == dom0) {
		entry_paddr += dom0_start;
		patch_paddr += dom0_start;
	}
#endif
	ASSIGN_NEW_DOMAIN_PAGE_IF_DOM0(d, entry_paddr);
	ASSIGN_NEW_DOMAIN_PAGE_IF_DOM0(d, patch_paddr);
	entry_imva = domain_mpa_to_imva(d, entry_paddr);
	patch_imva = domain_mpa_to_imva(d, patch_paddr);

	*entry_imva++ = patch_paddr;
	*entry_imva   = 0;
	build_hypercall_bundle(patch_imva, d->arch.breakimm, FW_HYPERCALL_FPSWA, 1);
}

// builds a hypercall bundle at domain physical address
static void dom_efi_hypercall_patch(struct domain *d, unsigned long paddr, unsigned long hypercall)
{
	unsigned long *imva;

#ifndef CONFIG_XEN_IA64_DOM0_VP
	if (d == dom0) paddr += dom0_start;
#endif
	ASSIGN_NEW_DOMAIN_PAGE_IF_DOM0(d, paddr);
	imva = domain_mpa_to_imva(d, paddr);
	build_hypercall_bundle(imva, d->arch.breakimm, hypercall, 1);
}

// builds a hypercall bundle at domain physical address
static void dom_fw_hypercall_patch(struct domain *d, unsigned long paddr, unsigned long hypercall,unsigned long ret)
{
	unsigned long *imva;

	ASSIGN_NEW_DOMAIN_PAGE_IF_DOM0(d, paddr);
	imva = domain_mpa_to_imva(d, paddr);
	build_hypercall_bundle(imva, d->arch.breakimm, hypercall, ret);
}

static void dom_fw_pal_hypercall_patch(struct domain *d, unsigned long paddr)
{
	unsigned long *imva;

	ASSIGN_NEW_DOMAIN_PAGE_IF_DOM0(d, paddr);
	imva = domain_mpa_to_imva(d, paddr);
	build_pal_hypercall_bundles(imva, d->arch.breakimm, FW_HYPERCALL_PAL_CALL);
}


// FIXME: This is really a hack: Forcing the boot parameter block
// at domain mpaddr 0 page, then grabbing only the low bits of the
// Xen imva, which is the offset into the page
unsigned long dom_fw_setup(struct domain *d, const char *args, int arglen)
{
	struct ia64_boot_param *bp;

	dom_fw_base_mpa = 0;
#ifndef CONFIG_XEN_IA64_DOM0_VP
	if (d == dom0) dom_fw_base_mpa += dom0_start;
#endif
	ASSIGN_NEW_DOMAIN_PAGE_IF_DOM0(d, dom_fw_base_mpa);
	imva_fw_base = (unsigned long) domain_mpa_to_imva(d, dom_fw_base_mpa);
	bp = dom_fw_init(d, args, arglen, (char *) imva_fw_base, PAGE_SIZE);
	return dom_pa((unsigned long) bp);
}


/* the following heavily leveraged from linux/arch/ia64/hp/sim/fw-emu.c */

#define NFUNCPTRS 20

static void print_md(efi_memory_desc_t *md)
{
#if 1
	printk("domain mem: type=%2u, attr=0x%016lx, range=[0x%016lx-0x%016lx) (%luMB)\n",
		md->type, md->attribute, md->phys_addr,
		md->phys_addr + (md->num_pages << EFI_PAGE_SHIFT),
		md->num_pages >> (20 - EFI_PAGE_SHIFT));
#endif
}

static u32 lsapic_nbr;

/* Modify lsapic table.  Provides LPs.  */
static int 
acpi_update_lsapic (acpi_table_entry_header *header, const unsigned long end)
{
	struct acpi_table_lsapic *lsapic;
	int enable;

	lsapic = (struct acpi_table_lsapic *) header;
	if (!lsapic)
		return -EINVAL;

	if (lsapic_nbr < MAX_VIRT_CPUS && dom0->vcpu[lsapic_nbr] != NULL)
		enable = 1;
	else
		enable = 0;
	if (lsapic->flags.enabled && enable) {
		printk("enable lsapic entry: 0x%lx\n", (u64)lsapic);
		lsapic_nbr++;
	} else if (lsapic->flags.enabled) {
		printk("DISABLE lsapic entry: 0x%lx\n", (u64)lsapic);
		lsapic->flags.enabled = 0;
	}
	return 0;
}

static u8
generate_acpi_checksum(void *tbl, unsigned long len)
{
	u8 *ptr, sum = 0;

	for (ptr = tbl; len > 0 ; len--, ptr++)
		sum += *ptr;

	return 0 - sum;
}

static int
acpi_update_madt_checksum (unsigned long phys_addr, unsigned long size)
{
	struct acpi_table_madt* acpi_madt;

	if (!phys_addr || !size)
		return -EINVAL;

	acpi_madt = (struct acpi_table_madt *) __va(phys_addr);
	acpi_madt->header.checksum = 0;
	acpi_madt->header.checksum = generate_acpi_checksum(acpi_madt, size);

	return 0;
}

/* base is physical address of acpi table */
static void touch_acpi_table(void)
{
	lsapic_nbr = 0;
	if (acpi_table_parse_madt(ACPI_MADT_LSAPIC, acpi_update_lsapic, 0) < 0)
		printk("Error parsing MADT - no LAPIC entires\n");
	acpi_table_parse(ACPI_APIC, acpi_update_madt_checksum);

	return;
}

struct fake_acpi_tables {
	struct acpi20_table_rsdp rsdp;
	struct xsdt_descriptor_rev2 xsdt;
	u64 madt_ptr;
	struct fadt_descriptor_rev2 fadt;
	struct facs_descriptor_rev2 facs;
	struct acpi_table_header dsdt;
	u8 aml[8 + 11 * MAX_VIRT_CPUS];
	struct acpi_table_madt madt;
	struct acpi_table_lsapic lsapic[MAX_VIRT_CPUS];
	u8 pm1a_evt_blk[4];
	u8 pm1a_cnt_blk[1];
	u8 pm_tmr_blk[4];
};

/* Create enough of an ACPI structure to make the guest OS ACPI happy. */
static void
dom_fw_fake_acpi(struct domain *d, struct fake_acpi_tables *tables)
{
	struct acpi20_table_rsdp *rsdp = &tables->rsdp;
	struct xsdt_descriptor_rev2 *xsdt = &tables->xsdt;
	struct fadt_descriptor_rev2 *fadt = &tables->fadt;
	struct facs_descriptor_rev2 *facs = &tables->facs;
	struct acpi_table_header *dsdt = &tables->dsdt;
	struct acpi_table_madt *madt = &tables->madt;
	struct acpi_table_lsapic *lsapic = tables->lsapic;
	int i;
	int aml_len;

	memset(tables, 0, sizeof(struct fake_acpi_tables));

	/* setup XSDT (64bit version of RSDT) */
	strncpy(xsdt->signature, XSDT_SIG, 4);
	/* XSDT points to both the FADT and the MADT, so add one entry */
	xsdt->length = sizeof(struct xsdt_descriptor_rev2) + sizeof(u64);
	xsdt->revision = 1;
	strcpy(xsdt->oem_id, "XEN");
	strcpy(xsdt->oem_table_id, "Xen/ia64");
	strcpy(xsdt->asl_compiler_id, "XEN");
	xsdt->asl_compiler_revision = (XEN_VERSION<<16)|(XEN_SUBVERSION);

	xsdt->table_offset_entry[0] = dom_pa((unsigned long) fadt);
	tables->madt_ptr = dom_pa((unsigned long) madt);

	xsdt->checksum = generate_acpi_checksum(xsdt, xsdt->length);

	/* setup FADT */
	strncpy(fadt->signature, FADT_SIG, 4);
	fadt->length = sizeof(struct fadt_descriptor_rev2);
	fadt->revision = FADT2_REVISION_ID;
	strcpy(fadt->oem_id, "XEN");
	strcpy(fadt->oem_table_id, "Xen/ia64");
	strcpy(fadt->asl_compiler_id, "XEN");
	fadt->asl_compiler_revision = (XEN_VERSION<<16)|(XEN_SUBVERSION);

	strncpy(facs->signature, FACS_SIG, 4);
	facs->version = 1;
	facs->length = sizeof(struct facs_descriptor_rev2);

	fadt->xfirmware_ctrl = dom_pa((unsigned long) facs);
	fadt->Xdsdt = dom_pa((unsigned long) dsdt);

	/*
	 * All of the below FADT entries are filled it to prevent warnings
	 * from sanity checks in the ACPI CA.  Emulate required ACPI hardware
	 * registers in system memory.
	 */
	fadt->pm1_evt_len = 4;
	fadt->xpm1a_evt_blk.address_space_id = ACPI_ADR_SPACE_SYSTEM_MEMORY;
	fadt->xpm1a_evt_blk.register_bit_width = 8;
	fadt->xpm1a_evt_blk.address = dom_pa((unsigned long) &tables->pm1a_evt_blk);
	fadt->pm1_cnt_len = 1;
	fadt->xpm1a_cnt_blk.address_space_id = ACPI_ADR_SPACE_SYSTEM_MEMORY;
	fadt->xpm1a_cnt_blk.register_bit_width = 8;
	fadt->xpm1a_cnt_blk.address = dom_pa((unsigned long) &tables->pm1a_cnt_blk);
	fadt->pm_tm_len = 4;
	fadt->xpm_tmr_blk.address_space_id = ACPI_ADR_SPACE_SYSTEM_MEMORY;
	fadt->xpm_tmr_blk.register_bit_width = 8;
	fadt->xpm_tmr_blk.address = dom_pa((unsigned long) &tables->pm_tmr_blk);

	fadt->checksum = generate_acpi_checksum(fadt, fadt->length);

	/* setup RSDP */
	strncpy(rsdp->signature, RSDP_SIG, 8);
	strcpy(rsdp->oem_id, "XEN");
	rsdp->revision = 2; /* ACPI 2.0 includes XSDT */
	rsdp->length = sizeof(struct acpi20_table_rsdp);
	rsdp->xsdt_address = dom_pa((unsigned long) xsdt);

	rsdp->checksum = generate_acpi_checksum(rsdp,
	                                        ACPI_RSDP_CHECKSUM_LENGTH);
	rsdp->ext_checksum = generate_acpi_checksum(rsdp, rsdp->length);

	/* setup DSDT with trivial namespace. */ 
	strncpy(dsdt->signature, DSDT_SIG, 4);
	dsdt->revision = 1;
	strcpy(dsdt->oem_id, "XEN");
	strcpy(dsdt->oem_table_id, "Xen/ia64");
	strcpy(dsdt->asl_compiler_id, "XEN");
	dsdt->asl_compiler_revision = (XEN_VERSION<<16)|(XEN_SUBVERSION);

	/* Trivial namespace, avoids ACPI CA complaints */
	tables->aml[0] = 0x10; /* Scope */
	tables->aml[1] = 0x40; /* length/offset to next object (patched) */
	tables->aml[2] = 0x00;
	strncpy((char *)&tables->aml[3], "_SB_", 4);

	/* The processor object isn't absolutely necessary, revist for SMP */
	aml_len = 7;
	for (i = 0; i < 3; i++) {
		unsigned char *p = tables->aml + aml_len;
		p[0] = 0x5b; /* processor object */
		p[1] = 0x83;
		p[2] = 0x0b; /* next */
		p[3] = 'C';
		p[4] = 'P';
		snprintf ((char *)p + 5, 3, "%02x", i);
		if (i < 16)
			p[5] = 'U';
		p[7] = i;	/* acpi_id */
		p[8] = 0;	/* pblk_addr */
		p[9] = 0;
		p[10] = 0;
		p[11] = 0;
		p[12] = 0;	/* pblk_len */
		aml_len += 13;
	}
	tables->aml[1] = 0x40 + ((aml_len - 1) & 0x0f);
	tables->aml[2] = (aml_len - 1) >> 4;
	dsdt->length = sizeof(struct acpi_table_header) + aml_len;
	dsdt->checksum = generate_acpi_checksum(dsdt, dsdt->length);

	/* setup MADT */
	strncpy(madt->header.signature, APIC_SIG, 4);
	madt->header.revision = 2;
	madt->header.length = sizeof(struct acpi_table_madt) +
		MAX_VIRT_CPUS * sizeof(struct acpi_table_lsapic);
	strcpy(madt->header.oem_id, "XEN");
	strcpy(madt->header.oem_table_id, "Xen/ia64");
	strcpy(madt->header.asl_compiler_id, "XEN");
	madt->header.asl_compiler_revision = (XEN_VERSION<<16)|(XEN_SUBVERSION);

	/* An LSAPIC entry describes a CPU.  */
	for (i = 0; i < MAX_VIRT_CPUS; i++) {
		lsapic[i].header.type = ACPI_MADT_LSAPIC;
		lsapic[i].header.length = sizeof(struct acpi_table_lsapic);
		lsapic[i].acpi_id = i;
		lsapic[i].id = i;
		lsapic[i].eid = 0;
		lsapic[i].flags.enabled = (d->vcpu[i] != NULL);
	}

	madt->header.checksum = generate_acpi_checksum(madt,
	                                               madt->header.length);
	return;
}

#define NUM_EFI_SYS_TABLES 6
#define NUM_MEM_DESCS	64 //large enough

struct dom0_passthrough_arg {
#ifdef CONFIG_XEN_IA64_DOM0_VP
    struct domain*      d;
    int                 flags;
#endif
    efi_memory_desc_t *md;
    int*                i;
};

static int
dom_fw_dom0_passthrough(efi_memory_desc_t *md, void *arg__)
{
    struct dom0_passthrough_arg* arg = (struct dom0_passthrough_arg*)arg__;
    unsigned long paddr;

#ifdef CONFIG_XEN_IA64_DOM0_VP
    struct domain* d = arg->d;
    u64 start = md->phys_addr;
    u64 size = md->num_pages << EFI_PAGE_SHIFT;

    if (md->type == EFI_MEMORY_MAPPED_IO ||
        md->type == EFI_MEMORY_MAPPED_IO_PORT_SPACE) {

        //XXX some machine has large mmio area whose size is about several TB.
        //    It requires impractical memory to map such a huge region
        //    to a domain.
        //    For now we don't map it, but later we must fix this.
        if (md->type == EFI_MEMORY_MAPPED_IO && (size > 0x100000000UL))
            return 0;

        paddr = assign_domain_mmio_page(d, start, size);
    } else
        paddr = assign_domain_mach_page(d, start, size, arg->flags);
#else
    paddr = md->phys_addr;
#endif

    BUG_ON(md->type != EFI_RUNTIME_SERVICES_CODE &&
           md->type != EFI_RUNTIME_SERVICES_DATA &&
           md->type != EFI_ACPI_RECLAIM_MEMORY &&
           md->type != EFI_MEMORY_MAPPED_IO &&
           md->type != EFI_MEMORY_MAPPED_IO_PORT_SPACE);

    arg->md->type = md->type;
    arg->md->pad = 0;
    arg->md->phys_addr = paddr;
    arg->md->virt_addr = 0;
    arg->md->num_pages = md->num_pages;
    arg->md->attribute = md->attribute;
    print_md(arg->md);

    (*arg->i)++;
    arg->md++;
    return 0;
}

/*
 * Create dom0 MDT entries for conventional memory below 1MB.  Without
 * this Linux will assume VGA is present because 0xA0000 will always
 * be either a hole in the MDT or an I/O region via the passthrough.
 */
static int
dom_fw_dom0_lowmem(efi_memory_desc_t *md, void *arg__)
{
    struct dom0_passthrough_arg* arg = (struct dom0_passthrough_arg*)arg__;
    u64 end = md->phys_addr + (md->num_pages << EFI_PAGE_SHIFT);

    BUG_ON(md->type != EFI_CONVENTIONAL_MEMORY);

    if (md->phys_addr >= 1*MB)
        return 0;

    if (end > 1*MB)
        end = 1*MB;

    arg->md->type = md->type;
    arg->md->pad = 0;
    arg->md->phys_addr = md->phys_addr;
    arg->md->virt_addr = 0;
    arg->md->num_pages = (end - md->phys_addr) >> EFI_PAGE_SHIFT;
    arg->md->attribute = md->attribute;
    print_md(arg->md);

    (*arg->i)++;
    arg->md++;
    return 0;
}

static int
efi_mdt_cmp(const void *a, const void *b)
{
	const efi_memory_desc_t *x = a, *y = b;

	if (x->phys_addr > y->phys_addr)
		return 1;
	if (x->phys_addr < y->phys_addr)
		return -1;

	// num_pages == 0 is allowed.
	if (x->num_pages > y->num_pages)
		return 1;
	if (x->num_pages < y->num_pages)
		return -1;

	return 0;
}

static struct ia64_boot_param *
dom_fw_init (struct domain *d, const char *args, int arglen, char *fw_mem, int fw_mem_size)
{
	efi_system_table_t *efi_systab;
	efi_runtime_services_t *efi_runtime;
	efi_config_table_t *efi_tables;
	struct ia64_sal_systab *sal_systab;
	struct ia64_sal_desc_entry_point *sal_ed;
	struct ia64_sal_desc_ap_wakeup *sal_wakeup;
	fpswa_interface_t *fpswa_inf;
	efi_memory_desc_t *efi_memmap, *md;
	struct ia64_boot_param *bp;
	unsigned long *pfn;
	unsigned char checksum = 0;
	char *cp, *cmd_line, *fw_vendor;
	int i = 0;
	unsigned long maxmem = (d->max_pages - d->arch.sys_pgnr) * PAGE_SIZE;
#ifdef CONFIG_XEN_IA64_DOM0_VP
	const unsigned long start_mpaddr = 0;
#else
	const unsigned long start_mpaddr = ((d==dom0)?dom0_start:0);
#endif

#	define MAKE_MD(typ, attr, start, end, abs) 	\
	do {						\
		md = efi_memmap + i++;			\
		md->type = typ;				\
		md->pad = 0;				\
		md->phys_addr = abs ? start : start_mpaddr + start;	\
		md->virt_addr = 0;			\
		md->num_pages = (end - start) >> 12;	\
		md->attribute = attr;			\
		print_md(md);				\
	} while (0)

/* FIXME: should check size but for now we have a whole MB to play with.
   And if stealing code from fw-emu.c, watch out for new fw_vendor on the end!
	if (fw_mem_size < sizeof(fw_mem_proto)) {
		printf("sys_fw_init: insufficient space for fw_mem\n");
		return 0;
	}
*/
	memset(fw_mem, 0, fw_mem_size);

	cp = fw_mem;
	efi_systab  = (void *) cp; cp += sizeof(*efi_systab);
	efi_runtime = (void *) cp; cp += sizeof(*efi_runtime);
	efi_tables  = (void *) cp; cp += NUM_EFI_SYS_TABLES * sizeof(*efi_tables);
	sal_systab  = (void *) cp; cp += sizeof(*sal_systab);
	sal_ed      = (void *) cp; cp += sizeof(*sal_ed);
	sal_wakeup  = (void *) cp; cp += sizeof(*sal_wakeup);
	fpswa_inf   = (void *) cp; cp += sizeof(*fpswa_inf);
	efi_memmap  = (void *) cp; cp += NUM_MEM_DESCS*sizeof(*efi_memmap);
	bp	    = (void *) cp; cp += sizeof(*bp);
	pfn         = (void *) cp; cp += NFUNCPTRS * 2 * sizeof(pfn);
	cmd_line    = (void *) cp;

	/* Initialise for EFI_SET_VIRTUAL_ADDRESS_MAP emulation */
	d->arch.efi_runtime = efi_runtime;
	d->arch.fpswa_inf   = fpswa_inf;

	if (args) {
		if (arglen >= 1024)
			arglen = 1023;
		memcpy(cmd_line, args, arglen);
	} else {
		arglen = 0;
	}
	cmd_line[arglen] = '\0';

	memset(efi_systab, 0, sizeof(efi_systab));
	efi_systab->hdr.signature = EFI_SYSTEM_TABLE_SIGNATURE;
	efi_systab->hdr.revision  = EFI_SYSTEM_TABLE_REVISION;
	efi_systab->hdr.headersize = sizeof(efi_systab->hdr);
	cp = fw_vendor = &cmd_line[arglen] + (2-(arglen&1)); // round to 16-bit boundary
#define FW_VENDOR "X\0e\0n\0/\0i\0a\0\066\0\064\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
	cp += sizeof(FW_VENDOR) + (8-((unsigned long)cp & 7)); // round to 64-bit boundary

	memcpy(fw_vendor,FW_VENDOR,sizeof(FW_VENDOR));
	efi_systab->fw_vendor = dom_pa((unsigned long) fw_vendor);
	
	efi_systab->fw_revision = 1;
	efi_systab->runtime = (void *) dom_pa((unsigned long) efi_runtime);
	efi_systab->nr_tables = NUM_EFI_SYS_TABLES;
	efi_systab->tables = dom_pa((unsigned long) efi_tables);

	efi_runtime->hdr.signature = EFI_RUNTIME_SERVICES_SIGNATURE;
	efi_runtime->hdr.revision = EFI_RUNTIME_SERVICES_REVISION;
	efi_runtime->hdr.headersize = sizeof(efi_runtime->hdr);
#define EFI_HYPERCALL_PATCH(tgt,call) do { \
    dom_efi_hypercall_patch(d,FW_HYPERCALL_##call##_PADDR,FW_HYPERCALL_##call); \
    tgt = dom_pa((unsigned long) pfn); \
    *pfn++ = FW_HYPERCALL_##call##_PADDR + start_mpaddr; \
    *pfn++ = 0; \
    } while (0)

	EFI_HYPERCALL_PATCH(efi_runtime->get_time,EFI_GET_TIME);
	EFI_HYPERCALL_PATCH(efi_runtime->set_time,EFI_SET_TIME);
	EFI_HYPERCALL_PATCH(efi_runtime->get_wakeup_time,EFI_GET_WAKEUP_TIME);
	EFI_HYPERCALL_PATCH(efi_runtime->set_wakeup_time,EFI_SET_WAKEUP_TIME);
	EFI_HYPERCALL_PATCH(efi_runtime->set_virtual_address_map,EFI_SET_VIRTUAL_ADDRESS_MAP);
	EFI_HYPERCALL_PATCH(efi_runtime->get_variable,EFI_GET_VARIABLE);
	EFI_HYPERCALL_PATCH(efi_runtime->get_next_variable,EFI_GET_NEXT_VARIABLE);
	EFI_HYPERCALL_PATCH(efi_runtime->set_variable,EFI_SET_VARIABLE);
	EFI_HYPERCALL_PATCH(efi_runtime->get_next_high_mono_count,EFI_GET_NEXT_HIGH_MONO_COUNT);
	EFI_HYPERCALL_PATCH(efi_runtime->reset_system,EFI_RESET_SYSTEM);

	efi_tables[0].guid = SAL_SYSTEM_TABLE_GUID;
	efi_tables[0].table = dom_pa((unsigned long) sal_systab);
	for (i = 1; i < NUM_EFI_SYS_TABLES; i++) {
		efi_tables[i].guid = NULL_GUID;
		efi_tables[i].table = 0;
	}
	if (d == dom0) {
#ifdef CONFIG_XEN_IA64_DOM0_VP
# define ASSIGN_DOMAIN_MACH_PAGE(d, p) \
        assign_domain_mach_page((d), (p), PAGE_SIZE, ASSIGN_readonly)
#else
# define ASSIGN_DOMAIN_MACH_PAGE(d, p) (p)
#endif

		printf("Domain0 EFI passthrough:");
		i = 1;
		if (efi.mps) {
			efi_tables[i].guid = MPS_TABLE_GUID;
			efi_tables[i].table = ASSIGN_DOMAIN_MACH_PAGE(d, __pa(efi.mps));
			printf(" MPS=0x%lx",efi_tables[i].table);
			i++;
		}

		touch_acpi_table();

		if (efi.acpi20) {
			efi_tables[i].guid = ACPI_20_TABLE_GUID;
			efi_tables[i].table = ASSIGN_DOMAIN_MACH_PAGE(d, __pa(efi.acpi20));
			printf(" ACPI 2.0=0x%lx",efi_tables[i].table);
			i++;
		}
		if (efi.acpi) {
			efi_tables[i].guid = ACPI_TABLE_GUID;
			efi_tables[i].table = ASSIGN_DOMAIN_MACH_PAGE(d, __pa(efi.acpi));
			printf(" ACPI=0x%lx",efi_tables[i].table);
			i++;
		}
		if (efi.smbios) {
			efi_tables[i].guid = SMBIOS_TABLE_GUID;
			efi_tables[i].table = ASSIGN_DOMAIN_MACH_PAGE(d, __pa(efi.smbios));
			printf(" SMBIOS=0x%lx",efi_tables[i].table);
			i++;
		}
		if (efi.hcdp) {
			efi_tables[i].guid = HCDP_TABLE_GUID;
			efi_tables[i].table = ASSIGN_DOMAIN_MACH_PAGE(d, __pa(efi.hcdp));
			printf(" HCDP=0x%lx",efi_tables[i].table);
			i++;
		}
		printf("\n");
	} else {
		printf("DomainU EFI build up:");
		i = 1;

		if ((unsigned long)fw_mem + fw_mem_size - (unsigned long)cp >=
		    sizeof(struct fake_acpi_tables)) {
			struct fake_acpi_tables *acpi_tables;

			acpi_tables = (void *)cp;
			cp += sizeof(struct fake_acpi_tables);
			dom_fw_fake_acpi(d, acpi_tables);

			efi_tables[i].guid = ACPI_20_TABLE_GUID;
			efi_tables[i].table = dom_pa((unsigned long) acpi_tables);
			printf(" ACPI 2.0=0x%lx",efi_tables[i].table);
			i++;
		}
		printf("\n");
	}

	/* fill in the SAL system table: */
	memcpy(sal_systab->signature, "SST_", 4);
	sal_systab->size = sizeof(*sal_systab);
	sal_systab->sal_rev_minor = 1;
	sal_systab->sal_rev_major = 0;
	sal_systab->entry_count = 2;

	strcpy((char *)sal_systab->oem_id, "Xen/ia64");
	strcpy((char *)sal_systab->product_id, "Xen/ia64");

	/* fill in an entry point: */
	sal_ed->type = SAL_DESC_ENTRY_POINT;
	sal_ed->pal_proc = FW_HYPERCALL_PAL_CALL_PADDR + start_mpaddr;
	dom_fw_pal_hypercall_patch (d, sal_ed->pal_proc);
	sal_ed->sal_proc = FW_HYPERCALL_SAL_CALL_PADDR + start_mpaddr;
	dom_fw_hypercall_patch (d, sal_ed->sal_proc, FW_HYPERCALL_SAL_CALL, 1);
	sal_ed->gp = 0;  // will be ignored

	/* SAL return point.  */
	d->arch.sal_return_addr = FW_HYPERCALL_SAL_RETURN_PADDR + start_mpaddr;
	dom_fw_hypercall_patch (d, d->arch.sal_return_addr,
				FW_HYPERCALL_SAL_RETURN, 0);

	/* Fill an AP wakeup descriptor.  */
	sal_wakeup->type = SAL_DESC_AP_WAKEUP;
	sal_wakeup->mechanism = IA64_SAL_AP_EXTERNAL_INT;
	sal_wakeup->vector = XEN_SAL_BOOT_RENDEZ_VEC;

	for (cp = (char *) sal_systab; cp < (char *) efi_memmap; ++cp)
		checksum += *cp;

	sal_systab->checksum = -checksum;

	/* Fill in the FPSWA interface: */
	fpswa_inf->revision = fpswa_interface->revision;
	dom_fpswa_hypercall_patch(d);
	fpswa_inf->fpswa = (void *) FW_HYPERCALL_FPSWA_ENTRY_PADDR + start_mpaddr;

	i = 0;
	if (d == dom0) {
#ifndef CONFIG_XEN_IA64_DOM0_VP
		/*
		 * This is a bad hack.  Dom0 may share other domains' memory
		 * through a dom0 physical address.  Unfortunately, this
		 * address may be used in maddr_to_page (e.g. in the loopback
		 * driver) but when Linux initializes memory it only creates
		 * page structs for the physical memory it knows about.  And
		 * on ia64, only for full writeback granules.  So, we reserve
		 * the last full granule of Xen's memory for dom0 (in
		 * start_kernel) to ensure dom0 creates a large enough memmap
		 */
		unsigned long last_start = max_page << PAGE_SHIFT;
		unsigned long last_end = last_start + IA64_GRANULE_SIZE;

		/* simulate 1MB free memory at physical address zero */
		MAKE_MD(EFI_LOADER_DATA,EFI_MEMORY_WB,0*MB,1*MB, 0);//XXX
#else
		int num_mds;
		int j;
#endif
		/* hypercall patches live here, masquerade as reserved PAL memory */
		MAKE_MD(EFI_PAL_CODE,EFI_MEMORY_WB|EFI_MEMORY_RUNTIME,HYPERCALL_START,HYPERCALL_END, 0);

#ifndef CONFIG_XEN_IA64_DOM0_VP
 		MAKE_MD(EFI_CONVENTIONAL_MEMORY,EFI_MEMORY_WB,HYPERCALL_END,maxmem-IA64_GRANULE_SIZE, 0);//XXX make sure this doesn't overlap on i/o, runtime area.
/* hack */	MAKE_MD(EFI_CONVENTIONAL_MEMORY,EFI_MEMORY_WB,last_start,last_end,1);
#endif

		/* pass through the I/O port space */
		if (!running_on_sim) {
			struct dom0_passthrough_arg arg;
			arg.md = &efi_memmap[i];
			arg.i = &i;
#ifdef CONFIG_XEN_IA64_DOM0_VP
			arg.d = d;
			arg.flags = ASSIGN_writable;
#endif
			//XXX Is this needed?
			efi_memmap_walk_type(EFI_RUNTIME_SERVICES_CODE,
			                     dom_fw_dom0_passthrough, &arg);
			// for ACPI table.
#ifdef CONFIG_XEN_IA64_DOM0_VP
			arg.flags = ASSIGN_readonly;
#endif
			efi_memmap_walk_type(EFI_RUNTIME_SERVICES_DATA,
			                     dom_fw_dom0_passthrough, &arg);
#ifdef CONFIG_XEN_IA64_DOM0_VP
			arg.flags = ASSIGN_writable;
#endif
			efi_memmap_walk_type(EFI_ACPI_RECLAIM_MEMORY,
			                     dom_fw_dom0_passthrough, &arg);
			efi_memmap_walk_type(EFI_MEMORY_MAPPED_IO,
			                     dom_fw_dom0_passthrough, &arg);
			efi_memmap_walk_type(EFI_MEMORY_MAPPED_IO_PORT_SPACE,
			                     dom_fw_dom0_passthrough, &arg);
			efi_memmap_walk_type(EFI_CONVENTIONAL_MEMORY,
			                     dom_fw_dom0_lowmem, &arg);
		}
		else MAKE_MD(EFI_RESERVED_TYPE,0,0,0,0);

#ifdef CONFIG_XEN_IA64_DOM0_VP
		// simple
		// MAKE_MD(EFI_CONVENTIONAL_MEMORY, EFI_MEMORY_WB,
		//         HYPERCALL_END, maxmem, 0);
		// is not good. Check overlap.
		sort(efi_memmap, i, sizeof(efi_memory_desc_t),
		     efi_mdt_cmp, NULL);

		// find gap and fill it with conventional memory
		num_mds = i;
		for (j = 0; j < num_mds; j++) {
			unsigned long end;
			unsigned long next_start;

			md = &efi_memmap[j];
			end = md->phys_addr + (md->num_pages << EFI_PAGE_SHIFT);

			next_start = maxmem;
			if (j + 1 < num_mds) {
				efi_memory_desc_t* next_md = &efi_memmap[j + 1];
				next_start = next_md->phys_addr;
				BUG_ON(end > next_start);
				if (end == next_md->phys_addr)
					continue;
			}

			// clip the range and align to PAGE_SIZE
			// Avoid "legacy" low memory addresses and the
			// HYPERCALL patch area.      
			if (end < HYPERCALL_END)
				end = HYPERCALL_END;
			if (next_start > maxmem)
				next_start = maxmem;
			end = PAGE_ALIGN(end);
			next_start = next_start & PAGE_MASK;
			if (end >= next_start)
				continue;

			MAKE_MD(EFI_CONVENTIONAL_MEMORY, EFI_MEMORY_WB,
			        end, next_start, 0);
			if (next_start >= maxmem)
				break;
		}
#endif        
	}
	else {
#ifndef CONFIG_XEN_IA64_DOM0_VP
		MAKE_MD(EFI_LOADER_DATA,EFI_MEMORY_WB,0*MB,1*MB, 1);
#endif
		/* hypercall patches live here, masquerade as reserved PAL memory */
		MAKE_MD(EFI_PAL_CODE,EFI_MEMORY_WB|EFI_MEMORY_RUNTIME,HYPERCALL_START,HYPERCALL_END, 1);
		MAKE_MD(EFI_CONVENTIONAL_MEMORY,EFI_MEMORY_WB,HYPERCALL_END,maxmem, 1);
		/* Create a dummy entry for IO ports, so that IO accesses are
		   trapped by Xen.  */
		MAKE_MD(EFI_MEMORY_MAPPED_IO_PORT_SPACE,EFI_MEMORY_UC,
			0x00000ffffc000000, 0x00000fffffffffff, 1);
		MAKE_MD(EFI_RESERVED_TYPE,0,0,0,0);
	}

	sort(efi_memmap, i, sizeof(efi_memory_desc_t), efi_mdt_cmp, NULL);

	bp->efi_systab = dom_pa((unsigned long) fw_mem);
	bp->efi_memmap = dom_pa((unsigned long) efi_memmap);
	BUG_ON(i > NUM_MEM_DESCS);
	bp->efi_memmap_size = i * sizeof(efi_memory_desc_t);
	bp->efi_memdesc_size = sizeof(efi_memory_desc_t);
	bp->efi_memdesc_version = EFI_MEMDESC_VERSION;
	bp->command_line = dom_pa((unsigned long) cmd_line);
	bp->console_info.num_cols = 80;
	bp->console_info.num_rows = 25;
	bp->console_info.orig_x = 0;
	bp->console_info.orig_y = 24;
	bp->fpswa = dom_pa((unsigned long) fpswa_inf);
	if (d == dom0) {
		int j;
		u64 addr;

		// XXX CONFIG_XEN_IA64_DOM0_VP
		// initrd_start address is hard coded in construct_dom0()
		bp->initrd_start = (dom0_start+dom0_size) -
		  (PAGE_ALIGN(ia64_boot_param->initrd_size) + 4*1024*1024);
		bp->initrd_size = ia64_boot_param->initrd_size;

		// dom0 doesn't need build_physmap_table()
		// see arch_set_info_guest()
		// instead we allocate pages manually.
		for (j = 0; j < i; j++) {
			md = &efi_memmap[j];
			if (md->phys_addr > maxmem)
				break;

			if (md->type == EFI_LOADER_DATA ||
			    md->type == EFI_PAL_CODE ||
			    md->type == EFI_CONVENTIONAL_MEMORY) {
				unsigned long start = md->phys_addr & PAGE_MASK;
				unsigned long end = md->phys_addr +
				              (md->num_pages << EFI_PAGE_SHIFT);

				if (end == start) {
					// md->num_pages = 0 is allowed.
					end += PAGE_SIZE;
				}
				if (end > (max_page << PAGE_SHIFT))
					end = (max_page << PAGE_SHIFT);

				for (addr = start; addr < end; addr += PAGE_SIZE) {
					assign_new_domain0_page(d, addr);
				}
			}
		}
		// Map low-memory holes & unmapped MMIO for legacy drivers
		for (addr = 0; addr < 1*MB; addr += PAGE_SIZE) {
			if (domain_page_mapped(d, addr))
				continue;
					
			if (efi_mmio(addr, PAGE_SIZE))
				assign_domain_mmio_page(d, addr, PAGE_SIZE);
		}
		d->arch.physmap_built = 1;
	}
	else {
		bp->initrd_start = d->arch.initrd_start;
		bp->initrd_size  = d->arch.initrd_len;
	}
	printf(" initrd start 0x%lx", bp->initrd_start);
	printf(" initrd size 0x%lx\n", bp->initrd_size);
	return bp;
}
