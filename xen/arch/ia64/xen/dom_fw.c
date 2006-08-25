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
#include <xen/version.h>
#include <xen/acpi.h>
#include <xen/errno.h>

#include <asm/dom_fw.h>
#include <asm/bundle.h>

#define ONE_MB (1UL << 20)

extern unsigned long running_on_sim;

/* Base of FW tables.  */
static const unsigned long dom_fw_base_mpa = FW_HYPERCALL_END_PADDR;
static unsigned long dom_fw_end_mpa;

/* Note: two domains cannot be created simulteanously!  */
static unsigned long imva_fw_base = -1;

#define FW_VENDOR "X\0e\0n\0/\0i\0a\0\066\0\064\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"

#define MAKE_MD(typ, attr, start, end) 					\
	do {								\
		md = tables->efi_memmap + i++;				\
		md->type = typ;						\
		md->pad = 0;						\
		md->phys_addr = start;					\
		md->virt_addr = 0;					\
		md->num_pages = (end - start) >> EFI_PAGE_SHIFT;	\
		md->attribute = attr;					\
	} while (0)

#define EFI_HYPERCALL_PATCH(tgt, call)					\
	do {								\
		dom_efi_hypercall_patch(d, FW_HYPERCALL_##call##_PADDR,	\
		                        FW_HYPERCALL_##call);		\
		tables->efi_runtime.tgt = dom_pa((unsigned long) pfn);  \
		*pfn++ = FW_HYPERCALL_##call##_PADDR;			\
		*pfn++ = 0;						\
	} while (0)

// return domain (meta)physical address for a given imva
// this function is a call-back from dom_fw_init
static unsigned long
dom_pa(unsigned long imva)
{
	if (imva_fw_base == -1) {
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
static inline void
assign_new_domain_page_if_dom0(struct domain *d, unsigned long mpaddr)
{
        if (d == dom0)
            assign_new_domain0_page(d, mpaddr);
}

/**************************************************************************
Hypercall bundle creation
**************************************************************************/

static void build_hypercall_bundle(UINT64 *imva, UINT64 brkimm, UINT64 hypnum, UINT64 ret)
{
	INST64_A5 slot0;
	INST64_I19 slot1;
	INST64_B4 slot2;
	IA64_BUNDLE bundle;

	// slot1: mov r2 = hypnum (low 20 bits)
	slot0.inst = 0;
	slot0.qp = 0; slot0.r1 = 2; slot0.r3 = 0; slot0.major = 0x9;
	slot0.imm7b = hypnum; slot0.imm9d = hypnum >> 7;
	slot0.imm5c = hypnum >> 16; slot0.s = 0;
	// slot1: break brkimm
	slot1.inst = 0;
	slot1.qp = 0; slot1.x6 = 0; slot1.x3 = 0; slot1.major = 0x0;
	slot1.imm20 = brkimm; slot1.i = brkimm >> 20;
	// if ret slot2:  br.ret.sptk.many rp
	// else   slot2:  br.cond.sptk.many rp
	slot2.inst = 0; slot2.qp = 0; slot2.p = 1; slot2.b2 = 0;
	slot2.wh = 0; slot2.d = 0; slot2.major = 0x0;
	if (ret) {
		slot2.btype = 4; slot2.x6 = 0x21;
	}
	else {
		slot2.btype = 0; slot2.x6 = 0x20;
	}
	
	bundle.i64[0] = 0; bundle.i64[1] = 0;
	bundle.template = 0x11;
	bundle.slot0 = slot0.inst; bundle.slot2 = slot2.inst;
	bundle.slot1a = slot1.inst; bundle.slot1b = slot1.inst >> 18;
	
	imva[0] = bundle.i64[0]; imva[1] = bundle.i64[1];
	ia64_fc(imva);
	ia64_fc(imva + 1);
}

static void build_pal_hypercall_bundles(UINT64 *imva, UINT64 brkimm, UINT64 hypnum)
{
	extern unsigned long pal_call_stub[];
	IA64_BUNDLE bundle;
	INST64_A5 slot_a5;
	INST64_M37 slot_m37;

	/* The source of the hypercall stub is the pal_call_stub function
	   defined in xenasm.S.  */

	/* Copy the first bundle and patch the hypercall number.  */
	bundle.i64[0] = pal_call_stub[0];
	bundle.i64[1] = pal_call_stub[1];
	slot_a5.inst = bundle.slot0;
	slot_a5.imm7b = hypnum;
	slot_a5.imm9d = hypnum >> 7;
	slot_a5.imm5c = hypnum >> 16;
	bundle.slot0 = slot_a5.inst;
	imva[0] = bundle.i64[0];
	imva[1] = bundle.i64[1];
	ia64_fc(imva);
	ia64_fc(imva + 1);
	
	/* Copy the second bundle and patch the hypercall vector.  */
	bundle.i64[0] = pal_call_stub[2];
	bundle.i64[1] = pal_call_stub[3];
	slot_m37.inst = bundle.slot0;
	slot_m37.imm20a = brkimm;
	slot_m37.i = brkimm >> 20;
	bundle.slot0 = slot_m37.inst;
	imva[2] = bundle.i64[0];
	imva[3] = bundle.i64[1];
	ia64_fc(imva + 2);
	ia64_fc(imva + 3);
}

// builds a hypercall bundle at domain physical address
static void dom_fpswa_hypercall_patch(struct domain *d)
{
	unsigned long *entry_imva, *patch_imva;
	unsigned long entry_paddr = FW_HYPERCALL_FPSWA_ENTRY_PADDR;
	unsigned long patch_paddr = FW_HYPERCALL_FPSWA_PATCH_PADDR;

	assign_new_domain_page_if_dom0(d, entry_paddr);
	assign_new_domain_page_if_dom0(d, patch_paddr);
	entry_imva = domain_mpa_to_imva(d, entry_paddr);
	patch_imva = domain_mpa_to_imva(d, patch_paddr);

	*entry_imva++ = patch_paddr;
	*entry_imva   = 0;
	build_hypercall_bundle(patch_imva, d->arch.breakimm,
	                       FW_HYPERCALL_FPSWA, 1);
}

// builds a hypercall bundle at domain physical address
static void dom_efi_hypercall_patch(struct domain *d, unsigned long paddr, unsigned long hypercall)
{
	unsigned long *imva;

	assign_new_domain_page_if_dom0(d, paddr);
	imva = domain_mpa_to_imva(d, paddr);
	build_hypercall_bundle(imva, d->arch.breakimm, hypercall, 1);
}

// builds a hypercall bundle at domain physical address
static void dom_fw_hypercall_patch(struct domain *d, unsigned long paddr, unsigned long hypercall,unsigned long ret)
{
	unsigned long *imva;

	assign_new_domain_page_if_dom0(d, paddr);
	imva = domain_mpa_to_imva(d, paddr);
	build_hypercall_bundle(imva, d->arch.breakimm, hypercall, ret);
}

static void dom_fw_pal_hypercall_patch(struct domain *d, unsigned long paddr)
{
	unsigned long *imva;

	assign_new_domain_page_if_dom0(d, paddr);
	imva = domain_mpa_to_imva(d, paddr);
	build_pal_hypercall_bundles(imva, d->arch.breakimm,
	                            FW_HYPERCALL_PAL_CALL);
}

/* the following heavily leveraged from linux/arch/ia64/hp/sim/fw-emu.c */

static inline void
print_md(efi_memory_desc_t *md)
{
	u64 size;
	
	printk("dom mem: type=%2u, attr=0x%016lx, range=[0x%016lx-0x%016lx) ",
	       md->type, md->attribute, md->phys_addr,
	       md->phys_addr + (md->num_pages << EFI_PAGE_SHIFT));

	size = md->num_pages << EFI_PAGE_SHIFT;
	if (size > ONE_MB)
		printf ("(%luMB)\n", size >> 20);
	else
		printf ("(%luKB)\n", size >> 10);
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
		lsapic->id = lsapic_nbr;
		lsapic->eid = 0;
		lsapic_nbr++;
	} else if (lsapic->flags.enabled) {
		printk("DISABLE lsapic entry: 0x%lx\n", (u64)lsapic);
		lsapic->flags.enabled = 0;
		lsapic->id = 0;
		lsapic->eid = 0;
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
	int nbr_cpus;

	memset(tables, 0, sizeof(struct fake_acpi_tables));

	/* setup XSDT (64bit version of RSDT) */
	strncpy(xsdt->signature, XSDT_SIG, 4);
	/* XSDT points to both the FADT and the MADT, so add one entry */
	xsdt->length = sizeof(struct xsdt_descriptor_rev2) + sizeof(u64);
	xsdt->revision = 1;
	strcpy(xsdt->oem_id, "XEN");
	strcpy(xsdt->oem_table_id, "Xen/ia64");
	strcpy(xsdt->asl_compiler_id, "XEN");
	xsdt->asl_compiler_revision = (xen_major_version() << 16) |
		xen_minor_version();

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
	fadt->asl_compiler_revision = (xen_major_version() << 16) |
		xen_minor_version();

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
	dsdt->asl_compiler_revision = (xen_major_version() << 16) |
		xen_minor_version();

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
	strcpy(madt->header.oem_id, "XEN");
	strcpy(madt->header.oem_table_id, "Xen/ia64");
	strcpy(madt->header.asl_compiler_id, "XEN");
	madt->header.asl_compiler_revision = (xen_major_version() << 16) |
		xen_minor_version();

	/* An LSAPIC entry describes a CPU.  */
	nbr_cpus = 0;
	for (i = 0; i < MAX_VIRT_CPUS; i++) {
		lsapic[i].header.type = ACPI_MADT_LSAPIC;
		lsapic[i].header.length = sizeof(struct acpi_table_lsapic);
		lsapic[i].acpi_id = i;
		lsapic[i].id = i;
		lsapic[i].eid = 0;
		if (d->vcpu[i] != NULL) {
			lsapic[i].flags.enabled = 1;
			nbr_cpus++;
		}
	}
	madt->header.length = sizeof(struct acpi_table_madt) +
	                      nbr_cpus * sizeof(struct acpi_table_lsapic);
	madt->header.checksum = generate_acpi_checksum(madt,
	                                               madt->header.length);
	return;
}

struct dom0_passthrough_arg {
    struct domain*      d;
    int                 flags;
    efi_memory_desc_t *md;
    int*                i;
};

static int
dom_fw_dom0_passthrough(efi_memory_desc_t *md, void *arg__)
{
    struct dom0_passthrough_arg* arg = (struct dom0_passthrough_arg*)arg__;
    unsigned long paddr;
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

    BUG_ON(md->type != EFI_RUNTIME_SERVICES_CODE &&
           md->type != EFI_RUNTIME_SERVICES_DATA &&
           md->type != EFI_ACPI_RECLAIM_MEMORY &&
           md->type != EFI_ACPI_MEMORY_NVS &&
           md->type != EFI_RESERVED_TYPE &&
           md->type != EFI_MEMORY_MAPPED_IO &&
           md->type != EFI_MEMORY_MAPPED_IO_PORT_SPACE);

    arg->md->type = md->type;
    arg->md->pad = 0;
    arg->md->phys_addr = paddr;
    arg->md->virt_addr = 0;
    arg->md->num_pages = md->num_pages;
    arg->md->attribute = md->attribute;

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
    u64 end = min(ONE_MB, md->phys_addr + (md->num_pages << EFI_PAGE_SHIFT));

    BUG_ON(md->type != EFI_CONVENTIONAL_MEMORY);

    /* Avoid firmware and hypercall area.
       We know they are 0-based.  */
    if (end < dom_fw_end_mpa || md->phys_addr >= ONE_MB)
	return 0;
    if (md->phys_addr < dom_fw_end_mpa)
        md->phys_addr = dom_fw_end_mpa;

    arg->md->type = md->type;
    arg->md->pad = 0;
    arg->md->phys_addr = md->phys_addr;
    arg->md->virt_addr = 0;
    arg->md->num_pages = (end - md->phys_addr) >> EFI_PAGE_SHIFT;
    arg->md->attribute = md->attribute;

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

#define NFUNCPTRS 16
#define NUM_EFI_SYS_TABLES 6
#define NUM_MEM_DESCS 64 //large enough

struct fw_tables {
	efi_system_table_t efi_systab;
	efi_runtime_services_t efi_runtime;
	efi_config_table_t efi_tables[NUM_EFI_SYS_TABLES];

	struct ia64_sal_systab sal_systab;
	struct ia64_sal_desc_entry_point sal_ed;
	struct ia64_sal_desc_ap_wakeup sal_wakeup;
	/* End of SAL descriptors.  Do not forget to update checkum bound.  */

	fpswa_interface_t fpswa_inf;
	efi_memory_desc_t efi_memmap[NUM_MEM_DESCS];
	unsigned long func_ptrs[2*NFUNCPTRS];
 	struct xen_sal_data sal_data;
	unsigned char fw_vendor[sizeof(FW_VENDOR)];

	struct fake_acpi_tables acpi_tables;
};
	
static void
dom_fw_init(struct domain *d,
            struct ia64_boot_param *bp,
            struct fw_tables *tables,
            unsigned long maxmem)
{
	efi_memory_desc_t *md;
	unsigned long *pfn;
	unsigned char checksum;
	char *cp;
	int num_mds, i;

	memset(tables, 0, sizeof(struct fw_tables));

	/* Initialise for EFI_SET_VIRTUAL_ADDRESS_MAP emulation */
	d->arch.efi_runtime = &tables->efi_runtime;
	d->arch.fpswa_inf   = &tables->fpswa_inf;
	d->arch.sal_data    = &tables->sal_data;

	/* EFI systab.  */
	tables->efi_systab.hdr.signature = EFI_SYSTEM_TABLE_SIGNATURE;
	tables->efi_systab.hdr.revision  = EFI_SYSTEM_TABLE_REVISION;
	tables->efi_systab.hdr.headersize = sizeof(tables->efi_systab.hdr);

	memcpy(tables->fw_vendor,FW_VENDOR,sizeof(FW_VENDOR));
	tables->efi_systab.fw_vendor =
	                             dom_pa((unsigned long)tables->fw_vendor);
	tables->efi_systab.fw_revision = 1;
	tables->efi_systab.runtime =
	                 (void *)dom_pa((unsigned long)&tables->efi_runtime);
	tables->efi_systab.nr_tables = NUM_EFI_SYS_TABLES;
	tables->efi_systab.tables = dom_pa((unsigned long)tables->efi_tables);

	/* EFI runtime.  */
	tables->efi_runtime.hdr.signature = EFI_RUNTIME_SERVICES_SIGNATURE;
	tables->efi_runtime.hdr.revision = EFI_RUNTIME_SERVICES_REVISION;
	tables->efi_runtime.hdr.headersize = sizeof(tables->efi_runtime.hdr);

	pfn = tables->func_ptrs;
	EFI_HYPERCALL_PATCH(get_time,EFI_GET_TIME);
	EFI_HYPERCALL_PATCH(set_time,EFI_SET_TIME);
	EFI_HYPERCALL_PATCH(get_wakeup_time,EFI_GET_WAKEUP_TIME);
	EFI_HYPERCALL_PATCH(set_wakeup_time,EFI_SET_WAKEUP_TIME);
	EFI_HYPERCALL_PATCH(set_virtual_address_map,
	                    EFI_SET_VIRTUAL_ADDRESS_MAP);
	EFI_HYPERCALL_PATCH(get_variable,EFI_GET_VARIABLE);
	EFI_HYPERCALL_PATCH(get_next_variable,EFI_GET_NEXT_VARIABLE);
	EFI_HYPERCALL_PATCH(set_variable,EFI_SET_VARIABLE);
	EFI_HYPERCALL_PATCH(get_next_high_mono_count,
	                    EFI_GET_NEXT_HIGH_MONO_COUNT);
	EFI_HYPERCALL_PATCH(reset_system,EFI_RESET_SYSTEM);

	/* System tables.  */
	tables->efi_tables[0].guid = SAL_SYSTEM_TABLE_GUID;
	tables->efi_tables[0].table =
	                           dom_pa((unsigned long)&tables->sal_systab);
	for (i = 1; i < NUM_EFI_SYS_TABLES; i++) {
		tables->efi_tables[i].guid = NULL_GUID;
		tables->efi_tables[i].table = 0;
	}
	i = 1;
	if (d == dom0) {
		printf("Domain0 EFI passthrough:");
		if (efi.mps) {
			tables->efi_tables[i].guid = MPS_TABLE_GUID;
			tables->efi_tables[i].table = __pa(efi.mps);
			printf(" MPS=0x%lx",tables->efi_tables[i].table);
			i++;
		}

		touch_acpi_table();

		if (efi.acpi20) {
			tables->efi_tables[i].guid = ACPI_20_TABLE_GUID;
			tables->efi_tables[i].table = __pa(efi.acpi20);
			printf(" ACPI 2.0=0x%lx",tables->efi_tables[i].table);
			i++;
		}
		if (efi.acpi) {
			tables->efi_tables[i].guid = ACPI_TABLE_GUID;
			tables->efi_tables[i].table = __pa(efi.acpi);
			printf(" ACPI=0x%lx",tables->efi_tables[i].table);
			i++;
		}
		if (efi.smbios) {
			tables->efi_tables[i].guid = SMBIOS_TABLE_GUID;
			tables->efi_tables[i].table = __pa(efi.smbios);
			printf(" SMBIOS=0x%lx",tables->efi_tables[i].table);
			i++;
		}
		if (efi.hcdp) {
			tables->efi_tables[i].guid = HCDP_TABLE_GUID;
			tables->efi_tables[i].table = __pa(efi.hcdp);
			printf(" HCDP=0x%lx",tables->efi_tables[i].table);
			i++;
		}
		printf("\n");
	} else {
		printf("DomainU EFI build up:");

		dom_fw_fake_acpi(d, &tables->acpi_tables);

		tables->efi_tables[i].guid = ACPI_20_TABLE_GUID;
		tables->efi_tables[i].table =
		                  dom_pa((unsigned long) &tables->acpi_tables);
		printf(" ACPI 2.0=0x%lx",tables->efi_tables[i].table);
		i++;
		printf("\n");
	}

	/* fill in the SAL system table: */
	memcpy(tables->sal_systab.signature, "SST_", 4);
	tables->sal_systab.size = sizeof(tables->sal_systab);
	tables->sal_systab.sal_rev_minor = 1;
	tables->sal_systab.sal_rev_major = 0;
	tables->sal_systab.entry_count = 2;

	strcpy((char *)tables->sal_systab.oem_id, "Xen/ia64");
	strcpy((char *)tables->sal_systab.product_id, "Xen/ia64");

	/* fill in an entry point: */
	tables->sal_ed.type = SAL_DESC_ENTRY_POINT;
	tables->sal_ed.pal_proc = FW_HYPERCALL_PAL_CALL_PADDR;
	dom_fw_pal_hypercall_patch(d, tables->sal_ed.pal_proc);
	tables->sal_ed.sal_proc = FW_HYPERCALL_SAL_CALL_PADDR;
	dom_fw_hypercall_patch(d, tables->sal_ed.sal_proc,
	                       FW_HYPERCALL_SAL_CALL, 1);
	tables->sal_ed.gp = 0;  /* will be ignored */

	/* Fill an AP wakeup descriptor.  */
	tables->sal_wakeup.type = SAL_DESC_AP_WAKEUP;
	tables->sal_wakeup.mechanism = IA64_SAL_AP_EXTERNAL_INT;
	tables->sal_wakeup.vector = XEN_SAL_BOOT_RENDEZ_VEC;

	/* Compute checksum.  */
	checksum = 0;
	for (cp = (char *)&tables->sal_systab;
	     cp < (char *)&tables->fpswa_inf;
	     ++cp)
		checksum += *cp;
	tables->sal_systab.checksum = -checksum;

	/* SAL return point.  */
	d->arch.sal_return_addr = FW_HYPERCALL_SAL_RETURN_PADDR;
	dom_fw_hypercall_patch (d, d->arch.sal_return_addr,
				FW_HYPERCALL_SAL_RETURN, 0);

	/* Fill in the FPSWA interface: */
	tables->fpswa_inf.revision = fpswa_interface->revision;
	dom_fpswa_hypercall_patch(d);
	tables->fpswa_inf.fpswa = (void *)FW_HYPERCALL_FPSWA_ENTRY_PADDR;

	i = 0; /* Used by MAKE_MD */

	/* hypercall patches live here, masquerade as reserved PAL memory */
	MAKE_MD(EFI_PAL_CODE,EFI_MEMORY_WB|EFI_MEMORY_RUNTIME,
	        FW_HYPERCALL_BASE_PADDR, FW_HYPERCALL_END_PADDR);

	/* Create dom0/domu md entry for fw tables area */
	MAKE_MD(EFI_RUNTIME_SERVICES_DATA, EFI_MEMORY_WB | EFI_MEMORY_RUNTIME,
	        dom_fw_base_mpa, dom_fw_end_mpa);

	if (d != dom0 || running_on_sim) {
		/* Memory.  */
		MAKE_MD(EFI_CONVENTIONAL_MEMORY, EFI_MEMORY_WB,
		        dom_fw_end_mpa, maxmem);
		
		/* Create an entry for IO ports.  */
		MAKE_MD(EFI_MEMORY_MAPPED_IO_PORT_SPACE, EFI_MEMORY_UC,
		        IO_PORTS_PADDR, IO_PORTS_PADDR + IO_PORTS_SIZE);

		num_mds = i;
	}
	else {
		/* pass through the I/O port space */
		struct dom0_passthrough_arg arg;
		u64 addr;
		int j;

		/* Fill from real entries.  */
		arg.md = &tables->efi_memmap[i];
		arg.i = &i;
		arg.d = d;
		arg.flags = ASSIGN_writable;
		//XXX Is this needed?
		efi_memmap_walk_type(EFI_RUNTIME_SERVICES_CODE,
		                     dom_fw_dom0_passthrough, &arg);
		// for ACPI table.
		arg.flags = ASSIGN_readonly;
		efi_memmap_walk_type(EFI_RUNTIME_SERVICES_DATA,
		                     dom_fw_dom0_passthrough, &arg);
		arg.flags = ASSIGN_writable;
		efi_memmap_walk_type(EFI_ACPI_RECLAIM_MEMORY,
		                     dom_fw_dom0_passthrough, &arg);
		efi_memmap_walk_type(EFI_ACPI_MEMORY_NVS,
		                     dom_fw_dom0_passthrough, &arg);
		efi_memmap_walk_type(EFI_RESERVED_TYPE,
		                     dom_fw_dom0_passthrough, &arg);
		efi_memmap_walk_type(EFI_MEMORY_MAPPED_IO,
		                     dom_fw_dom0_passthrough, &arg);
		efi_memmap_walk_type(EFI_MEMORY_MAPPED_IO_PORT_SPACE,
		                     dom_fw_dom0_passthrough, &arg);
		efi_memmap_walk_type(EFI_CONVENTIONAL_MEMORY,
		                     dom_fw_dom0_lowmem, &arg);
		num_mds = i;

		sort(tables->efi_memmap, num_mds, sizeof(efi_memory_desc_t),
		     efi_mdt_cmp, NULL);

		// find gaps and fill them with conventional memory
		for (j = 0; j < num_mds; j++) {
			unsigned long end;
			unsigned long next_start;

			md = &tables->efi_memmap[j];
			end = md->phys_addr + (md->num_pages << EFI_PAGE_SHIFT);

			if (j + 1 < num_mds) {
				efi_memory_desc_t* next_md;
				next_md = &tables->efi_memmap[j+1];
				next_start = next_md->phys_addr;
				
				/* Have just been sorted.  */
				BUG_ON(end > next_start);
				
				/* No room for memory!  */
				if (end == next_start)
					continue;
				
				if (next_start > maxmem)
					next_start = maxmem;
			}
			else
				next_start = maxmem;
			
			/* Avoid "legacy" low memory addresses and
			   the HYPERCALL area.  */
			if (end < ONE_MB)
				end = ONE_MB;
						      
			// clip the range and align to PAGE_SIZE
			next_start = next_start & PAGE_MASK;
			end = PAGE_ALIGN(end);
			
			/* No room for memory.  */
			if (end >= next_start)
				continue;

			MAKE_MD(EFI_CONVENTIONAL_MEMORY, EFI_MEMORY_WB,
			        end, next_start);

			if (next_start >= maxmem)
				break;
		}
		num_mds = i;
		BUG_ON(num_mds > NUM_MEM_DESCS);
		sort(tables->efi_memmap, num_mds, sizeof(efi_memory_desc_t),
		     efi_mdt_cmp, NULL);

		// dom0 doesn't need build_physmap_table()
		// see arch_set_info_guest()
		// instead we allocate pages manually.
		for (i = 0; i < num_mds; i++) {
			md = &tables->efi_memmap[i];
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
					continue;
				}
				if (end > (max_page << PAGE_SHIFT))
					end = (max_page << PAGE_SHIFT);

				for (addr = start;
				     addr < end;
				     addr += PAGE_SIZE) {
					assign_new_domain0_page(d, addr);
				}
			}
		}
		// Map low-memory holes & unmapped MMIO for legacy drivers
		for (addr = 0; addr < ONE_MB; addr += PAGE_SIZE) {
			if (domain_page_mapped(d, addr))
				continue;
					
			if (efi_mmio(addr, PAGE_SIZE))
				assign_domain_mmio_page(d, addr, PAGE_SIZE);
		}
	}

	/* Display memmap.  */
	for (i = 0 ; i < num_mds; i++)
		print_md(&tables->efi_memmap[i]);

	/* Fill boot_param  */
	bp->efi_systab = dom_pa((unsigned long)&tables->efi_systab);
	bp->efi_memmap = dom_pa((unsigned long)tables->efi_memmap);
	bp->efi_memmap_size = num_mds * sizeof(efi_memory_desc_t);
	bp->efi_memdesc_size = sizeof(efi_memory_desc_t);
	bp->efi_memdesc_version = EFI_MEMDESC_VERSION;
	bp->command_line = 0;
	bp->console_info.num_cols = 80;
	bp->console_info.num_rows = 25;
	bp->console_info.orig_x = 0;
	bp->console_info.orig_y = 24;
	bp->fpswa = dom_pa((unsigned long) &tables->fpswa_inf);
}

void dom_fw_setup(struct domain *d, unsigned long bp_mpa, unsigned long maxmem)
{
	struct ia64_boot_param *bp;

	/* Note: 4KB < size < 8KB.  */
	BUILD_BUG_ON(sizeof(struct fw_tables) > PAGE_SIZE);

	dom_fw_end_mpa = PAGE_ALIGN(dom_fw_base_mpa + sizeof(struct fw_tables));

	/* Create page for hypercalls.  */
	assign_new_domain_page_if_dom0(d, dom_fw_base_mpa);
	imva_fw_base = (unsigned long)domain_mpa_to_imva(d, dom_fw_base_mpa);

	/* Create page for boot_param.  */
	assign_new_domain_page_if_dom0(d, bp_mpa);
	bp = domain_mpa_to_imva(d, bp_mpa);

	dom_fw_init(d, bp, (struct fw_tables *)imva_fw_base, maxmem);
}
