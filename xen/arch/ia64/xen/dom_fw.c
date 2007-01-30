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
		                 FW_HYPERCALL_##call, hypercalls_imva);	\
		/* Descriptor address.  */                              \
		tables->efi_runtime.tgt =                               \
		                    FW_FIELD_MPA(func_ptrs) + 8 * pfn;  \
		/* Descriptor.  */                                      \
		tables->func_ptrs[pfn++] = FW_HYPERCALL_##call##_PADDR;	\
		tables->func_ptrs[pfn++] = 0;                     	\
	} while (0)

/* allocate a page for fw
 * guest_setup() @ libxc/xc_linux_build.c does for domU
 */
static inline void
assign_new_domain_page_if_dom0(struct domain *d, unsigned long mpaddr)
{
        if (d == dom0)
            assign_new_domain0_page(d, mpaddr);
}

/**************************************************************************
Hypercall bundle creation
**************************************************************************/

static void
build_hypercall_bundle(u64 *imva, u64 brkimm, u64 hypnum, u64 ret)
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

static void
build_pal_hypercall_bundles(u64 *imva, u64 brkimm, u64 hypnum)
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
static void
dom_fpswa_hypercall_patch(struct domain *d, unsigned long imva)
{
	unsigned long *entry_imva, *patch_imva;
	const unsigned long entry_paddr = FW_HYPERCALL_FPSWA_ENTRY_PADDR;
	const unsigned long patch_paddr = FW_HYPERCALL_FPSWA_PATCH_PADDR;

	entry_imva = (unsigned long *)(imva + entry_paddr -
	                               FW_HYPERCALL_BASE_PADDR);
	patch_imva = (unsigned long *)(imva + patch_paddr -
	                               FW_HYPERCALL_BASE_PADDR);

	/* Descriptor.  */
	*entry_imva++ = patch_paddr;
	*entry_imva   = 0;

	build_hypercall_bundle(patch_imva, d->arch.breakimm,
	                       FW_HYPERCALL_FPSWA, 1);
}

// builds a hypercall bundle at domain physical address
static void
dom_efi_hypercall_patch(struct domain *d, unsigned long paddr,
                        unsigned long hypercall, unsigned long imva)
{
	build_hypercall_bundle((u64 *)(imva + paddr - FW_HYPERCALL_BASE_PADDR),
	                       d->arch.breakimm, hypercall, 1);
}

// builds a hypercall bundle at domain physical address
static void
dom_fw_hypercall_patch(struct domain *d, unsigned long paddr,
                       unsigned long hypercall,unsigned long ret,
                       unsigned long imva)
{
	build_hypercall_bundle((u64 *)(imva + paddr - FW_HYPERCALL_BASE_PADDR),
	                       d->arch.breakimm, hypercall, ret);
}

static void
dom_fw_pal_hypercall_patch(struct domain *d, unsigned long paddr,
                           unsigned long imva)
{
	build_pal_hypercall_bundles((u64*)(imva + paddr -
	                            FW_HYPERCALL_BASE_PADDR),
	                            d->arch.breakimm, FW_HYPERCALL_PAL_CALL);
}

static inline void
print_md(efi_memory_desc_t *md)
{
	u64 size;
	
	printk("dom mem: type=%2u, attr=0x%016lx, range=[0x%016lx-0x%016lx) ",
	       md->type, md->attribute, md->phys_addr,
	       md->phys_addr + (md->num_pages << EFI_PAGE_SHIFT));

	size = md->num_pages << EFI_PAGE_SHIFT;
	if (size > ONE_MB)
		printk ("(%luMB)\n", size >> 20);
	else
		printk ("(%luKB)\n", size >> 10);
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

static int __init
acpi_patch_plat_int_src (
	acpi_table_entry_header *header, const unsigned long end)
{
	struct acpi_table_plat_int_src *plintsrc;

	plintsrc = (struct acpi_table_plat_int_src *)header;
	if (!plintsrc)
		return -EINVAL;

	if (plintsrc->type == ACPI_INTERRUPT_CPEI) {
		printk("ACPI_INTERRUPT_CPEI disabled for Domain0\n");
		plintsrc->type = -1;
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
		printk("Error parsing MADT - no LAPIC entries\n");
	if (acpi_table_parse_madt(ACPI_MADT_PLAT_INT_SRC,
	                          acpi_patch_plat_int_src, 0) < 0)
		printk("Error parsing MADT - no PLAT_INT_SRC entries\n");

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
#define ACPI_TABLE_MPA(field) \
  FW_ACPI_BASE_PADDR + offsetof(struct fake_acpi_tables, field);

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
	memcpy(xsdt->signature, XSDT_SIG, sizeof(xsdt->signature));
	/* XSDT points to both the FADT and the MADT, so add one entry */
	xsdt->length = sizeof(struct xsdt_descriptor_rev2) + sizeof(u64);
	xsdt->revision = 1;
	memcpy(xsdt->oem_id, "XEN", 3);
	memcpy(xsdt->oem_table_id, "Xen/ia64", 8);
	memcpy(xsdt->asl_compiler_id, "XEN", 3);
	xsdt->asl_compiler_revision = (xen_major_version() << 16) |
		xen_minor_version();

	xsdt->table_offset_entry[0] = ACPI_TABLE_MPA(fadt);
	tables->madt_ptr = ACPI_TABLE_MPA(madt);

	xsdt->checksum = generate_acpi_checksum(xsdt, xsdt->length);

	/* setup FADT */
	memcpy(fadt->signature, FADT_SIG, sizeof(fadt->signature));
	fadt->length = sizeof(struct fadt_descriptor_rev2);
	fadt->revision = FADT2_REVISION_ID;
	memcpy(fadt->oem_id, "XEN", 3);
	memcpy(fadt->oem_table_id, "Xen/ia64", 8);
	memcpy(fadt->asl_compiler_id, "XEN", 3);
	fadt->asl_compiler_revision = (xen_major_version() << 16) |
		xen_minor_version();

	memcpy(facs->signature, FACS_SIG, sizeof(facs->signature));
	facs->version = 1;
	facs->length = sizeof(struct facs_descriptor_rev2);

	fadt->xfirmware_ctrl = ACPI_TABLE_MPA(facs);
	fadt->Xdsdt = ACPI_TABLE_MPA(dsdt);

	/*
	 * All of the below FADT entries are filled it to prevent warnings
	 * from sanity checks in the ACPI CA.  Emulate required ACPI hardware
	 * registers in system memory.
	 */
	fadt->pm1_evt_len = 4;
	fadt->xpm1a_evt_blk.address_space_id = ACPI_ADR_SPACE_SYSTEM_MEMORY;
	fadt->xpm1a_evt_blk.register_bit_width = 8;
	fadt->xpm1a_evt_blk.address = ACPI_TABLE_MPA(pm1a_evt_blk);
	fadt->pm1_cnt_len = 1;
	fadt->xpm1a_cnt_blk.address_space_id = ACPI_ADR_SPACE_SYSTEM_MEMORY;
	fadt->xpm1a_cnt_blk.register_bit_width = 8;
	fadt->xpm1a_cnt_blk.address = ACPI_TABLE_MPA(pm1a_cnt_blk);
	fadt->pm_tm_len = 4;
	fadt->xpm_tmr_blk.address_space_id = ACPI_ADR_SPACE_SYSTEM_MEMORY;
	fadt->xpm_tmr_blk.register_bit_width = 8;
	fadt->xpm_tmr_blk.address = ACPI_TABLE_MPA(pm_tmr_blk);

	fadt->checksum = generate_acpi_checksum(fadt, fadt->length);

	/* setup RSDP */
	memcpy(rsdp->signature, RSDP_SIG, strlen(RSDP_SIG));
	memcpy(rsdp->oem_id, "XEN", 3);
	rsdp->revision = 2; /* ACPI 2.0 includes XSDT */
	rsdp->length = sizeof(struct acpi20_table_rsdp);
	rsdp->xsdt_address = ACPI_TABLE_MPA(xsdt);

	rsdp->checksum = generate_acpi_checksum(rsdp,
	                                        ACPI_RSDP_CHECKSUM_LENGTH);
	rsdp->ext_checksum = generate_acpi_checksum(rsdp, rsdp->length);

	/* setup DSDT with trivial namespace. */ 
	memcpy(dsdt->signature, DSDT_SIG, strlen(DSDT_SIG));
	dsdt->revision = 1;
	memcpy(dsdt->oem_id, "XEN", 3);
	memcpy(dsdt->oem_table_id, "Xen/ia64", 8);
	memcpy(dsdt->asl_compiler_id, "XEN", 3);
	dsdt->asl_compiler_revision = (xen_major_version() << 16) |
		xen_minor_version();

	/* Trivial namespace, avoids ACPI CA complaints */
	tables->aml[0] = 0x10; /* Scope */
	tables->aml[1] = 0x40; /* length/offset to next object (patched) */
	tables->aml[2] = 0x00;
	memcpy(&tables->aml[3], "_SB_", 4);

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
	memcpy(madt->header.signature, APIC_SIG, sizeof(madt->header.signature));
	madt->header.revision = 2;
	memcpy(madt->header.oem_id, "XEN", 3);
	memcpy(madt->header.oem_table_id, "Xen/ia64", 8);
	memcpy(madt->header.asl_compiler_id, "XEN", 3);
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
};
#define FW_FIELD_MPA(field) \
   FW_TABLES_BASE_PADDR + offsetof(struct fw_tables, field)

/* Complete the dom0 memmap.  */
static int
complete_dom0_memmap(struct domain *d,
                     struct fw_tables *tables,
                     unsigned long maxmem,
                     int num_mds)
{
	efi_memory_desc_t *md;
	u64 addr;
	void *efi_map_start, *efi_map_end, *p;
	u64 efi_desc_size;
	int i;
	unsigned long dom_mem = maxmem - (d->tot_pages << PAGE_SHIFT);

	/* Walk through all MDT entries.
	   Copy all interesting entries.  */
	efi_map_start = __va(ia64_boot_param->efi_memmap);
	efi_map_end = efi_map_start + ia64_boot_param->efi_memmap_size;
	efi_desc_size = ia64_boot_param->efi_memdesc_size;

	for (p = efi_map_start; p < efi_map_end; p += efi_desc_size) {
		const efi_memory_desc_t *md = p;
		efi_memory_desc_t *dom_md = &tables->efi_memmap[num_mds];
		u64 start = md->phys_addr;
		u64 size = md->num_pages << EFI_PAGE_SHIFT;
		u64 end = start + size;
		unsigned long flags;

		switch (md->type) {
		case EFI_RUNTIME_SERVICES_CODE:
		case EFI_RUNTIME_SERVICES_DATA:
		case EFI_ACPI_RECLAIM_MEMORY:
		case EFI_ACPI_MEMORY_NVS:
		case EFI_RESERVED_TYPE:
			/*
			 * Map into dom0 - We must respect protection
			 * and cache attributes.  Not all of these pages
			 * are writable!!!
			 */
			flags = ASSIGN_writable;	/* dummy - zero */
			if (md->attribute & EFI_MEMORY_WP)
				flags |= ASSIGN_readonly;
			if ((md->attribute & EFI_MEMORY_UC) &&
			    !(md->attribute & EFI_MEMORY_WB))
				flags |= ASSIGN_nocache;

			assign_domain_mach_page(d, start, size, flags);

			/* Fall-through.  */
		case EFI_MEMORY_MAPPED_IO:
			/* Will be mapped with ioremap.  */
			/* Copy descriptor.  */
			*dom_md = *md;
			dom_md->virt_addr = 0;
			num_mds++;
			break;

		case EFI_MEMORY_MAPPED_IO_PORT_SPACE:
			/* Map into dom0.  */
			assign_domain_mmio_page(d, start, size);
			/* Copy descriptor.  */
			*dom_md = *md;
			dom_md->virt_addr = 0;
			num_mds++;
			break;

		case EFI_CONVENTIONAL_MEMORY:
		case EFI_LOADER_CODE:
		case EFI_LOADER_DATA:
		case EFI_BOOT_SERVICES_CODE:
		case EFI_BOOT_SERVICES_DATA:
			if (!(md->attribute & EFI_MEMORY_WB))
				break;

			start = max(FW_END_PADDR, start);
			end = min(start + dom_mem, end);
			if (end <= start)
				break;

			dom_md->type = EFI_CONVENTIONAL_MEMORY;
			dom_md->phys_addr = start;
			dom_md->virt_addr = 0;
			dom_md->num_pages = (end - start) >> EFI_PAGE_SHIFT;
			dom_md->attribute = EFI_MEMORY_WB;
			num_mds++;

			dom_mem -= dom_md->num_pages << EFI_PAGE_SHIFT;
			d->arch.convmem_end = end;
			break;

		case EFI_UNUSABLE_MEMORY:
		case EFI_PAL_CODE:
			/* Discard.  */
			break;

		default:
			/* Print a warning but continue.  */
			printk("complete_dom0_memmap: warning: "
			       "unhandled MDT entry type %u\n", md->type);
		}
	}
	BUG_ON(num_mds > NUM_MEM_DESCS);
	
	sort(tables->efi_memmap, num_mds, sizeof(efi_memory_desc_t),
	     efi_mdt_cmp, NULL);

	/* setup_guest() @ libxc/xc_linux_build() arranges memory for domU.
	 * however no one arranges memory for dom0,
	 * instead we allocate pages manually.
	 */
	for (i = 0; i < num_mds; i++) {
		md = &tables->efi_memmap[i];

		if (md->type == EFI_LOADER_DATA ||
		    md->type == EFI_PAL_CODE ||
		    md->type == EFI_CONVENTIONAL_MEMORY) {
			unsigned long start = md->phys_addr & PAGE_MASK;
			unsigned long end = md->phys_addr +
				(md->num_pages << EFI_PAGE_SHIFT);

			if (end == start) {
				/* md->num_pages = 0 is allowed. */
				continue;
			}
			
			for (addr = start; addr < end; addr += PAGE_SIZE)
				assign_new_domain0_page(d, addr);
		}
	}
	// Map low-memory holes & unmapped MMIO for legacy drivers
	for (addr = 0; addr < ONE_MB; addr += PAGE_SIZE) {
		if (domain_page_mapped(d, addr))
			continue;
		
		if (efi_mmio(addr, PAGE_SIZE))
			assign_domain_mmio_page(d, addr, PAGE_SIZE);
	}
	return num_mds;
}
	
static void
dom_fw_init(struct domain *d,
            struct ia64_boot_param *bp,
            struct fw_tables *tables,
            unsigned long hypercalls_imva,
            unsigned long maxmem)
{
	efi_memory_desc_t *md;
	unsigned long pfn;
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
	tables->efi_systab.fw_vendor = FW_FIELD_MPA(fw_vendor);
	tables->efi_systab.fw_revision = 1;
	tables->efi_systab.runtime = (void *)FW_FIELD_MPA(efi_runtime);
	tables->efi_systab.nr_tables = NUM_EFI_SYS_TABLES;
	tables->efi_systab.tables = FW_FIELD_MPA(efi_tables);

	/* EFI runtime.  */
	tables->efi_runtime.hdr.signature = EFI_RUNTIME_SERVICES_SIGNATURE;
	tables->efi_runtime.hdr.revision = EFI_RUNTIME_SERVICES_REVISION;
	tables->efi_runtime.hdr.headersize = sizeof(tables->efi_runtime.hdr);

	pfn = 0;
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
	tables->efi_tables[0].table = FW_FIELD_MPA(sal_systab);
	for (i = 1; i < NUM_EFI_SYS_TABLES; i++) {
		tables->efi_tables[i].guid = NULL_GUID;
		tables->efi_tables[i].table = 0;
	}
	i = 1;
	if (d == dom0) {
		/* Write messages to the console.  */
		touch_acpi_table();

		printk("Domain0 EFI passthrough:");
		if (efi.mps) {
			tables->efi_tables[i].guid = MPS_TABLE_GUID;
			tables->efi_tables[i].table = __pa(efi.mps);
			printk(" MPS=0x%lx",tables->efi_tables[i].table);
			i++;
		}

		if (efi.acpi20) {
			tables->efi_tables[i].guid = ACPI_20_TABLE_GUID;
			tables->efi_tables[i].table = __pa(efi.acpi20);
			printk(" ACPI 2.0=0x%lx",tables->efi_tables[i].table);
			i++;
		}
		if (efi.acpi) {
			tables->efi_tables[i].guid = ACPI_TABLE_GUID;
			tables->efi_tables[i].table = __pa(efi.acpi);
			printk(" ACPI=0x%lx",tables->efi_tables[i].table);
			i++;
		}
		if (efi.smbios) {
			tables->efi_tables[i].guid = SMBIOS_TABLE_GUID;
			tables->efi_tables[i].table = __pa(efi.smbios);
			printk(" SMBIOS=0x%lx",tables->efi_tables[i].table);
			i++;
		}
		if (efi.hcdp) {
			tables->efi_tables[i].guid = HCDP_TABLE_GUID;
			tables->efi_tables[i].table = __pa(efi.hcdp);
			printk(" HCDP=0x%lx",tables->efi_tables[i].table);
			i++;
		}
		printk("\n");
	} else {
		printk("DomainU EFI build up:");

		tables->efi_tables[i].guid = ACPI_20_TABLE_GUID;
		tables->efi_tables[i].table = FW_ACPI_BASE_PADDR;
		printk(" ACPI 2.0=0x%lx",tables->efi_tables[i].table);
		i++;
		printk("\n");
	}

	/* fill in the SAL system table: */
	memcpy(tables->sal_systab.signature, "SST_", 4);
	tables->sal_systab.size = sizeof(tables->sal_systab);
	tables->sal_systab.sal_rev_minor = 1;
	tables->sal_systab.sal_rev_major = 0;
	tables->sal_systab.entry_count = 2;

	memcpy((char *)tables->sal_systab.oem_id, "Xen/ia64", 8);
	memcpy((char *)tables->sal_systab.product_id, "Xen/ia64", 8);

	/* PAL entry point: */
	tables->sal_ed.type = SAL_DESC_ENTRY_POINT;
	tables->sal_ed.pal_proc = FW_HYPERCALL_PAL_CALL_PADDR;
	dom_fw_pal_hypercall_patch(d, tables->sal_ed.pal_proc, 
	                           hypercalls_imva);
	/* SAL entry point.  */
	tables->sal_ed.sal_proc = FW_HYPERCALL_SAL_CALL_PADDR;
	dom_fw_hypercall_patch(d, tables->sal_ed.sal_proc,
	                       FW_HYPERCALL_SAL_CALL, 1, hypercalls_imva);
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
	dom_fw_hypercall_patch(d, FW_HYPERCALL_SAL_RETURN_PADDR,
	                       FW_HYPERCALL_SAL_RETURN, 0, hypercalls_imva);

	/* Fill in the FPSWA interface: */
	if (fpswa_interface) {
		tables->fpswa_inf.revision = fpswa_interface->revision;
		dom_fpswa_hypercall_patch(d, hypercalls_imva);
		tables->fpswa_inf.fpswa = 
		                       (void *)FW_HYPERCALL_FPSWA_ENTRY_PADDR;
	}

	i = 0; /* Used by MAKE_MD */

	/* hypercall patches live here, masquerade as reserved PAL memory */
	MAKE_MD(EFI_PAL_CODE,EFI_MEMORY_WB|EFI_MEMORY_RUNTIME,
	        FW_HYPERCALL_BASE_PADDR, FW_HYPERCALL_END_PADDR);

	/* Create dom0/domu md entry for fw and cpi tables area.  */
	MAKE_MD(EFI_ACPI_MEMORY_NVS, EFI_MEMORY_WB | EFI_MEMORY_RUNTIME,
	        FW_ACPI_BASE_PADDR, FW_ACPI_END_PADDR);
	MAKE_MD(EFI_RUNTIME_SERVICES_DATA, EFI_MEMORY_WB | EFI_MEMORY_RUNTIME,
	        FW_TABLES_BASE_PADDR, FW_TABLES_END_PADDR);

	if (d != dom0 || running_on_sim) {
		/* DomU (or hp-ski).
		   Create a continuous memory area.  */
		/* Memory.  */
		MAKE_MD(EFI_CONVENTIONAL_MEMORY, EFI_MEMORY_WB,
		        FW_END_PADDR, maxmem);
		d->arch.convmem_end = maxmem;
		
		/* Create an entry for IO ports.  */
		MAKE_MD(EFI_MEMORY_MAPPED_IO_PORT_SPACE, EFI_MEMORY_UC,
		        IO_PORTS_PADDR, IO_PORTS_PADDR + IO_PORTS_SIZE);

		num_mds = i;
	}
	else {
		/* Dom0.
		   We must preserve ACPI data from real machine,
		   as well as IO areas.  */
		num_mds = complete_dom0_memmap(d, tables, maxmem, i);
	}

	/* Display memmap.  */
	for (i = 0 ; i < num_mds; i++)
		print_md(&tables->efi_memmap[i]);

	/* Fill boot_param  */
	bp->efi_systab = FW_FIELD_MPA(efi_systab);
	bp->efi_memmap = FW_FIELD_MPA(efi_memmap);
	bp->efi_memmap_size = num_mds * sizeof(efi_memory_desc_t);
	bp->efi_memdesc_size = sizeof(efi_memory_desc_t);
	bp->efi_memdesc_version = EFI_MEMDESC_VERSION;
	bp->command_line = 0;
	bp->console_info.num_cols = 80;
	bp->console_info.num_rows = 25;
	bp->console_info.orig_x = 0;
	bp->console_info.orig_y = 24;
	if (fpswa_interface)
		bp->fpswa = FW_FIELD_MPA(fpswa_inf);
}

void dom_fw_setup(struct domain *d, unsigned long bp_mpa, unsigned long maxmem)
{
	struct ia64_boot_param *bp;
	unsigned long imva_tables_base;
	unsigned long imva_hypercall_base;

	BUILD_BUG_ON(sizeof(struct fw_tables) >
	             (FW_TABLES_END_PADDR - FW_TABLES_BASE_PADDR));

	BUILD_BUG_ON(sizeof(struct fake_acpi_tables) >
	             (FW_ACPI_END_PADDR - FW_ACPI_BASE_PADDR));

	/* Create page for hypercalls.  */
	assign_new_domain_page_if_dom0(d, FW_HYPERCALL_BASE_PADDR);
	imva_hypercall_base = (unsigned long)domain_mpa_to_imva
	                                     (d, FW_HYPERCALL_BASE_PADDR);

	/* Create page for acpi tables.  */
	if (d != dom0) {
		void *imva;

		assign_new_domain_page_if_dom0(d, FW_ACPI_BASE_PADDR);
		imva = domain_mpa_to_imva (d, FW_ACPI_BASE_PADDR);
		dom_fw_fake_acpi(d, (struct fake_acpi_tables *)imva);
	}

	/* Create page for FW tables.  */
	assign_new_domain_page_if_dom0(d, FW_TABLES_BASE_PADDR);
	imva_tables_base = (unsigned long)domain_mpa_to_imva
	                                  (d, FW_TABLES_BASE_PADDR);

	/* Create page for boot_param.  */
	assign_new_domain_page_if_dom0(d, bp_mpa);
	bp = domain_mpa_to_imva(d, bp_mpa);

	dom_fw_init(d, bp, (struct fw_tables *)imva_tables_base,
	            imva_hypercall_base, maxmem);
}
