/*
 *  Xen domain firmware emulation support
 *  Copyright (C) 2004 Hewlett-Packard Co.
 *       Dan Magenheimer (dan.magenheimer@hp.com)
 *
 * Copyright (c) 2006, 2007
 *                    Isaku Yamahata <yamahata at valinux co jp>
 *                    VA Linux Systems Japan K.K.
 *                    dom0 vp model support
 */

#ifdef __XEN__
#include <asm/system.h>
#include <asm/dom_fw_dom0.h>
#include <asm/dom_fw_utils.h>
#else
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <inttypes.h>

#include <xen/xen.h>
#include <asm/bundle.h>

#include "xg_private.h"
#include "xc_dom.h"
#include "ia64/xc_dom_ia64_util.h"

#define ia64_fc(addr)   asm volatile ("fc %0" :: "r"(addr) : "memory")
#define MAX_VIRT_CPUS XEN_LEGACY_MAX_VCPUS /* XXX */
#endif /* __XEN__ */

#include <xen/acpi.h>
#include <acpi/actables.h>
#include <asm/dom_fw.h>
#include <asm/dom_fw_domu.h>

void
xen_ia64_efi_make_md(efi_memory_desc_t *md,
		     uint32_t type, uint64_t attr, 
		     uint64_t start, uint64_t end)
{
	md->type = type;
	md->pad = 0;
	md->phys_addr = start;
	md->virt_addr = 0;
	md->num_pages = (end - start) >> EFI_PAGE_SHIFT;
	md->attribute = attr;
}

#define EFI_HYPERCALL_PATCH(tgt, call)					\
	do {								\
		dom_efi_hypercall_patch(brkimm,				\
					FW_HYPERCALL_##call##_PADDR,	\
		                 FW_HYPERCALL_##call, hypercalls_imva);	\
		/* Descriptor address.  */                              \
		tables->efi_runtime.tgt =                               \
		                    FW_FIELD_MPA(func_ptrs) + 8 * pfn;  \
		/* Descriptor.  */                                      \
		tables->func_ptrs[pfn++] = FW_HYPERCALL_##call##_PADDR;	\
		tables->func_ptrs[pfn++] = 0;                     	\
	} while (0)

/**************************************************************************
Hypercall bundle creation
**************************************************************************/

static void
build_hypercall_bundle(uint64_t *imva, uint64_t brkimm, uint64_t hypnum, uint64_t ret)
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
build_pal_hypercall_bundles(uint64_t *imva, uint64_t brkimm, uint64_t hypnum)
{
	extern unsigned long xen_ia64_pal_call_stub[];
	IA64_BUNDLE bundle;
	INST64_A5 slot_a5;
	INST64_M37 slot_m37;

	/*
	 * The source of the hypercall stub is
	 * the xen_ia64_pal_call_stub function defined in dom_fw_asm.S. 
	 */

	/* Copy the first bundle and patch the hypercall number.  */
	bundle.i64[0] = xen_ia64_pal_call_stub[0];
	bundle.i64[1] = xen_ia64_pal_call_stub[1];
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
	bundle.i64[0] = xen_ia64_pal_call_stub[2];
	bundle.i64[1] = xen_ia64_pal_call_stub[3];
	slot_m37.inst = bundle.slot0;
	slot_m37.imm20a = brkimm;
	slot_m37.i = brkimm >> 20;
	bundle.slot0 = slot_m37.inst;
	imva[2] = bundle.i64[0];
	imva[3] = bundle.i64[1];
	ia64_fc(imva + 2);
	ia64_fc(imva + 3);
}

/* xen fpswa call stub. 14 bundles */
extern const unsigned long xen_ia64_fpswa_call_stub[];
extern const unsigned long xen_ia64_fpswa_call_stub_end[];
extern const unsigned long xen_ia64_fpswa_call_stub_patch[];
asm(
	".align 32\n"
	".proc xen_ia64_fpswa_call_stub;\n"
	"xen_ia64_fpswa_call_stub:\n"
	".prologue\n"
	"alloc r3 = ar.pfs, 8, 0, 0, 0\n"
	".body\n"
	"mov r14 = in0\n"
	"ld8 r15 = [in1], 8\n"
	";;\n"
	"ld8 r16 = [in1]\n"
	"ld8 r17 = [in2]\n"
	"ld8 r18 = [in3]\n"
	"ld8 r19 = [in4]\n"
	"ld8 r20 = [in5]\n"
	"ld8 r21 = [in6]\n"
	"ld8 r22 = [in7], 8\n"
	";;\n"
	"ld8 r23 = [in7], 8\n"
	";;\n"
	"ld8 r24 = [in7], 8\n"
	";;\n"
	"cmp.ne p6, p0 = r24, r0\n"
	"ld8 r25 = [in7], 8\n"
	";;\n"
	"(p6) tpa r24 = r24\n"
	"cmp.ne p7, p0 = r25, r0\n"
	"ld8 r26 = [in7], 8\n"
	";;\n"
	"(p7)tpa r25 = r25\n"
	"cmp.ne p8, p0 = r26, r0\n"
	"ld8 r27 = [in7], 8\n"
	";;\n"
	"(p8)tpa r26 = r26\n"
	"cmp.ne p9, p0 = r27, r0\n"
	";;\n"
	"tpa r27 = r27\n"
	"xen_ia64_fpswa_call_stub_patch:"
	"{\n"
	"mov r2 = " FW_HYPERCALL_FPSWA_STR "\n"
	"break " __IA64_XEN_HYPERCALL_DEFAULT_STR "\n"
	"nop.i 0\n"
	"}\n"
	"st8 [in2] = r17\n"
	"st8 [in3] = r18\n"
	"st8 [in4] = r19\n"
	"st8 [in5] = r20\n"
	"st8 [in6] = r21\n"
	"br.ret.sptk.many rp\n"
	"xen_ia64_fpswa_call_stub_end:"
	".endp xen_ia64_fpswa_call_stub\n"
);

static void
build_fpswa_hypercall_bundle(uint64_t *imva, uint64_t brkimm, uint64_t hypnum)
{
	INST64_A5 slot0;
	INST64_I19 slot1;
	INST64_I18 slot2;
	IA64_BUNDLE bundle;

	/* slot0: mov r2 = hypnum (low 20 bits) */
	slot0.inst = 0;
	slot0.qp = 0;
	slot0.r1 = 2;
	slot0.r3 = 0;
	slot0.major = 0x9;

	slot0.s = 0;
	slot0.imm9d = hypnum >> 7;
	slot0.imm5c = hypnum >> 16;
	slot0.imm7b = hypnum;

	/* slot1: break brkimm */
	slot1.inst = 0;
	slot1.qp = 0;
	slot1.x6 = 0;
	slot1.x3 = 0;
	slot1.major = 0x0;
	slot1.i = brkimm >> 20;
	slot1.imm20 = brkimm;

	/* slot2: nop.i */
	slot2.inst = 0;
	slot2.qp = 0;
	slot2.imm20 = 0;
	slot2.y = 0;
	slot2.x6 = 1;
	slot2.x3 = 0;
	slot2.i = 0;
	slot2.major = 0;

	/* MII bundle */
	bundle.i64[0] = 0;
	bundle.i64[1] = 0;
	bundle.template = 0x0; /* MII */
	bundle.slot0 = slot0.inst;
	bundle.slot1a = slot1.inst;
	bundle.slot1b = slot1.inst >> 18;
	bundle.slot2 = slot2.inst;
	
	imva[0] = bundle.i64[0];
	imva[1] = bundle.i64[1];
	ia64_fc(imva);
	ia64_fc(imva + 1);
}

// builds a hypercall bundle at domain physical address
static void
dom_fpswa_hypercall_patch(uint64_t brkimm, unsigned long imva)
{
	unsigned long *entry_imva, *patch_imva;
	const unsigned long entry_paddr = FW_HYPERCALL_FPSWA_ENTRY_PADDR;
	const unsigned long patch_paddr = FW_HYPERCALL_FPSWA_PATCH_PADDR;
	const size_t stub_size =
		(char*)xen_ia64_fpswa_call_stub_end -
		(char*)xen_ia64_fpswa_call_stub;
	size_t i;

	entry_imva = (unsigned long *)(imva + entry_paddr -
	                               FW_HYPERCALL_BASE_PADDR);
	patch_imva = (unsigned long *)(imva + patch_paddr -
	                               FW_HYPERCALL_BASE_PADDR);

	/* Descriptor.  */
	*entry_imva++ = patch_paddr;
	*entry_imva   = 0;

	/* see dom_fw.h */
	BUG_ON((char*)xen_ia64_fpswa_call_stub_end -
	       (char*)xen_ia64_fpswa_call_stub > 0xff - 16 + 1);

	/* call stub */
	memcpy(patch_imva, xen_ia64_fpswa_call_stub, stub_size);
	for (i = 0; i < stub_size; i++)
		ia64_fc(imva + i);
	patch_imva +=
		xen_ia64_fpswa_call_stub_patch - xen_ia64_fpswa_call_stub;
	build_fpswa_hypercall_bundle(patch_imva, brkimm, FW_HYPERCALL_FPSWA);
}

// builds a hypercall bundle at domain physical address
static void
dom_efi_hypercall_patch(uint64_t brkimm, unsigned long paddr,
                        unsigned long hypercall, unsigned long imva)
{
	build_hypercall_bundle((uint64_t *)(imva + paddr -
			       FW_HYPERCALL_BASE_PADDR),
			       brkimm, hypercall, 1);
}

// builds a hypercall bundle at domain physical address
static void
dom_fw_hypercall_patch(uint64_t brkimm, unsigned long paddr,
		       unsigned long hypercall,unsigned long ret,
                       unsigned long imva)
{
	build_hypercall_bundle((uint64_t *)(imva + paddr -
			       FW_HYPERCALL_BASE_PADDR),
			       brkimm, hypercall, ret);
}

static void
dom_fw_pal_hypercall_patch(uint64_t brkimm, unsigned long paddr, unsigned long imva)
{
	build_pal_hypercall_bundles((uint64_t*)(imva + paddr -
	                            FW_HYPERCALL_BASE_PADDR),
	                            brkimm, FW_HYPERCALL_PAL_CALL);
}

static inline void
#ifdef __XEN__ 
print_md(efi_memory_desc_t *md)
#else
print_md(xc_interface *xch, efi_memory_desc_t *md)
#endif
{
	uint64_t size;
	
	printk(XENLOG_INFO "dom mem: type=%2u, attr=0x%016lx, "
	       "range=[0x%016lx-0x%016lx) ",
	       md->type, md->attribute, md->phys_addr,
	       md->phys_addr + (md->num_pages << EFI_PAGE_SHIFT));

	size = md->num_pages << EFI_PAGE_SHIFT;
	if (size > ONE_MB)
		printk("(%luMB)\n", size >> 20);
	else
		printk("(%luKB)\n", size >> 10);
}

struct fake_acpi_tables {
	struct acpi_table_rsdp rsdp;
	struct acpi_table_xsdt xsdt;
	uint64_t madt_ptr;
	struct acpi_table_fadt fadt;
	struct acpi_table_facs facs;
	struct acpi_table_header dsdt;
	uint8_t aml[8 + 11 * MAX_VIRT_CPUS];
	struct acpi_table_madt madt;
	struct acpi_table_lsapic lsapic[MAX_VIRT_CPUS];
	uint8_t pm1a_event_block[4];
	uint8_t pm1a_control_block[1];
	uint8_t pm_timer_block[4];
};
#define ACPI_TABLE_MPA(field)                                       \
    FW_ACPI_BASE_PADDR + offsetof(struct fake_acpi_tables, field);

/* Create enough of an ACPI structure to make the guest OS ACPI happy. */
void
dom_fw_fake_acpi(domain_t *d, struct fake_acpi_tables *tables)
{
	struct acpi_table_rsdp *rsdp = &tables->rsdp;
	struct acpi_table_xsdt *xsdt = &tables->xsdt;
	struct acpi_table_fadt *fadt = &tables->fadt;
	struct acpi_table_facs *facs = &tables->facs;
	struct acpi_table_header *dsdt = &tables->dsdt;
	struct acpi_table_madt *madt = &tables->madt;
	struct acpi_table_lsapic *lsapic = tables->lsapic;
	int i;
	int aml_len;
	int nbr_cpus;

	BUILD_BUG_ON(sizeof(struct fake_acpi_tables) >
	             (FW_ACPI_END_PADDR - FW_ACPI_BASE_PADDR));

	memset(tables, 0, sizeof(struct fake_acpi_tables));

	/* setup XSDT (64bit version of RSDT) */
	memcpy(xsdt->header.signature, ACPI_SIG_XSDT,
	       sizeof(xsdt->header.signature));
	/* XSDT points to both the FADT and the MADT, so add one entry */
	xsdt->header.length = sizeof(struct acpi_table_xsdt) + sizeof(uint64_t);
	xsdt->header.revision = 1;
	memcpy(xsdt->header.oem_id, "XEN", 3);
	memcpy(xsdt->header.oem_table_id, "Xen/ia64", 8);
	memcpy(xsdt->header.asl_compiler_id, "XEN", 3);
	xsdt->header.asl_compiler_revision = xen_ia64_version(d);

	xsdt->table_offset_entry[0] = ACPI_TABLE_MPA(fadt);
	tables->madt_ptr = ACPI_TABLE_MPA(madt);

	xsdt->header.checksum = -acpi_tb_checksum((u8*)xsdt,
						  xsdt->header.length);

	/* setup FADT */
	memcpy(fadt->header.signature, ACPI_SIG_FADT,
	       sizeof(fadt->header.signature));
	fadt->header.length = sizeof(struct acpi_table_fadt);
	fadt->header.revision = FADT2_REVISION_ID;
	memcpy(fadt->header.oem_id, "XEN", 3);
	memcpy(fadt->header.oem_table_id, "Xen/ia64", 8);
	memcpy(fadt->header.asl_compiler_id, "XEN", 3);
	fadt->header.asl_compiler_revision = xen_ia64_version(d);

	memcpy(facs->signature, ACPI_SIG_FACS, sizeof(facs->signature));
	facs->version = 1;
	facs->length = sizeof(struct acpi_table_facs);

	fadt->Xfacs = ACPI_TABLE_MPA(facs);
	fadt->Xdsdt = ACPI_TABLE_MPA(dsdt);

	/*
	 * All of the below FADT entries are filled it to prevent warnings
	 * from sanity checks in the ACPI CA.  Emulate required ACPI hardware
	 * registers in system memory.
	 */
	fadt->pm1_event_length = 4;
	fadt->xpm1a_event_block.space_id = ACPI_ADR_SPACE_SYSTEM_MEMORY;
	fadt->xpm1a_event_block.bit_width = 8;
	fadt->xpm1a_event_block.address = ACPI_TABLE_MPA(pm1a_event_block);
	fadt->pm1_control_length = 1;
	fadt->xpm1a_control_block.space_id = ACPI_ADR_SPACE_SYSTEM_MEMORY;
	fadt->xpm1a_control_block.bit_width = 8;
	fadt->xpm1a_control_block.address = ACPI_TABLE_MPA(pm1a_control_block);
	fadt->pm_timer_length = 4;
	fadt->xpm_timer_block.space_id = ACPI_ADR_SPACE_SYSTEM_MEMORY;
	fadt->xpm_timer_block.bit_width = 8;
	fadt->xpm_timer_block.address = ACPI_TABLE_MPA(pm_timer_block);

	fadt->header.checksum = -acpi_tb_checksum((u8*)fadt,
						  fadt->header.length);

	/* setup RSDP */
	memcpy(rsdp->signature, ACPI_SIG_RSDP, strlen(ACPI_SIG_RSDP));
	memcpy(rsdp->oem_id, "XEN", 3);
	rsdp->revision = 2; /* ACPI 2.0 includes XSDT */
	rsdp->length = sizeof(struct acpi_table_rsdp);
	rsdp->xsdt_physical_address = ACPI_TABLE_MPA(xsdt);

	rsdp->checksum = -acpi_tb_checksum((u8*)rsdp,
					   ACPI_RSDP_CHECKSUM_LENGTH);
	rsdp->extended_checksum = -acpi_tb_checksum((u8*)rsdp, rsdp->length);

	/* setup DSDT with trivial namespace. */ 
	memcpy(dsdt->signature, ACPI_SIG_DSDT, strlen(ACPI_SIG_DSDT));
	dsdt->revision = 1;
	memcpy(dsdt->oem_id, "XEN", 3);
	memcpy(dsdt->oem_table_id, "Xen/ia64", 8);
	memcpy(dsdt->asl_compiler_id, "XEN", 3);
	dsdt->asl_compiler_revision = xen_ia64_version(d);

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
	dsdt->checksum = -acpi_tb_checksum((u8*)dsdt, dsdt->length);

	/* setup MADT */
	memcpy(madt->header.signature, ACPI_SIG_MADT,
	       sizeof(madt->header.signature));
	madt->header.revision = 2;
	memcpy(madt->header.oem_id, "XEN", 3);
	memcpy(madt->header.oem_table_id, "Xen/ia64", 8);
	memcpy(madt->header.asl_compiler_id, "XEN", 3);
	madt->header.asl_compiler_revision = xen_ia64_version(d);

	/* An LSAPIC entry describes a CPU.  */
	nbr_cpus = 0;
	for (i = 0; i < MAX_VIRT_CPUS; i++) {
		lsapic[i].header.type = ACPI_MADT_LSAPIC;
		lsapic[i].header.length = sizeof(struct acpi_table_lsapic);
		lsapic[i].acpi_id = i;
		lsapic[i].id = i;
		lsapic[i].eid = 0;
		if (xen_ia64_is_vcpu_allocated(d, i)) {
			lsapic[i].flags.enabled = 1;
			nbr_cpus++;
		}
	}
	madt->header.length = sizeof(struct acpi_table_madt) +
	                      nbr_cpus * sizeof(struct acpi_table_lsapic);
	madt->header.checksum = -acpi_tb_checksum((u8*)madt,
						  madt->header.length);
	return;
}

int
efi_mdt_cmp(const void *a, const void *b)
{
	const efi_memory_desc_t *x = a, *y = b;

	if (x->phys_addr > y->phys_addr)
		return 1;
	if (x->phys_addr < y->phys_addr)
		return -1;

	/* num_pages == 0 is allowed. */
	if (x->num_pages > y->num_pages)
		return 1;
	if (x->num_pages < y->num_pages)
		return -1;

	return 0;
}

int
dom_fw_init(domain_t *d,
	    uint64_t brkimm,
            struct xen_ia64_boot_param *bp,
            struct fw_tables *tables,
            unsigned long hypercalls_imva,
            unsigned long maxmem)
{
	unsigned long pfn;
	unsigned char checksum;
	char *cp;
	int num_mds, i;
	int fpswa_supported = 0;

	/* Caller must zero-clear fw_tables */

	/* EFI systab.  */
	tables->efi_systab.hdr.signature = EFI_SYSTEM_TABLE_SIGNATURE;
	tables->efi_systab.hdr.revision  = ((1 << 16) | 00); /* EFI 1.00 */
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
	if (xen_ia64_is_dom0(d)) {
		efi_systable_init_dom0(tables);
	} else {
#ifdef __XEN__
		efi_systable_init_domu(tables);
#else
		efi_systable_init_domu(d->xch, tables);
#endif
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
	dom_fw_pal_hypercall_patch(brkimm, tables->sal_ed.pal_proc,
				   hypercalls_imva);
	/* SAL entry point.  */
	tables->sal_ed.sal_proc = FW_HYPERCALL_SAL_CALL_PADDR;
	dom_fw_hypercall_patch(brkimm, tables->sal_ed.sal_proc,
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
	dom_fw_hypercall_patch(brkimm, FW_HYPERCALL_SAL_RETURN_PADDR,
	                       FW_HYPERCALL_SAL_RETURN, 0, hypercalls_imva);

	/* Fill in the FPSWA interface: */
	if (!xen_ia64_fpswa_revision(d, &tables->fpswa_inf.revision)) {
		fpswa_supported = 1;
		dom_fpswa_hypercall_patch(brkimm, hypercalls_imva);
		tables->fpswa_inf.fpswa = 
			(void *)FW_HYPERCALL_FPSWA_ENTRY_PADDR;
	}

	tables->num_mds = 0;
	/* hypercall patches live here, masquerade as reserved PAL memory */
	xen_ia64_efi_make_md(&tables->efi_memmap[tables->num_mds],
			     EFI_PAL_CODE, EFI_MEMORY_WB | EFI_MEMORY_RUNTIME,
			     FW_HYPERCALL_BASE_PADDR, FW_HYPERCALL_END_PADDR);
	tables->num_mds++;

	/* Create dom0/domu md entry for fw and cpi tables area.  */
	xen_ia64_efi_make_md(&tables->efi_memmap[tables->num_mds],
			     EFI_ACPI_MEMORY_NVS,
			     EFI_MEMORY_WB | EFI_MEMORY_RUNTIME,
			     FW_ACPI_BASE_PADDR, FW_ACPI_END_PADDR);
	tables->num_mds++;
	xen_ia64_efi_make_md(&tables->efi_memmap[tables->num_mds],
			     EFI_RUNTIME_SERVICES_DATA,
			     EFI_MEMORY_WB | EFI_MEMORY_RUNTIME,
			     FW_TABLES_BASE_PADDR,
			     tables->fw_tables_end_paddr);
	tables->num_mds++;

	if (!xen_ia64_is_dom0(d) || xen_ia64_is_running_on_sim(d)) {
		/* DomU (or hp-ski).
		   Create a continuous memory area.  */
		/* kludge: bp->efi_memmap is used to pass memmap_info
		 * page's pfn and number of pages to reserve. 
		 * Currently the following pages must be reserved.
		 * memmap info page, start info page, xenstore page
		 * and console page.
		 * see ia64_setup_memmap() @ xc_dom_boot.c
		 */
		num_mds = complete_domu_memmap(d, tables, maxmem,
					       XEN_IA64_MEMMAP_INFO_PFN(bp),
					       XEN_IA64_MEMMAP_INFO_NUM_PAGES(bp));
	} else {
		/* Dom0.
		   We must preserve ACPI data from real machine,
		   as well as IO areas.  */
		num_mds = complete_dom0_memmap(d, tables);
	}
	if (num_mds < 0)
		return num_mds;
	BUG_ON(num_mds != tables->num_mds);

	/* Display memmap.  */
	for (i = 0 ; i < tables->num_mds; i++)
#ifdef __XEN__
		print_md(&tables->efi_memmap[i]);
#else
		print_md(d->xch, &tables->efi_memmap[i]);
#endif

	/* Fill boot_param  */
	bp->efi_systab = FW_FIELD_MPA(efi_systab);
	bp->efi_memmap = FW_FIELD_MPA(efi_memmap);
	bp->efi_memmap_size = tables->num_mds * sizeof(efi_memory_desc_t);
	bp->efi_memdesc_size = sizeof(efi_memory_desc_t);
	bp->efi_memdesc_version = EFI_MEMDESC_VERSION;
	bp->command_line = 0;
	bp->console_info.num_cols = 80;
	bp->console_info.num_rows = 25;
	bp->console_info.orig_x = 0;
	bp->console_info.orig_y = 24;
	if (fpswa_supported)
		bp->fpswa = FW_FIELD_MPA(fpswa_inf);
	return 0;
}
