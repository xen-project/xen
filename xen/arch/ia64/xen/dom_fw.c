/*
 *  Xen domain firmware emulation support
 *  Copyright (C) 2004 Hewlett-Packard Co.
 *       Dan Magenheimer (dan.magenheimer@hp.com)
 *
 */

#include <xen/config.h>
#include <asm/system.h>
#include <asm/pgalloc.h>

#include <linux/efi.h>
#include <asm/io.h>
#include <asm/pal.h>
#include <asm/sal.h>
#include <asm/meminit.h>
#include <xen/compile.h>
#include <xen/acpi.h>

#include <asm/dom_fw.h>
#include <public/sched.h>

static struct ia64_boot_param *dom_fw_init(struct domain *, char *,int,char *,int);
extern unsigned long domain_mpa_to_imva(struct domain *,unsigned long mpaddr);
extern struct domain *dom0;
extern unsigned long dom0_start;

extern unsigned long running_on_sim;


unsigned long dom_fw_base_mpa = -1;
unsigned long imva_fw_base = -1;

// return domain (meta)physical address for a given imva
// this function is a call-back from dom_fw_init
unsigned long dom_pa(unsigned long imva)
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

// builds a hypercall bundle at domain physical address
static void dom_efi_hypercall_patch(struct domain *d, unsigned long paddr, unsigned long hypercall)
{
	unsigned long *imva;

	if (d == dom0) paddr += dom0_start;
	imva = (unsigned long *) domain_mpa_to_imva(d, paddr);
	build_hypercall_bundle(imva, d->arch.breakimm, hypercall, 1);
}


// builds a hypercall bundle at domain physical address
static void dom_fw_hypercall_patch(struct domain *d, unsigned long paddr, unsigned long hypercall,unsigned long ret)
{
	unsigned long *imva;

	imva = (unsigned long *) domain_mpa_to_imva(d, paddr);
	build_hypercall_bundle(imva, d->arch.breakimm, hypercall, ret);
}

static void dom_fw_pal_hypercall_patch(struct domain *d, unsigned long paddr)
{
	unsigned long *imva;

	imva = (unsigned long *) domain_mpa_to_imva(d, paddr);
	build_pal_hypercall_bundles(imva, d->arch.breakimm, FW_HYPERCALL_PAL_CALL);
}


// FIXME: This is really a hack: Forcing the boot parameter block
// at domain mpaddr 0 page, then grabbing only the low bits of the
// Xen imva, which is the offset into the page
unsigned long dom_fw_setup(struct domain *d, const char *args, int arglen)
{
	struct ia64_boot_param *bp;

	dom_fw_base_mpa = 0;
	if (d == dom0) dom_fw_base_mpa += dom0_start;
	imva_fw_base = domain_mpa_to_imva(d, dom_fw_base_mpa);
	bp = dom_fw_init(d, args, arglen, (char *) imva_fw_base, PAGE_SIZE);
	return dom_pa((unsigned long) bp);
}


/* the following heavily leveraged from linux/arch/ia64/hp/sim/fw-emu.c */

#define NUM_EFI_SYS_TABLES 6
# define NUM_MEM_DESCS	5


struct sal_ret_values
sal_emulator (long index, unsigned long in1, unsigned long in2,
	      unsigned long in3, unsigned long in4, unsigned long in5,
	      unsigned long in6, unsigned long in7)
{
	unsigned long r9  = 0;
	unsigned long r10 = 0;
	long r11 = 0;
	long status;

	status = 0;
	switch (index) {
	    case SAL_FREQ_BASE:
		if (!running_on_sim)
			status = ia64_sal_freq_base(in1,&r9,&r10);
		else switch (in1) {
		      case SAL_FREQ_BASE_PLATFORM:
			r9 = 200000000;
			break;

		      case SAL_FREQ_BASE_INTERVAL_TIMER:
			r9 = 700000000;
			break;

		      case SAL_FREQ_BASE_REALTIME_CLOCK:
			r9 = 1;
			break;

		      default:
			status = -1;
			break;
		}
		break;
	    case SAL_PCI_CONFIG_READ:
		if (current->domain == dom0) {
			u64 value;
			// note that args 2&3 are swapped!!
			status = ia64_sal_pci_config_read(in1,in3,in2,&value);
			r9 = value;
		}
		else
		     printf("NON-PRIV DOMAIN CALLED SAL_PCI_CONFIG_READ\n");
		break;
	    case SAL_PCI_CONFIG_WRITE:
		if (current->domain == dom0) {
			if (((in1 & ~0xffffffffUL) && (in4 == 0)) ||
			    (in4 > 1) ||
			    (in2 > 8) || (in2 & (in2-1)))
				printf("*** SAL_PCI_CONF_WRITE?!?(adr=0x%lx,typ=0x%lx,sz=0x%lx,val=0x%lx)\n",
					in1,in4,in2,in3);
			// note that args are in a different order!!
			status = ia64_sal_pci_config_write(in1,in4,in2,in3);
		}
		else
		     printf("NON-PRIV DOMAIN CALLED SAL_PCI_CONFIG_WRITE\n");
		break;
	    case SAL_SET_VECTORS:
		printf("*** CALLED SAL_SET_VECTORS.  IGNORED...\n");
		break;
	    case SAL_GET_STATE_INFO:
		printf("*** CALLED SAL_GET_STATE_INFO.  IGNORED...\n");
		break;
	    case SAL_GET_STATE_INFO_SIZE:
		printf("*** CALLED SAL_GET_STATE_INFO_SIZE.  IGNORED...\n");
		break;
	    case SAL_CLEAR_STATE_INFO:
		printf("*** CALLED SAL_CLEAR_STATE_INFO.  IGNORED...\n");
		break;
	    case SAL_MC_RENDEZ:
		printf("*** CALLED SAL_MC_RENDEZ.  IGNORED...\n");
		break;
	    case SAL_MC_SET_PARAMS:
		printf("*** CALLED SAL_MC_SET_PARAMS.  IGNORED...\n");
		break;
	    case SAL_CACHE_FLUSH:
		printf("*** CALLED SAL_CACHE_FLUSH.  IGNORED...\n");
		break;
	    case SAL_CACHE_INIT:
		printf("*** CALLED SAL_CACHE_INIT.  IGNORED...\n");
		break;
	    case SAL_UPDATE_PAL:
		printf("*** CALLED SAL_UPDATE_PAL.  IGNORED...\n");
		break;
	    default:
		printf("*** CALLED SAL_ WITH UNKNOWN INDEX.  IGNORED...\n");
		status = -1;
		break;
	}
	return ((struct sal_ret_values) {status, r9, r10, r11});
}

struct ia64_pal_retval
xen_pal_emulator(unsigned long index, u64 in1, u64 in2, u64 in3)
{
	unsigned long r9  = 0;
	unsigned long r10 = 0;
	unsigned long r11 = 0;
	long status = -1;

	if (running_on_sim)
		return pal_emulator_static(index);

	// pal code must be mapped by a TR when pal is called, however
	// calls are rare enough that we will map it lazily rather than
	// at every context switch
	//efi_map_pal_code();
	switch (index) {
	    case PAL_MEM_ATTRIB:
		status = ia64_pal_mem_attrib(&r9);
		break;
	    case PAL_FREQ_BASE:
		status = ia64_pal_freq_base(&r9);
		break;
	    case PAL_PROC_GET_FEATURES:
		status = ia64_pal_proc_get_features(&r9,&r10,&r11);
		break;
	    case PAL_BUS_GET_FEATURES:
		status = ia64_pal_bus_get_features(
				(pal_bus_features_u_t *) &r9,
				(pal_bus_features_u_t *) &r10,
				(pal_bus_features_u_t *) &r11);
		break;
	    case PAL_FREQ_RATIOS:
		status = ia64_pal_freq_ratios(
				(struct pal_freq_ratio *) &r9,
				(struct pal_freq_ratio *) &r10,
				(struct pal_freq_ratio *) &r11);
		break;
	    case PAL_PTCE_INFO:
		{
			// return hard-coded xen-specific values because ptc.e
			// is emulated on xen to always flush everything
			// these values result in only one ptc.e instruction
			status = 0; r9 = 0; r10 = (1L << 32) | 1L; r11 = 0;
		}
		break;
	    case PAL_VERSION:
		status = ia64_pal_version(
				(pal_version_u_t *) &r9,
				(pal_version_u_t *) &r10);
		break;
	    case PAL_VM_PAGE_SIZE:
		status = ia64_pal_vm_page_size(&r9,&r10);
		break;
	    case PAL_DEBUG_INFO:
		status = ia64_pal_debug_info(&r9,&r10);
		break;
	    case PAL_CACHE_SUMMARY:
		status = ia64_pal_cache_summary(&r9,&r10);
		break;
	    case PAL_VM_SUMMARY:
		// FIXME: what should xen return for these, figure out later
		// For now, linux does the right thing if pal call fails
		// In particular, rid_size must be set properly!
		//status = ia64_pal_vm_summary(
		//		(pal_vm_info_1_u_t *) &r9,
		//		(pal_vm_info_2_u_t *) &r10);
		break;
	    case PAL_RSE_INFO:
		status = ia64_pal_rse_info(
				&r9,
				(pal_hints_u_t *) &r10);
		break;
	    case PAL_VM_INFO:
		status = ia64_pal_vm_info(
				in1,
				in2,
				(pal_tc_info_u_t *) &r9,
				&r10);
		break;
	    case PAL_REGISTER_INFO:
		status = ia64_pal_register_info(in1, &r9, &r10);
		break;
	    case PAL_CACHE_FLUSH:
		/* FIXME */
		printk("PAL_CACHE_FLUSH NOT IMPLEMENTED!\n");
		BUG();
		break;
	    case PAL_PERF_MON_INFO:
		{
			unsigned long pm_buffer[16];
			status = ia64_pal_perf_mon_info(
					pm_buffer,
					(pal_perf_mon_info_u_t *) &r9);
			if (status != 0) {
				while(1)
				printk("PAL_PERF_MON_INFO fails ret=%ld\n", status);
				break;
			}
			if (copy_to_user((void __user *)in1,pm_buffer,128)) {
				while(1)
				printk("xen_pal_emulator: PAL_PERF_MON_INFO "
					"can't copy to user!!!!\n");
				status = -1;
				break;
			}
		}
		break;
	    case PAL_CACHE_INFO:
		{
			pal_cache_config_info_t ci;
			status = ia64_pal_cache_config_info(in1,in2,&ci);
			if (status != 0) break;
			r9 = ci.pcci_info_1.pcci1_data;
			r10 = ci.pcci_info_2.pcci2_data;
		}
		break;
	    case PAL_VM_TR_READ:	/* FIXME: vcpu_get_tr?? */
		printk("PAL_VM_TR_READ NOT IMPLEMENTED, IGNORED!\n");
		break;
	    case PAL_HALT_INFO:
	        {
		    /* 1000 cycles to enter/leave low power state,
		       consumes 10 mW, implemented and cache/TLB coherent.  */
		    unsigned long res = 1000UL | (1000UL << 16) | (10UL << 32)
			    | (1UL << 61) | (1UL << 60);
		    if (copy_to_user ((void *)in1, &res, sizeof (res)))
			    status = PAL_STATUS_EINVAL;    
		    else
			    status = PAL_STATUS_SUCCESS;
	        }
		break;
	    case PAL_HALT:
		    if (current->domain == dom0) {
			    printf ("Domain0 halts the machine\n");
			    (*efi.reset_system)(EFI_RESET_SHUTDOWN,0,0,NULL);
		    }
		    else
			    domain_shutdown (current->domain,
					     SHUTDOWN_poweroff);
		    break;
	    default:
		printk("xen_pal_emulator: UNIMPLEMENTED PAL CALL %lu!!!!\n",
				index);
		break;
	}
	return ((struct ia64_pal_retval) {status, r9, r10, r11});
}


#define NFUNCPTRS 20

static void print_md(efi_memory_desc_t *md)
{
#if 1
	printk("domain mem: type=%u, attr=0x%lx, range=[0x%016lx-0x%016lx) (%luMB)\n",
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
	u8 aml[16];
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
	dsdt->length = sizeof(struct acpi_table_header) + sizeof(tables->aml);
	strcpy(dsdt->oem_id, "XEN");
	strcpy(dsdt->oem_table_id, "Xen/ia64");
	strcpy(dsdt->asl_compiler_id, "XEN");
	dsdt->asl_compiler_revision = (XEN_VERSION<<16)|(XEN_SUBVERSION);

	/* Trivial namespace, avoids ACPI CA complaints */
	tables->aml[0] = 0x10; /* Scope */
	tables->aml[1] = 0x12; /* length/offset to next object */
	strncpy((char *)&tables->aml[2], "_SB_", 4);

	/* The processor object isn't absolutely necessary, revist for SMP */
	tables->aml[6] = 0x5b; /* processor object */
	tables->aml[7] = 0x83;
	tables->aml[8] = 0x0b; /* next */
	strncpy((char *)&tables->aml[9], "CPU0", 4);

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
		lsapic[i].id = i;
		lsapic[i].eid = 0;
		lsapic[i].flags.enabled = (d->vcpu[i] != NULL);
	}

	madt->header.checksum = generate_acpi_checksum(madt,
	                                               madt->header.length);
	return;
}

static struct ia64_boot_param *
dom_fw_init (struct domain *d, char *args, int arglen, char *fw_mem, int fw_mem_size)
{
	efi_system_table_t *efi_systab;
	efi_runtime_services_t *efi_runtime;
	efi_config_table_t *efi_tables;
	struct ia64_sal_systab *sal_systab;
	efi_memory_desc_t *efi_memmap, *md;
	struct ia64_sal_desc_entry_point *sal_ed;
	struct ia64_boot_param *bp;
	unsigned long *pfn;
	unsigned char checksum = 0;
	char *cp, *cmd_line, *fw_vendor;
	int i = 0;
	unsigned long maxmem = (d->max_pages - d->arch.sys_pgnr) * PAGE_SIZE;
	const unsigned long start_mpaddr = ((d==dom0)?dom0_start:0);

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
	efi_memmap  = (void *) cp; cp += NUM_MEM_DESCS*sizeof(*efi_memmap);
	bp	    = (void *) cp; cp += sizeof(*bp);
	pfn         = (void *) cp; cp += NFUNCPTRS * 2 * sizeof(pfn);
	cmd_line    = (void *) cp;

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
		printf("Domain0 EFI passthrough:");
		i = 1;
		if (efi.mps) {
			efi_tables[i].guid = MPS_TABLE_GUID;
			efi_tables[i].table = __pa(efi.mps);
			printf(" MPS=0x%lx",efi_tables[i].table);
			i++;
		}

		touch_acpi_table();

		if (efi.acpi20) {
			efi_tables[i].guid = ACPI_20_TABLE_GUID;
			efi_tables[i].table = __pa(efi.acpi20);
			printf(" ACPI 2.0=0x%lx",efi_tables[i].table);
			i++;
		}
		if (efi.acpi) {
			efi_tables[i].guid = ACPI_TABLE_GUID;
			efi_tables[i].table = __pa(efi.acpi);
			printf(" ACPI=0x%lx",efi_tables[i].table);
			i++;
		}
		if (efi.smbios) {
			efi_tables[i].guid = SMBIOS_TABLE_GUID;
			efi_tables[i].table = __pa(efi.smbios);
			printf(" SMBIOS=0x%lx",efi_tables[i].table);
			i++;
		}
		if (efi.hcdp) {
			efi_tables[i].guid = HCDP_TABLE_GUID;
			efi_tables[i].table = __pa(efi.hcdp);
			printf(" HCDP=0x%lx",efi_tables[i].table);
			i++;
		}
		printf("\n");
	} else {
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
	}

	/* fill in the SAL system table: */
	memcpy(sal_systab->signature, "SST_", 4);
	sal_systab->size = sizeof(*sal_systab);
	sal_systab->sal_rev_minor = 1;
	sal_systab->sal_rev_major = 0;
	sal_systab->entry_count = 1;

	strcpy((char *)sal_systab->oem_id, "Xen/ia64");
	strcpy((char *)sal_systab->product_id, "Xen/ia64");

	/* fill in an entry point: */
	sal_ed->type = SAL_DESC_ENTRY_POINT;
	sal_ed->pal_proc = FW_HYPERCALL_PAL_CALL_PADDR + start_mpaddr;
	dom_fw_pal_hypercall_patch (d, sal_ed->pal_proc);
	sal_ed->sal_proc = FW_HYPERCALL_SAL_CALL_PADDR + start_mpaddr;
	dom_fw_hypercall_patch (d, sal_ed->sal_proc, FW_HYPERCALL_SAL_CALL, 1);
	sal_ed->gp = 0;  // will be ignored

	for (cp = (char *) sal_systab; cp < (char *) efi_memmap; ++cp)
		checksum += *cp;

	sal_systab->checksum = -checksum;

	i = 0;
	if (d == dom0) {
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
		MAKE_MD(EFI_LOADER_DATA,EFI_MEMORY_WB,0*MB,1*MB, 0);
		/* hypercall patches live here, masquerade as reserved PAL memory */
		MAKE_MD(EFI_PAL_CODE,EFI_MEMORY_WB,HYPERCALL_START,HYPERCALL_END, 0);
		MAKE_MD(EFI_CONVENTIONAL_MEMORY,EFI_MEMORY_WB,HYPERCALL_END,maxmem-IA64_GRANULE_SIZE, 0);
/* hack */	MAKE_MD(EFI_CONVENTIONAL_MEMORY,EFI_MEMORY_WB,last_start,last_end,1);

		/* pass through the I/O port space */
		if (!running_on_sim) {
			efi_memory_desc_t *efi_get_io_md(void);
			efi_memory_desc_t *ia64_efi_io_md;
			u32 type;
			u64 iostart, ioend, ioattr;

			ia64_efi_io_md = efi_get_io_md();
			type = ia64_efi_io_md->type;
			iostart = ia64_efi_io_md->phys_addr;
			ioend = ia64_efi_io_md->phys_addr +
				(ia64_efi_io_md->num_pages << 12);
			ioattr = ia64_efi_io_md->attribute;
			MAKE_MD(type,ioattr,iostart,ioend, 1);
		}
		else MAKE_MD(EFI_RESERVED_TYPE,0,0,0,0);
	}
	else {
		MAKE_MD(EFI_LOADER_DATA,EFI_MEMORY_WB,0*MB,1*MB, 1);
		/* hypercall patches live here, masquerade as reserved PAL memory */
		MAKE_MD(EFI_PAL_CODE,EFI_MEMORY_WB,HYPERCALL_START,HYPERCALL_END, 1);
		MAKE_MD(EFI_CONVENTIONAL_MEMORY,EFI_MEMORY_WB,HYPERCALL_END,maxmem, 1);
		/* Create a dummy entry for IO ports, so that IO accesses are
		   trapped by Xen.  */
		MAKE_MD(EFI_MEMORY_MAPPED_IO_PORT_SPACE,EFI_MEMORY_UC,
			0x00000ffffc000000, 0x00000fffffffffff, 1);
		MAKE_MD(EFI_RESERVED_TYPE,0,0,0,0);
	}

	bp->efi_systab = dom_pa((unsigned long) fw_mem);
	bp->efi_memmap = dom_pa((unsigned long) efi_memmap);
	bp->efi_memmap_size = NUM_MEM_DESCS*sizeof(efi_memory_desc_t);
	bp->efi_memdesc_size = sizeof(efi_memory_desc_t);
	bp->efi_memdesc_version = 1;
	bp->command_line = dom_pa((unsigned long) cmd_line);
	bp->console_info.num_cols = 80;
	bp->console_info.num_rows = 25;
	bp->console_info.orig_x = 0;
	bp->console_info.orig_y = 24;
	bp->fpswa = 0;
	if (d == dom0) {
		bp->initrd_start = (dom0_start+dom0_size) -
		  (PAGE_ALIGN(ia64_boot_param->initrd_size) + 4*1024*1024);
		bp->initrd_size = ia64_boot_param->initrd_size;
	}
	else {
		bp->initrd_start = d->arch.initrd_start;
		bp->initrd_size  = d->arch.initrd_len;
	}
	printf(" initrd start 0x%lx", bp->initrd_start);
	printf(" initrd size 0x%lx\n", bp->initrd_size);
	return bp;
}
