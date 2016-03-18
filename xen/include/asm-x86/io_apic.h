#ifndef __ASM_IO_APIC_H
#define __ASM_IO_APIC_H

#include <xen/config.h>
#include <asm/types.h>
#include <asm/mpspec.h>
#include <asm/apicdef.h>
#include <asm/fixmap.h>
#include <xen/iommu.h>

/*
 * Intel IO-APIC support for SMP and UP systems.
 *
 * Copyright (C) 1997, 1998, 1999, 2000 Ingo Molnar
 */

#ifdef CONFIG_X86_IO_APIC

#define IO_APIC_BASE(idx) \
		((volatile int *)(__fix_to_virt(FIX_IO_APIC_BASE_0 + idx) \
		+ (mp_ioapics[idx].mpc_apicaddr & ~PAGE_MASK)))

#define IO_APIC_ID(idx) (mp_ioapics[idx].mpc_apicid)

/* I/O Unit Redirection Table */
#define IO_APIC_REDIR_VECTOR_MASK   0x000FF
#define IO_APIC_REDIR_DEST_LOGICAL  0x00800
#define IO_APIC_REDIR_DEST_PHYSICAL 0x00000
#define IO_APIC_REDIR_SEND_PENDING  (1 << 12)
#define IO_APIC_REDIR_REMOTE_IRR    (1 << 14)
#define IO_APIC_REDIR_LEVEL_TRIGGER (1 << 15)
#define IO_APIC_REDIR_MASKED        (1 << 16)

/*
 * The structure of the IO-APIC:
 */
union IO_APIC_reg_00 {
	u32	raw;
	struct __packed {
		u32	__reserved_2	: 14,
			LTS		:  1,
			delivery_type	:  1,
			__reserved_1	:  8,
			ID		:  8;
	} bits;
};

union IO_APIC_reg_01 {
	u32	raw;
	struct __packed {
		u32	version		:  8,
			__reserved_2	:  7,
			PRQ		:  1,
			entries		:  8,
			__reserved_1	:  8;
	} bits;
};

union IO_APIC_reg_02 {
	u32	raw;
	struct __packed {
		u32	__reserved_2	: 24,
			arbitration	:  4,
			__reserved_1	:  4;
	} bits;
};

union IO_APIC_reg_03 {
	u32	raw;
	struct __packed {
		u32	boot_DT		:  1,
			__reserved_1	: 31;
	} bits;
};

/*
 * # of IO-APICs and # of IRQ routing registers
 */
extern int nr_ioapics;
extern int nr_ioapic_entries[MAX_IO_APICS];

enum ioapic_irq_destination_types {
	dest_Fixed = 0,
	dest_LowestPrio = 1,
	dest_SMI = 2,
	dest__reserved_1 = 3,
	dest_NMI = 4,
	dest_INIT = 5,
	dest__reserved_2 = 6,
	dest_ExtINT = 7
};

struct __packed IO_APIC_route_entry {
	__u32	vector		:  8,
		delivery_mode	:  3,	/* 000: FIXED
					 * 001: lowest prio
					 * 111: ExtINT
					 */
		dest_mode	:  1,	/* 0: physical, 1: logical */
		delivery_status	:  1,
		polarity	:  1,
		irr		:  1,
		trigger		:  1,	/* 0: edge, 1: level */
		mask		:  1,	/* 0: enabled, 1: disabled */
		__reserved_2	: 15;

	union {		struct { __u32
					__reserved_1	: 24,
					physical_dest	:  4,
					__reserved_2	:  4;
			} physical;

			struct { __u32
					__reserved_1	: 24,
					logical_dest	:  8;
			} logical;

			/* used when Interrupt Remapping with EIM is enabled */
			__u32 dest32;
	} dest;

};

/*
 * MP-BIOS irq configuration table structures:
 */

/* I/O APIC entries */
extern struct mpc_config_ioapic mp_ioapics[MAX_IO_APICS];

/* Only need to remap ioapic RTE (reg: 10~3Fh) */
#define ioapic_reg_remapped(reg) (iommu_intremap && ((reg) >= 0x10))

static inline unsigned int __io_apic_read(unsigned int apic, unsigned int reg)
{
	*IO_APIC_BASE(apic) = reg;
	return *(IO_APIC_BASE(apic)+4);
}

static inline unsigned int io_apic_read(unsigned int apic, unsigned int reg)
{
	if (ioapic_reg_remapped(reg))
		return iommu_read_apic_from_ire(apic, reg);
	return __io_apic_read(apic, reg);
}

static inline void __io_apic_write(unsigned int apic, unsigned int reg, unsigned int value)
{
	*IO_APIC_BASE(apic) = reg;
	*(IO_APIC_BASE(apic)+4) = value;
}

static inline void io_apic_write(unsigned int apic, unsigned int reg, unsigned int value)
{
	if (ioapic_reg_remapped(reg))
		return iommu_update_ire_from_apic(apic, reg, value);
	__io_apic_write(apic, reg, value);
}

/*
 * Re-write a value: to be used for read-modify-write
 * cycles where the read already set up the index register.
 */
static inline void io_apic_modify(unsigned int apic, unsigned int reg, unsigned int value)
{
	if (ioapic_reg_remapped(reg))
		return iommu_update_ire_from_apic(apic, reg, value);
	*(IO_APIC_BASE(apic)+4) = value;
}

/* 1 if "noapic" boot option passed */
extern bool_t skip_ioapic_setup;
extern bool_t ioapic_ack_new;
extern bool_t ioapic_ack_forced;

extern int io_apic_get_unique_id (int ioapic, int apic_id);
extern int io_apic_get_version (int ioapic);
extern int io_apic_get_redir_entries (int ioapic);
extern int io_apic_set_pci_routing (int ioapic, int pin, int irq, int edge_level, int active_high_low);

extern void init_ioapic_mappings(void);

extern void ioapic_suspend(void);
extern void ioapic_resume(void);

extern void dump_ioapic_irq_info(void);

extern struct IO_APIC_route_entry __ioapic_read_entry(
    unsigned int apic, unsigned int pin, bool_t raw);
void __ioapic_write_entry(
    unsigned int apic, unsigned int pin, bool_t raw,
    struct IO_APIC_route_entry);

extern struct IO_APIC_route_entry **alloc_ioapic_entries(void);
extern void free_ioapic_entries(struct IO_APIC_route_entry **ioapic_entries);
extern int save_IO_APIC_setup(struct IO_APIC_route_entry **ioapic_entries);
extern void mask_IO_APIC_setup(struct IO_APIC_route_entry **ioapic_entries);
extern int restore_IO_APIC_setup(struct IO_APIC_route_entry **ioapic_entries);

#else  /* !CONFIG_X86_IO_APIC */
static inline void init_ioapic_mappings(void) {}
static inline void ioapic_suspend(void) {}
static inline void ioapic_resume(void) {}
#endif

unsigned highest_gsi(void);

int ioapic_guest_read( unsigned long physbase, unsigned int reg, u32 *pval);
int ioapic_guest_write(unsigned long physbase, unsigned int reg, u32 pval);

#endif
