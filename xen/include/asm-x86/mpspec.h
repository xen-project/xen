#ifndef __ASM_MPSPEC_H
#define __ASM_MPSPEC_H

#include <xen/cpumask.h>
#include <asm/mpspec_def.h>
#include <mach_mpspec.h>

extern unsigned char mp_bus_id_to_type[MAX_MP_BUSSES];

extern bool def_to_bigsmp;
extern unsigned int boot_cpu_physical_apicid;
extern bool smp_found_config;
extern void find_smp_config (void);
extern void get_smp_config (void);
extern unsigned char apic_version [MAX_APICS];
extern int mp_irq_entries;
extern struct mpc_config_intsrc mp_irqs [MAX_IRQ_SOURCES];
extern int mpc_default_type;
extern unsigned long mp_lapic_addr;
extern bool pic_mode;

#ifdef CONFIG_ACPI
extern int mp_register_lapic(u32 id, bool enabled, bool hotplug);
extern void mp_unregister_lapic(uint32_t apic_id, uint32_t cpu);
extern void mp_register_lapic_address (u64 address);
extern void mp_register_ioapic (u8 id, u32 address, u32 gsi_base);
extern void mp_override_legacy_irq (u8 bus_irq, u8 polarity, u8 trigger, u32 gsi);
extern void mp_config_acpi_legacy_irqs (void);
extern int mp_register_gsi (u32 gsi, int edge_level, int active_high_low);
#endif /* CONFIG_ACPI */

#define PHYSID_ARRAY_SIZE	BITS_TO_LONGS(MAX_APICS)

struct physid_mask
{
	unsigned long mask[PHYSID_ARRAY_SIZE];
};

typedef struct physid_mask physid_mask_t;

#define physid_set(physid, map)			set_bit(physid, (map).mask)
#define physid_clear(physid, map)		clear_bit(physid, (map).mask)
#define physid_isset(physid, map)		test_bit(physid, (map).mask)
#define physid_test_and_set(physid, map)	test_and_set_bit(physid, (map).mask)

#define first_physid(map)			find_first_bit((map).mask, \
							       MAX_APICS)
#define next_physid(id, map)			find_next_bit((map).mask, \
							      MAX_APICS, (id) + 1)
#define last_physid(map) ({ \
	const unsigned long *mask = (map).mask; \
	unsigned int id, last = MAX_APICS; \
	for (id = find_first_bit(mask, MAX_APICS); id < MAX_APICS; \
	     id = find_next_bit(mask, MAX_APICS, (id) + 1)) \
		last = id; \
	last; \
})

#define physids_and(dst, src1, src2)		bitmap_and((dst).mask, (src1).mask, (src2).mask, MAX_APICS)
#define physids_or(dst, src1, src2)		bitmap_or((dst).mask, (src1).mask, (src2).mask, MAX_APICS)
#define physids_clear(map)			bitmap_zero((map).mask, MAX_APICS)
#define physids_complement(dst, src)		bitmap_complement((dst).mask,(src).mask, MAX_APICS)
#define physids_empty(map)			bitmap_empty((map).mask, MAX_APICS)
#define physids_equal(map1, map2)		bitmap_equal((map1).mask, (map2).mask, MAX_APICS)
#define physids_weight(map)			bitmap_weight((map).mask, MAX_APICS)

#define PHYSID_MASK_ALL		{ {[0 ... PHYSID_ARRAY_SIZE-1] = ~0UL} }
#define PHYSID_MASK_NONE	{ {[0 ... PHYSID_ARRAY_SIZE-1] = 0UL} }

extern physid_mask_t phys_cpu_present_map;

#endif

