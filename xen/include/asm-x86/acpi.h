#ifndef _ASM_X86_ACPI_H
#define _ASM_X86_ACPI_H

/*
 *  Copyright (C) 2001 Paul Diefenbaugh <paul.s.diefenbaugh@intel.com>
 *  Copyright (C) 2001 Patrick Mochel <mochel@osdl.org>
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; If not, see <http://www.gnu.org/licenses/>.
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */

#include <acpi/pdc_intel.h>
#include <acpi/acconfig.h>
#include <acpi/actbl.h>
#include <xen/errno.h>

#define COMPILER_DEPENDENT_INT64   long long
#define COMPILER_DEPENDENT_UINT64  unsigned long long

/*
 * Calling conventions:
 *
 * ACPI_SYSTEM_XFACE        - Interfaces to host OS (handlers, threads)
 * ACPI_EXTERNAL_XFACE      - External ACPI interfaces
 * ACPI_INTERNAL_XFACE      - Internal ACPI interfaces
 * ACPI_INTERNAL_VAR_XFACE  - Internal variable-parameter list interfaces
 */
#define ACPI_SYSTEM_XFACE
#define ACPI_EXTERNAL_XFACE
#define ACPI_INTERNAL_XFACE
#define ACPI_INTERNAL_VAR_XFACE

/* Asm macros */

#define ACPI_ASM_MACROS
#define BREAKPOINT3
#define ACPI_DISABLE_IRQS() local_irq_disable()
#define ACPI_ENABLE_IRQS()  local_irq_enable()
#define ACPI_FLUSH_CPU_CACHE()	wbinvd()

int __acpi_acquire_global_lock(unsigned int *lock);
int __acpi_release_global_lock(unsigned int *lock);

#define ACPI_ACQUIRE_GLOBAL_LOCK(facs, Acq) \
	((Acq) = __acpi_acquire_global_lock(&facs->global_lock))

#define ACPI_RELEASE_GLOBAL_LOCK(facs, Acq) \
	((Acq) = __acpi_release_global_lock(&facs->global_lock))

/*
 * Math helper asm macros
 */
#define ACPI_DIV_64_BY_32(n_hi, n_lo, d32, q32, r32) \
	asm("divl %2;"				     \
	    :"=a"(q32), "=d"(r32)		     \
	    :"r"(d32),				     \
	     "0"(n_lo), "1"(n_hi))


#define ACPI_SHIFT_RIGHT_64(n_hi, n_lo) \
	asm("shrl   $1,%2	;"	\
	    "rcrl   $1,%3;"		\
	    :"=r"(n_hi), "=r"(n_lo)	\
	    :"0"(n_hi), "1"(n_lo))

extern bool acpi_lapic, acpi_ioapic, acpi_noirq;
extern bool acpi_force, acpi_ht, acpi_disabled;
extern u32 acpi_smi_cmd;
extern u8 acpi_enable_value, acpi_disable_value;
void acpi_pic_sci_set_trigger(unsigned int, u16);

static inline void disable_acpi(void)
{
	acpi_disabled = 1;
	acpi_ht = 0;
	acpi_noirq = 1;
}

static inline void acpi_noirq_set(void) { acpi_noirq = 1; }

/* routines for saving/restoring kernel state */
extern int acpi_save_state_mem(void);
extern int acpi_save_state_disk(void);
extern void acpi_restore_state_mem(void);

extern unsigned long acpi_wakeup_address;

#define ARCH_HAS_POWER_INIT	1

extern s8 acpi_numa;
extern int acpi_scan_nodes(u64 start, u64 end);
#define NR_NODE_MEMBLKS (MAX_NUMNODES*2)

extern struct acpi_sleep_info acpi_sinfo;
#define acpi_video_flags bootsym(video_flags)
struct xenpf_enter_acpi_sleep;
extern int acpi_enter_sleep(struct xenpf_enter_acpi_sleep *sleep);
extern int acpi_enter_state(u32 state);

struct acpi_sleep_info {
    struct acpi_generic_address pm1a_cnt_blk;
    struct acpi_generic_address pm1b_cnt_blk;
    struct acpi_generic_address pm1a_evt_blk;
    struct acpi_generic_address pm1b_evt_blk;
    struct acpi_generic_address sleep_control;
    struct acpi_generic_address sleep_status;
    union {
        uint16_t pm1a_cnt_val;
        uint8_t sleep_type_a;
    };
    union {
        uint16_t pm1b_cnt_val;
        uint8_t sleep_type_b;
    };
    uint32_t sleep_state;
    uint64_t wakeup_vector;
    uint32_t vector_width;
    bool_t sleep_extended;
};

#define MAX_MADT_ENTRIES	MAX(256, 2 * NR_CPUS)
extern u32 x86_acpiid_to_apicid[];
#define MAX_LOCAL_APIC		MAX(256, 4 * NR_CPUS)

#define INVALID_ACPIID		(-1U)

extern u32 pmtmr_ioport;
extern unsigned int pmtmr_width;

int acpi_dmar_init(void);
int acpi_ivrs_init(void);

static inline int acpi_iommu_init(void)
{
    int ret = acpi_dmar_init();

    return ret == -ENODEV ? acpi_ivrs_init() : ret;
}

void acpi_mmcfg_init(void);

/* Incremented whenever we transition through S3. Value is 1 during boot. */
extern uint32_t system_reset_counter;

void hvm_acpi_power_button(struct domain *d);
void hvm_acpi_sleep_button(struct domain *d);

/* suspend/resume */
void save_rest_processor_state(void);
void restore_rest_processor_state(void);

#define ACPI_MAP_MEM_ATTR	PAGE_HYPERVISOR_UCMINUS

#endif /*__X86_ASM_ACPI_H*/
