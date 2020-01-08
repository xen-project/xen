/******************************************************************************
 * config.h
 * 
 * A Linux-style configuration list.
 */

#ifndef __X86_CONFIG_H__
#define __X86_CONFIG_H__

#define LONG_BYTEORDER 3
#define CONFIG_PAGING_LEVELS 4

#define BYTES_PER_LONG (1 << LONG_BYTEORDER)
#define BITS_PER_LONG (BYTES_PER_LONG << 3)
#define BITS_PER_BYTE 8
#define POINTER_ALIGN BYTES_PER_LONG

#define BITS_PER_LLONG 64

#define BITS_PER_XEN_ULONG BITS_PER_LONG

#define CONFIG_X86_PM_TIMER 1
#define CONFIG_HPET_TIMER 1
#define CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS 1
#define CONFIG_DISCONTIGMEM 1
#define CONFIG_NUMA_EMU 1
#define CONFIG_DOMAIN_PAGE 1

#define CONFIG_PAGEALLOC_MAX_ORDER (2 * PAGETABLE_ORDER)
#define CONFIG_DOMU_MAX_ORDER      PAGETABLE_ORDER
#define CONFIG_HWDOM_MAX_ORDER     12

/* Intel P4 currently has largest cache line (L2 line size is 128 bytes). */
#define CONFIG_X86_L1_CACHE_SHIFT 7

#define CONFIG_ACPI_NUMA 1
#define CONFIG_ACPI_SRAT 1
#define CONFIG_ACPI_CSTATE 1

#define CONFIG_WATCHDOG 1

#define CONFIG_MULTIBOOT 1

#define HZ 100

#define OPT_CONSOLE_STR "vga"

/* Linkage for x86 */
#ifdef __ASSEMBLY__
#define ALIGN .align 16,0x90
#define ENTRY(name)                             \
  .globl name;                                  \
  ALIGN;                                        \
  name:
#define GLOBAL(name)                            \
  .globl name;                                  \
  name:
#endif

#define NR_hypercalls 64

#ifndef NDEBUG
#define MEMORY_GUARD
#endif

#define STACK_ORDER 3
#define STACK_SIZE  (PAGE_SIZE << STACK_ORDER)

#define TRAMPOLINE_STACK_SPACE  PAGE_SIZE
#define TRAMPOLINE_SPACE        (KB(64) - TRAMPOLINE_STACK_SPACE)
#define WAKEUP_STACK_MIN        3072

#define MBI_SPACE_MIN           (2 * PAGE_SIZE)

/* Primary stack is restricted to 8kB by guard pages. */
#define PRIMARY_STACK_SIZE 8192

/* Total size of syscall and emulation stubs. */
#define STUB_BUF_SHIFT (L1_CACHE_SHIFT > 7 ? L1_CACHE_SHIFT : 7)
#define STUB_BUF_SIZE  (1 << STUB_BUF_SHIFT)
#define STUBS_PER_PAGE (PAGE_SIZE / STUB_BUF_SIZE)

/* Return value for zero-size _xmalloc(), distinguished from NULL. */
#define ZERO_BLOCK_PTR ((void *)0xBAD0BAD0BAD0BAD0UL)

/* Override include/xen/list.h to make these non-canonical addresses. */
#define LIST_POISON1  ((void *)0x0100100100100100UL)
#define LIST_POISON2  ((void *)0x0200200200200200UL)

#ifndef __ASSEMBLY__
extern unsigned long trampoline_phys;
#define bootsym_phys(sym)                                 \
    (((unsigned long)&(sym)-(unsigned long)&trampoline_start)+trampoline_phys)
#define bootsym(sym)                                      \
    (*((typeof(sym) *)__va(bootsym_phys(sym))))

extern char trampoline_start[], trampoline_end[];
extern char trampoline_realmode_entry[];
extern unsigned int trampoline_xen_phys_start;
extern unsigned char trampoline_cpu_started;
extern char wakeup_start[];

extern unsigned char video_flags;

extern unsigned short boot_edid_caps;
extern unsigned char boot_edid_info[128];
#endif

#include <xen/const.h>

#define PML4_ENTRY_BITS  39
#define PML4_ENTRY_BYTES (_AC(1,UL) << PML4_ENTRY_BITS)
#define PML4_ADDR(_slot)                              \
    (((_AC(_slot, UL) >> 8) * _AC(0xffff000000000000,UL)) | \
     (_AC(_slot, UL) << PML4_ENTRY_BITS))

/*
 * Memory layout:
 *  0x0000000000000000 - 0x00007fffffffffff [128TB, 2^47 bytes, PML4:0-255]
 *    Guest-defined use (see below for compatibility mode guests).
 *  0x0000800000000000 - 0xffff7fffffffffff [16EB]
 *    Inaccessible: current arch only supports 48-bit sign-extended VAs.
 *  0xffff800000000000 - 0xffff803fffffffff [256GB, 2^38 bytes, PML4:256]
 *    Read-only machine-to-phys translation table (GUEST ACCESSIBLE).
 *  0xffff804000000000 - 0xffff807fffffffff [256GB, 2^38 bytes, PML4:256]
 *    Reserved for future shared info with the guest OS (GUEST ACCESSIBLE).
 *  0xffff808000000000 - 0xffff80ffffffffff [512GB, 2^39 bytes, PML4:257]
 *    ioremap for PCI mmconfig space
 *  0xffff810000000000 - 0xffff817fffffffff [512GB, 2^39 bytes, PML4:258]
 *    Guest linear page table.
 *  0xffff818000000000 - 0xffff81ffffffffff [512GB, 2^39 bytes, PML4:259]
 *    Shadow linear page table.
 *  0xffff820000000000 - 0xffff827fffffffff [512GB, 2^39 bytes, PML4:260]
 *    Per-domain mappings (e.g., GDT, LDT).
 *  0xffff828000000000 - 0xffff82bfffffffff [256GB, 2^38 bytes, PML4:261]
 *    Machine-to-phys translation table.
 *  0xffff82c000000000 - 0xffff82cfffffffff [64GB,  2^36 bytes, PML4:261]
 *    vmap()/ioremap()/fixmap area.
 *  0xffff82d000000000 - 0xffff82d03fffffff [1GB,   2^30 bytes, PML4:261]
 *    Compatibility machine-to-phys translation table.
 *  0xffff82d040000000 - 0xffff82d07fffffff [1GB,   2^30 bytes, PML4:261]
 *    High read-only compatibility machine-to-phys translation table.
 *  0xffff82d080000000 - 0xffff82d0bfffffff [1GB,   2^30 bytes, PML4:261]
 *    Xen text, static data, bss.
#ifndef CONFIG_BIGMEM
 *  0xffff82d0c0000000 - 0xffff82dfffffffff [61GB,              PML4:261]
 *    Reserved for future use.
 *  0xffff82e000000000 - 0xffff82ffffffffff [128GB, 2^37 bytes, PML4:261]
 *    Page-frame information array.
 *  0xffff830000000000 - 0xffff87ffffffffff [5TB, 5*2^40 bytes, PML4:262-271]
 *    1:1 direct mapping of all physical memory.
#else
 *  0xffff82d0c0000000 - 0xffff82ffffffffff [189GB,             PML4:261]
 *    Reserved for future use.
 *  0xffff830000000000 - 0xffff847fffffffff [1.5TB, 3*2^39 bytes, PML4:262-264]
 *    Page-frame information array.
 *  0xffff848000000000 - 0xffff87ffffffffff [3.5TB, 7*2^39 bytes, PML4:265-271]
 *    1:1 direct mapping of all physical memory.
#endif
 *  0xffff880000000000 - 0xffffffffffffffff [120TB,             PML4:272-511]
 *    PV: Guest-defined use.
 *  0xffff880000000000 - 0xffffff7fffffffff [119.5TB,           PML4:272-510]
 *    HVM/idle: continuation of 1:1 mapping
 *  0xffffff8000000000 - 0xffffffffffffffff [512GB, 2^39 bytes  PML4:511]
 *    HVM/idle: unused
 *
 * Compatibility guest area layout:
 *  0x0000000000000000 - 0x00000000f57fffff [3928MB,            PML4:0]
 *    Guest-defined use.
 *  0x00000000f5800000 - 0x00000000ffffffff [168MB,             PML4:0]
 *    Read-only machine-to-phys translation table (GUEST ACCESSIBLE).
 *  0x0000000100000000 - 0x00007fffffffffff [128TB-4GB,         PML4:0-255]
 *    Unused / Reserved for future use.
 */


#define ROOT_PAGETABLE_FIRST_XEN_SLOT 256
#define ROOT_PAGETABLE_LAST_XEN_SLOT  271
#define ROOT_PAGETABLE_XEN_SLOTS \
    (L4_PAGETABLE_ENTRIES - ROOT_PAGETABLE_FIRST_XEN_SLOT - 1)
#define ROOT_PAGETABLE_PV_XEN_SLOTS \
    (ROOT_PAGETABLE_LAST_XEN_SLOT - ROOT_PAGETABLE_FIRST_XEN_SLOT + 1)

/* Hypervisor reserves PML4 slots 256 to 271 inclusive. */
#define HYPERVISOR_VIRT_START   (PML4_ADDR(256))
#define HYPERVISOR_VIRT_END     (HYPERVISOR_VIRT_START + PML4_ENTRY_BYTES*16)
/* Slot 256: read-only guest-accessible machine-to-phys translation table. */
#define RO_MPT_VIRT_START       (PML4_ADDR(256))
#define MPT_VIRT_SIZE           (PML4_ENTRY_BYTES / 2)
#define RO_MPT_VIRT_END         (RO_MPT_VIRT_START + MPT_VIRT_SIZE)
/* Slot 257: ioremap for PCI mmconfig space for 2048 segments (512GB)
 *     - full 16-bit segment support needs 44 bits
 *     - since PML4 slot has 39 bits, we limit segments to 2048 (11-bits)
 */
#define PCI_MCFG_VIRT_START     (PML4_ADDR(257))
#define PCI_MCFG_VIRT_END       (PCI_MCFG_VIRT_START + PML4_ENTRY_BYTES)
/* Slot 258: linear page table (guest table). */
#define LINEAR_PT_VIRT_START    (PML4_ADDR(258))
#define LINEAR_PT_VIRT_END      (LINEAR_PT_VIRT_START + PML4_ENTRY_BYTES)
/* Slot 259: linear page table (shadow table). */
#define SH_LINEAR_PT_VIRT_START (PML4_ADDR(259))
#define SH_LINEAR_PT_VIRT_END   (SH_LINEAR_PT_VIRT_START + PML4_ENTRY_BYTES)
/* Slot 260: per-domain mappings (including map cache). */
#define PERDOMAIN_VIRT_START    (PML4_ADDR(260))
#define PERDOMAIN_SLOT_MBYTES   (PML4_ENTRY_BYTES >> (20 + PAGETABLE_ORDER))
#define PERDOMAIN_SLOTS         3
#define PERDOMAIN_VIRT_SLOT(s)  (PERDOMAIN_VIRT_START + (s) * \
                                 (PERDOMAIN_SLOT_MBYTES << 20))
/* Slot 261: machine-to-phys conversion table (256GB). */
#define RDWR_MPT_VIRT_START     (PML4_ADDR(261))
#define RDWR_MPT_VIRT_END       (RDWR_MPT_VIRT_START + MPT_VIRT_SIZE)
/* Slot 261: vmap()/ioremap()/fixmap area (64GB). */
#define VMAP_VIRT_START         RDWR_MPT_VIRT_END
#define VMAP_VIRT_END           (VMAP_VIRT_START + GB(64))
/* Slot 261: compatibility machine-to-phys conversion table (1GB). */
#define RDWR_COMPAT_MPT_VIRT_START VMAP_VIRT_END
#define RDWR_COMPAT_MPT_VIRT_END (RDWR_COMPAT_MPT_VIRT_START + GB(1))
/* Slot 261: high read-only compat machine-to-phys conversion table (1GB). */
#define HIRO_COMPAT_MPT_VIRT_START RDWR_COMPAT_MPT_VIRT_END
#define HIRO_COMPAT_MPT_VIRT_END (HIRO_COMPAT_MPT_VIRT_START + GB(1))
/* Slot 261: xen text, static data, bss, per-cpu stubs and executable fixmap (1GB). */
#define XEN_VIRT_START          (HIRO_COMPAT_MPT_VIRT_END)
#define XEN_VIRT_END            (XEN_VIRT_START + GB(1))

#ifndef CONFIG_BIGMEM
/* Slot 261: page-frame information array (128GB). */
#define FRAMETABLE_SIZE         GB(128)
#else
/* Slot 262-264: page-frame information array (1.5TB). */
#define FRAMETABLE_SIZE         GB(1536)
#endif
#define FRAMETABLE_VIRT_END     DIRECTMAP_VIRT_START
#define FRAMETABLE_NR           (FRAMETABLE_SIZE / sizeof(*frame_table))
#define FRAMETABLE_VIRT_START   (FRAMETABLE_VIRT_END - FRAMETABLE_SIZE)

#ifndef CONFIG_BIGMEM
/* Slot 262-271/510: A direct 1:1 mapping of all of physical memory. */
#define DIRECTMAP_VIRT_START    (PML4_ADDR(262))
#define DIRECTMAP_SIZE          (PML4_ENTRY_BYTES * (511 - 262))
#else
/* Slot 265-271/510: A direct 1:1 mapping of all of physical memory. */
#define DIRECTMAP_VIRT_START    (PML4_ADDR(265))
#define DIRECTMAP_SIZE          (PML4_ENTRY_BYTES * (511 - 265))
#endif
#define DIRECTMAP_VIRT_END      (DIRECTMAP_VIRT_START + DIRECTMAP_SIZE)

#ifndef __ASSEMBLY__

/* This is not a fixed value, just a lower limit. */
#define __HYPERVISOR_COMPAT_VIRT_START 0xF5800000
#define HYPERVISOR_COMPAT_VIRT_START(d) ((d)->arch.hv_compat_vstart)
#define MACH2PHYS_COMPAT_VIRT_START    HYPERVISOR_COMPAT_VIRT_START
#define MACH2PHYS_COMPAT_VIRT_END      0xFFE00000
#define MACH2PHYS_COMPAT_NR_ENTRIES(d) \
    ((MACH2PHYS_COMPAT_VIRT_END-MACH2PHYS_COMPAT_VIRT_START(d))>>2)

#define COMPAT_L2_PAGETABLE_FIRST_XEN_SLOT(d) \
    l2_table_offset(HYPERVISOR_COMPAT_VIRT_START(d))
#define COMPAT_L2_PAGETABLE_LAST_XEN_SLOT  l2_table_offset(~0U)
#define COMPAT_L2_PAGETABLE_XEN_SLOTS(d) \
    (COMPAT_L2_PAGETABLE_LAST_XEN_SLOT - COMPAT_L2_PAGETABLE_FIRST_XEN_SLOT(d) + 1)

#define COMPAT_LEGACY_MAX_VCPUS XEN_LEGACY_MAX_VCPUS
#define COMPAT_HAVE_PV_GUEST_ENTRY XEN_HAVE_PV_GUEST_ENTRY
#define COMPAT_HAVE_PV_UPCALL_MASK XEN_HAVE_PV_UPCALL_MASK

#endif

#define __HYPERVISOR_CS   0xe008
#define __HYPERVISOR_DS64 0x0000
#define __HYPERVISOR_DS32 0xe010
#define __HYPERVISOR_DS   __HYPERVISOR_DS64

#define SYMBOLS_ORIGIN XEN_VIRT_START

/* For generic assembly code: use macros to define operation/operand sizes. */
#define __OS          "q"  /* Operation Suffix */
#define __OP          "r"  /* Operand Prefix */

#ifndef __ASSEMBLY__
extern unsigned long xen_phys_start;
#endif

/* GDT/LDT shadow mapping area. The first per-domain-mapping sub-area. */
#define GDT_LDT_VCPU_SHIFT       5
#define GDT_LDT_VCPU_VA_SHIFT    (GDT_LDT_VCPU_SHIFT + PAGE_SHIFT)
#define GDT_LDT_MBYTES           PERDOMAIN_SLOT_MBYTES
#define MAX_VIRT_CPUS            (GDT_LDT_MBYTES << (20-GDT_LDT_VCPU_VA_SHIFT))
#define GDT_LDT_VIRT_START       PERDOMAIN_VIRT_SLOT(0)
#define GDT_LDT_VIRT_END         (GDT_LDT_VIRT_START + (GDT_LDT_MBYTES << 20))

/* The address of a particular VCPU's GDT or LDT. */
#define GDT_VIRT_START(v)    \
    (PERDOMAIN_VIRT_START + ((v)->vcpu_id << GDT_LDT_VCPU_VA_SHIFT))
#define LDT_VIRT_START(v)    \
    (GDT_VIRT_START(v) + (64*1024))

/* map_domain_page() map cache. The second per-domain-mapping sub-area. */
#define MAPCACHE_VCPU_ENTRIES    (CONFIG_PAGING_LEVELS * CONFIG_PAGING_LEVELS)
#define MAPCACHE_ENTRIES         (MAX_VIRT_CPUS * MAPCACHE_VCPU_ENTRIES)
#define MAPCACHE_VIRT_START      PERDOMAIN_VIRT_SLOT(1)
#define MAPCACHE_VIRT_END        (MAPCACHE_VIRT_START + \
                                  MAPCACHE_ENTRIES * PAGE_SIZE)

/* Argument translation area. The third per-domain-mapping sub-area. */
#define ARG_XLAT_VIRT_START      PERDOMAIN_VIRT_SLOT(2)
/* Allow for at least one guard page (COMPAT_ARG_XLAT_SIZE being 2 pages): */
#define ARG_XLAT_VA_SHIFT        (2 + PAGE_SHIFT)
#define ARG_XLAT_START(v)        \
    (ARG_XLAT_VIRT_START + ((v)->vcpu_id << ARG_XLAT_VA_SHIFT))

#define NATIVE_VM_ASSIST_VALID   ((1UL << VMASST_TYPE_4gb_segments)        | \
                                  (1UL << VMASST_TYPE_4gb_segments_notify) | \
                                  (1UL << VMASST_TYPE_writable_pagetables) | \
                                  (1UL << VMASST_TYPE_pae_extended_cr3)    | \
                                  (1UL << VMASST_TYPE_architectural_iopl)  | \
                                  (1UL << VMASST_TYPE_runstate_update_flag)| \
                                  (1UL << VMASST_TYPE_m2p_strict))
#define VM_ASSIST_VALID          NATIVE_VM_ASSIST_VALID
#define COMPAT_VM_ASSIST_VALID   (NATIVE_VM_ASSIST_VALID & \
                                  ((1UL << COMPAT_BITS_PER_LONG) - 1))

#define ELFSIZE 64

#define ARCH_CRASH_SAVE_VMCOREINFO

#endif /* __X86_CONFIG_H__ */
