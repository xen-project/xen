#ifndef XC_EFI_H
#define XC_EFI_H

/* definitions from xen/include/asm-ia64/linux-xen/linux/efi.h */

/*
 * Extensible Firmware Interface
 * Based on 'Extensible Firmware Interface Specification' version 0.9, April 30, 1999
 *
 * Copyright (C) 1999 VA Linux Systems
 * Copyright (C) 1999 Walt Drummond <drummond@valinux.com>
 * Copyright (C) 1999, 2002-2003 Hewlett-Packard Co.
 *	David Mosberger-Tang <davidm@hpl.hp.com>
 *	Stephane Eranian <eranian@hpl.hp.com>
 */

/*
 * Memory map descriptor:
 */

/* Memory types: */
#define EFI_RESERVED_TYPE                0
#define EFI_LOADER_CODE                  1
#define EFI_LOADER_DATA                  2
#define EFI_BOOT_SERVICES_CODE           3
#define EFI_BOOT_SERVICES_DATA           4
#define EFI_RUNTIME_SERVICES_CODE        5
#define EFI_RUNTIME_SERVICES_DATA        6
#define EFI_CONVENTIONAL_MEMORY          7
#define EFI_UNUSABLE_MEMORY              8
#define EFI_ACPI_RECLAIM_MEMORY          9
#define EFI_ACPI_MEMORY_NVS             10
#define EFI_MEMORY_MAPPED_IO            11
#define EFI_MEMORY_MAPPED_IO_PORT_SPACE 12
#define EFI_PAL_CODE                    13
#define EFI_MAX_MEMORY_TYPE             14

/* Attribute values: */
#define EFI_MEMORY_UC           ((uint64_t)0x0000000000000001ULL)    /* uncached */
#define EFI_MEMORY_WC           ((uint64_t)0x0000000000000002ULL)    /* write-coalescing */
#define EFI_MEMORY_WT           ((uint64_t)0x0000000000000004ULL)    /* write-through */
#define EFI_MEMORY_WB           ((uint64_t)0x0000000000000008ULL)    /* write-back */
#define EFI_MEMORY_WP           ((uint64_t)0x0000000000001000ULL)    /* write-protect */
#define EFI_MEMORY_RP           ((uint64_t)0x0000000000002000ULL)    /* read-protect */
#define EFI_MEMORY_XP           ((uint64_t)0x0000000000004000ULL)    /* execute-protect */
#define EFI_MEMORY_RUNTIME      ((uint64_t)0x8000000000000000ULL)    /* range requires runtime mapping */
#define EFI_MEMORY_DESCRIPTOR_VERSION   1

#define EFI_PAGE_SHIFT          12

/*
 * For current x86 implementations of EFI, there is
 * additional padding in the mem descriptors.  This is not
 * the case in ia64.  Need to have this fixed in the f/w.
 */
typedef struct {
        uint32_t type;
        uint32_t pad;
        uint64_t phys_addr;
        uint64_t virt_addr;
        uint64_t num_pages;
        uint64_t attribute;
#if defined (__i386__)
        uint64_t pad1;
#endif
} efi_memory_desc_t;

#endif /* XC_EFI_H */
