/* SPDX-License-Identifier: MIT */
/******************************************************************************
 * kexec.h - Public portion
 *
 * Xen port written by:
 * - Simon 'Horms' Horman <horms@verge.net.au>
 * - Magnus Damm <magnus@valinux.co.jp>
 */

#ifndef _XEN_PUBLIC_KEXEC_H
#define _XEN_PUBLIC_KEXEC_H


/* This file describes the Kexec / Kdump hypercall interface for Xen.
 *
 * Kexec under vanilla Linux allows a user to reboot the physical machine
 * into a new user-specified kernel. The Xen port extends this idea
 * to allow rebooting of the machine from dom0. When kexec for dom0
 * is used to reboot,  both the hypervisor and the domains get replaced
 * with some other kernel. It is possible to kexec between vanilla
 * Linux and Xen and back again. Xen to Xen works well too.
 *
 * The hypercall interface for kexec can be divided into three main
 * types of hypercall operations:
 *
 * 1) Range information:
 *    This is used by the dom0 kernel to ask the hypervisor about various
 *    address information. This information is needed to allow kexec-tools
 *    to fill in the ELF headers for /proc/vmcore properly.
 *
 * 2) Load and unload of images:
 *    There are no big surprises here, the kexec binary from kexec-tools
 *    runs in userspace in dom0. The tool loads/unloads data into the
 *    dom0 kernel such as new kernel, initramfs and hypervisor. When
 *    loaded the dom0 kernel performs a load hypercall operation, and
 *    before releasing all page references the dom0 kernel calls unload.
 *
 * 3) Kexec operation:
 *    This is used to start a previously loaded kernel.
 */

#include "xen.h"

/*
 * Prototype for this hypercall is:
 *  int kexec_op(unsigned long cmd, void *args)
 * @cmd  == KEXEC_CMD_...
 *          KEXEC operation to perform
 * @args == Operation-specific extra arguments (NULL if none).
 */

/*
 * Kexec supports two types of operation:
 * - kexec into a regular kernel, very similar to a standard reboot
 *   - KEXEC_TYPE_DEFAULT is used to specify this type
 * - kexec into a special "crash kernel", aka kexec-on-panic
 *   - KEXEC_TYPE_CRASH is used to specify this type
 *   - parts of our system may be broken at kexec-on-panic time
 *     - the code should be kept as simple and self-contained as possible
 */

#define KEXEC_TYPE_DEFAULT 0
#define KEXEC_TYPE_CRASH   1

/*
 * Perform kexec having previously loaded a kexec or kdump kernel
 * as appropriate.
 * type == KEXEC_TYPE_DEFAULT or KEXEC_TYPE_CRASH [in]
 *
 * Control is transferred to the image entry point with the host in
 * the following state.
 *
 * - The image may be executed on any PCPU and all other PCPUs are
 *   stopped.
 *
 * - Local interrupts are disabled.
 *
 * - Register values are undefined.
 *
 * - The image segments have writeable 1:1 virtual to machine
 *   mappings.  The location of any page tables is undefined and these
 *   page table frames are not be mapped.
 */
#define KEXEC_CMD_kexec                 0
typedef struct xen_kexec_exec {
    int type;
} xen_kexec_exec_t;

/*
 * Obsolete since Xen 4.4.  Removed in Xen 4.23
 *
#define KEXEC_CMD_kexec_load_v1         1
#define KEXEC_CMD_kexec_unload_v1       2
 */

#define KEXEC_RANGE_MA_CRASH      0 /* machine address and size of crash area */
#define KEXEC_RANGE_MA_XEN        1 /* machine address and size of Xen itself */
#define KEXEC_RANGE_MA_CPU        2 /* machine address and size of a CPU note */
#define KEXEC_RANGE_MA_XENHEAP    3 /* machine address and size of xenheap
                                     * Note that although this is adjacent
                                     * to Xen it exists in a separate EFI
                                     * region on ia64, and thus needs to be
                                     * inserted into iomem_machine separately */
#define KEXEC_RANGE_MA_BOOT_PARAM 4 /* Obsolete: machine address and size of
                                     * the ia64_boot_param */
#define KEXEC_RANGE_MA_EFI_MEMMAP 5 /* machine address and size of
                                     * of the EFI Memory Map */
#define KEXEC_RANGE_MA_VMCOREINFO 6 /* machine address and size of vmcoreinfo */

/*
 * Find the address and size of certain memory areas
 * range == KEXEC_RANGE_... [in]
 * nr    == physical CPU number (starting from 0) if KEXEC_RANGE_MA_CPU [in]
 * size  == number of bytes reserved in window [out]
 * start == address of the first byte in the window [out]
 */
#define KEXEC_CMD_kexec_get_range       3
typedef struct xen_kexec_range {
    int range;
    int nr;
    unsigned long size;
    unsigned long start;
} xen_kexec_range_t;

/*
 * A contiguous chunk of a kexec image and it's destination machine
 * address.
 */
typedef struct xen_kexec_segment {
    union {
        XEN_GUEST_HANDLE(const_void) h;
        uint64_t _pad;
    } buf;
    uint64_t buf_size;
    uint64_t dest_maddr;
    uint64_t dest_size;
} xen_kexec_segment_t;
DEFINE_XEN_GUEST_HANDLE(xen_kexec_segment_t);

/*
 * Load a kexec image into memory.
 *
 * For KEXEC_TYPE_DEFAULT images, the segments may be anywhere in RAM.
 * The image is relocated prior to being executed.
 *
 * For KEXEC_TYPE_CRASH images, each segment of the image must reside
 * in the memory region reserved for kexec (KEXEC_RANGE_MA_CRASH) and
 * the entry point must be within the image. The caller is responsible
 * for ensuring that multiple images do not overlap.
 *
 * All image segments will be loaded to their destination machine
 * addresses prior to being executed.  The trailing portion of any
 * segments with a source buffer (from dest_maddr + buf_size to
 * dest_maddr + dest_size) will be zeroed.
 *
 * Segments with no source buffer will be accessible to the image when
 * it is executed.
 */

#define KEXEC_CMD_kexec_load 4
typedef struct xen_kexec_load {
    uint8_t  type;        /* One of KEXEC_TYPE_* */
    uint8_t  _pad;
    uint16_t arch;        /* ELF machine type (EM_*). */
    uint32_t nr_segments;
    union {
        XEN_GUEST_HANDLE(xen_kexec_segment_t) h;
        uint64_t _pad;
    } segments;
    uint64_t entry_maddr; /* image entry point machine address. */
} xen_kexec_load_t;
DEFINE_XEN_GUEST_HANDLE(xen_kexec_load_t);

/*
 * Unload a kexec image.
 *
 * Type must be one of KEXEC_TYPE_DEFAULT or KEXEC_TYPE_CRASH.
 */
#define KEXEC_CMD_kexec_unload 5
typedef struct xen_kexec_unload {
    uint8_t type;
} xen_kexec_unload_t;
DEFINE_XEN_GUEST_HANDLE(xen_kexec_unload_t);

/*
 * Figure out whether we have an image loaded. A return value of
 * zero indicates no image loaded. A return value of one
 * indicates an image is loaded. A negative return value
 * indicates an error.
 *
 * Type must be one of KEXEC_TYPE_DEFAULT or KEXEC_TYPE_CRASH.
 */
#define KEXEC_CMD_kexec_status 6
typedef struct xen_kexec_status {
    uint8_t type;
} xen_kexec_status_t;
DEFINE_XEN_GUEST_HANDLE(xen_kexec_status_t);

#endif /* _XEN_PUBLIC_KEXEC_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
