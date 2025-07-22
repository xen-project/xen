/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef XEN_BOOTFDT_H
#define XEN_BOOTFDT_H

#include <xen/byteorder.h>
#include <xen/bug.h>
#include <xen/types.h>
#include <xen/lib.h>

#if __has_include(<asm/bootfdt.h>)
#include <asm/bootfdt.h>
#endif

#define MIN_FDT_ALIGN 8

/* Default #address and #size cells */
#define DT_ROOT_NODE_ADDR_CELLS_DEFAULT 2
#define DT_ROOT_NODE_SIZE_CELLS_DEFAULT 1

#define DEVICE_TREE_MAX_DEPTH 16

/* Helper to read a big number; size is in cells (not bytes) */
static inline u64 dt_read_number(const __be32 *cell, int size)
{
    u64 r = be32_to_cpu(*cell);

    switch ( size )
    {
    case 1:
        break;
    case 2:
        r = (r << 32) | be32_to_cpu(cell[1]);
        break;
    default:
        /* Nonsensical size. default to 1 */
        printk(XENLOG_ERR "dt_read_number(,%d) bad size\n", size);
        ASSERT_UNREACHABLE();
        break;
    };

    return r;
}

/* Wrapper for dt_read_number() to return paddr_t (instead of uint64_t) */
static inline paddr_t dt_read_paddr(const __be32 *cell, int size)
{
    uint64_t dt_r;
    paddr_t r;

    /*
     * dt_read_number will return uint64_t whereas paddr_t may not be 64-bit.
     * Thus, there is an implicit cast from uint64_t to paddr_t.
     */
    dt_r = dt_read_number(cell, size);

    if ( dt_r != (paddr_t)dt_r )
    {
        printk("Physical address greater than max width supported\n");
        WARN();
    }

    /*
     * Xen will truncate the address/size if it is greater than the maximum
     * supported width and it will give an appropriate warning.
     */
    r = dt_r;

    return r;
}

static inline u64 dt_next_cell(int s, const __be32 **cellp)
{
    const __be32 *p = *cellp;

    *cellp = p + s;
    return dt_read_number(p, s);
}

typedef int (*device_tree_node_func)(const void *fdt,
                                     int node, const char *name, int depth,
                                     u32 address_cells, u32 size_cells,
                                     void *data);

/**
 * device_tree_for_each_node - iterate over all device tree sub-nodes
 * @fdt: flat device tree.
 * @node: parent node to start the search from
 * @func: function to call for each sub-node.
 * @data: data to pass to @func.
 *
 * Any nodes nested at DEVICE_TREE_MAX_DEPTH or deeper are ignored.
 *
 * Returns 0 if all nodes were iterated over successfully.  If @func
 * returns a value different from 0, that value is returned immediately.
 */
int device_tree_for_each_node(const void *fdt, int node,
                              device_tree_node_func func,
                              void *data);

typedef enum {
    BOOTMOD_XEN,
    BOOTMOD_FDT,
    BOOTMOD_KERNEL,
    BOOTMOD_RAMDISK,
    BOOTMOD_XSM_POLICY,
    BOOTMOD_GUEST_DTB,
    BOOTMOD_MICROCODE,
    BOOTMOD_UNKNOWN
}  boot_module_kind;

struct boot_domain {
    struct domain *d;

#ifdef CONFIG_X86
    domid_t domid;
#endif

    struct boot_module *kernel;
    struct boot_module *initrd;

    const char *cmdline;
};

#define BOOTMOD_MAX_CMDLINE 1024
struct boot_module {
    boot_module_kind kind;
#ifndef CONFIG_X86
    /*
     * The domU flag is set for kernels and ramdisks of "xen,domain" nodes.
     * The purpose of the domU flag is to avoid getting confused in
     * kernel_probe, where we try to guess which is the dom0 kernel and
     * initrd to be compatible with all versions of the multiboot spec.
     */
    bool domU;
#endif
    paddr_t start;
    paddr_t size;

#if __has_include(<asm/bootfdt.h>)
    struct arch_boot_module arch;
#endif
};

/*
 * Interpret the property `prop_name` of `node` as a u32.
 *
 * Returns the property value on success; otherwise returns `dflt`.
 */
u32 device_tree_get_u32(const void *fdt, int node,
                        const char *prop_name, u32 dflt);

/*
 * Interpret the property `prop_name` of `node` as a "reg".
 *
 * Returns outputs in `start` and `size`.
 */
void device_tree_get_reg(const __be32 **cell, uint32_t address_cells,
                         uint32_t size_cells, paddr_t *start, paddr_t *size);

#endif /* XEN_BOOTFDT_H */
