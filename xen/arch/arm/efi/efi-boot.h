/*
 * Architecture specific implementation for EFI boot code.  This file
 * is intended to be included by common/efi/boot.c _only_, and
 * therefore can define arch specific global variables.
 */
#include <xen/device_tree.h>
#include <xen/libfdt/libfdt.h>
#include <asm/setup.h>
#include <asm/smp.h>
#include "efi-dom0.h"

void noreturn efi_xen_start(void *fdt_ptr, uint32_t fdt_size);
void __flush_dcache_area(const void *vaddr, unsigned long size);

#define DEVICE_TREE_GUID \
{0xb1b621d5, 0xf19c, 0x41a5, {0x83, 0x0b, 0xd9, 0x15, 0x2c, 0x69, 0xaa, 0xe0}}

static struct file __initdata dtbfile;
static void __initdata *fdt;
static void __initdata *memmap;

static int __init setup_chosen_node(void *fdt, int *addr_cells, int *size_cells)
{
    int node;
    const struct fdt_property *prop;
    int len;
    uint32_t val;

    if ( !fdt || !addr_cells || !size_cells )
        return -1;

    /* locate chosen node, which is where we add Xen module info. */
    node = fdt_subnode_offset(fdt, 0, "chosen");
    if ( node < 0 )
    {
        node = fdt_add_subnode(fdt, 0, "chosen");
        if ( node < 0 )
            return node;
    }

    /* Get or set #address-cells and #size-cells */
    prop = fdt_get_property(fdt, node, "#address-cells", &len);
    if ( !prop )
    {
        val = cpu_to_fdt32(2);
        if ( fdt_setprop(fdt, node, "#address-cells", &val, sizeof(val)) )
            return -1;
        *addr_cells = 2;
    }
    else
        *addr_cells = fdt32_to_cpu(*((uint32_t *)prop->data));

    prop = fdt_get_property(fdt, node, "#size-cells", &len);
    if ( !prop )
    {
        val = cpu_to_fdt32(2);
        if ( fdt_setprop(fdt, node, "#size-cells", &val, sizeof(val)) )
            return -1;
        *size_cells = 2;
    }
    else
        *size_cells = fdt32_to_cpu(*((uint32_t *)prop->data));

    /*
     * Make sure ranges is empty if it exists, otherwise create empty ranges
     * property.
     */
    prop = fdt_get_property(fdt, node, "ranges", &len);
    if ( !prop )
    {
        val = cpu_to_fdt32(0);
        if ( fdt_setprop(fdt, node, "ranges", &val, 0) )
            return -1;
    }
    else if ( fdt32_to_cpu(prop->len) )
            return -1;  /* Non-empty ranges property */
    return node;
}

/*
 * Set a single 'reg' property taking into account the
 * configured addr and size cell sizes.
 */
static int __init fdt_set_reg(void *fdt, int node, int addr_cells,
                              int size_cells, uint64_t addr, uint64_t len)
{
    __be32 val[4]; /* At most 2 64 bit values to be stored */
    __be32 *cellp;

    /*
     * Make sure that the values provided can be represented in
     * the reg property, and sizes are valid.
     */
    if ( addr_cells < 1 || addr_cells > 2 || size_cells < 1 || size_cells > 2 )
        return -1;
    if ( addr_cells == 1 && (addr >> 32) )
        return -1;
    if ( size_cells == 1 && (len >> 32) )
        return -1;

    cellp = (__be32 *)val;
    dt_set_cell(&cellp, addr_cells, addr);
    dt_set_cell(&cellp, size_cells, len);

    return(fdt_setprop(fdt, node, "reg", val, sizeof(*cellp) * (cellp - val)));
}

static void __init *lookup_fdt_config_table(EFI_SYSTEM_TABLE *sys_table)
{
    static const EFI_GUID __initconst fdt_guid = DEVICE_TREE_GUID;
    EFI_CONFIGURATION_TABLE *tables;
    void *fdt = NULL;
    int i;

    tables = sys_table->ConfigurationTable;
    for ( i = 0; i < sys_table->NumberOfTableEntries; i++ )
    {
        if ( match_guid(&tables[i].VendorGuid, &fdt_guid) )
        {
            fdt = tables[i].VendorTable;
            break;
        }
    }
    return fdt;
}

static EFI_STATUS __init efi_process_memory_map_bootinfo(EFI_MEMORY_DESCRIPTOR *map,
                                                UINTN mmap_size,
                                                UINTN desc_size)
{
    int Index;
    int i = 0;
#ifdef CONFIG_ACPI
    int j = 0;
#endif
    EFI_MEMORY_DESCRIPTOR *desc_ptr = map;

    for ( Index = 0; Index < (mmap_size / desc_size); Index++ )
    {
        if ( desc_ptr->Type == EfiConventionalMemory ||
             (!map_bs &&
              (desc_ptr->Type == EfiBootServicesCode ||
               desc_ptr->Type == EfiBootServicesData)) )
        {
            if ( i >= NR_MEM_BANKS )
            {
                PrintStr(L"Warning: All " __stringify(NR_MEM_BANKS)
                          " bootinfo mem banks exhausted.\r\n");
                break;
            }
            bootinfo.mem.bank[i].start = desc_ptr->PhysicalStart;
            bootinfo.mem.bank[i].size = desc_ptr->NumberOfPages * EFI_PAGE_SIZE;
            ++i;
        }
#ifdef CONFIG_ACPI
        else if ( desc_ptr->Type == EfiACPIReclaimMemory )
        {
            if ( j >= NR_MEM_BANKS )
            {
                PrintStr(L"Error: All " __stringify(NR_MEM_BANKS)
                          " acpi meminfo mem banks exhausted.\r\n");
                return EFI_LOAD_ERROR;
            }
            acpi_mem.bank[j].start = desc_ptr->PhysicalStart;
            acpi_mem.bank[j].size  = desc_ptr->NumberOfPages * EFI_PAGE_SIZE;
            ++j;
        }
#endif
        desc_ptr = NextMemoryDescriptor(desc_ptr, desc_size);
    }

    bootinfo.mem.nr_banks = i;
#ifdef CONFIG_ACPI
    acpi_mem.nr_banks = j;
#endif
    return EFI_SUCCESS;
}

/*
 * Add the FDT nodes for the standard EFI information, which consist
 * of the System table address, the address of the final EFI memory map,
 * and memory map information.
 */
EFI_STATUS __init fdt_add_uefi_nodes(EFI_SYSTEM_TABLE *sys_table,
                                            void *fdt,
                                            EFI_MEMORY_DESCRIPTOR *memory_map,
                                            UINTN map_size,
                                            UINTN desc_size,
                                            UINT32 desc_ver)
{
    int node;
    int status;
    u32 fdt_val32;
    u64 fdt_val64;
    int prev;
    int num_rsv;

    /*
     * Delete any memory nodes present.  The EFI memory map is the only
     * memory description provided to Xen.
     */
    prev = 0;
    for (;;)
    {
        const char *type;
        int len;

        node = fdt_next_node(fdt, prev, NULL);
        if ( node < 0 )
            break;

        type = fdt_getprop(fdt, node, "device_type", &len);
        if ( type && strncmp(type, "memory", len) == 0 )
        {
            fdt_del_node(fdt, node);
            continue;
        }

        prev = node;
    }

   /*
    * Delete all memory reserve map entries. When booting via UEFI,
    * kernel will use the UEFI memory map to find reserved regions.
    */
   num_rsv = fdt_num_mem_rsv(fdt);
   while ( num_rsv-- > 0 )
       fdt_del_mem_rsv(fdt, num_rsv);

    /* Add FDT entries for EFI runtime services in chosen node. */
    node = fdt_subnode_offset(fdt, 0, "chosen");
    if ( node < 0 )
    {
        node = fdt_add_subnode(fdt, 0, "chosen");
        if ( node < 0 )
        {
            status = node; /* node is error code when negative */
            goto fdt_set_fail;
        }
    }

    fdt_val64 = cpu_to_fdt64((u64)(uintptr_t)sys_table);
    status = fdt_setprop(fdt, node, "linux,uefi-system-table",
                         &fdt_val64, sizeof(fdt_val64));
    if ( status )
        goto fdt_set_fail;

    fdt_val64 = cpu_to_fdt64((u64)(uintptr_t)memory_map);
    status = fdt_setprop(fdt, node, "linux,uefi-mmap-start",
                         &fdt_val64,  sizeof(fdt_val64));
    if ( status )
        goto fdt_set_fail;

    fdt_val32 = cpu_to_fdt32(map_size);
    status = fdt_setprop(fdt, node, "linux,uefi-mmap-size",
                         &fdt_val32,  sizeof(fdt_val32));
    if ( status )
        goto fdt_set_fail;

    fdt_val32 = cpu_to_fdt32(desc_size);
    status = fdt_setprop(fdt, node, "linux,uefi-mmap-desc-size",
                         &fdt_val32, sizeof(fdt_val32));
    if ( status )
        goto fdt_set_fail;

    fdt_val32 = cpu_to_fdt32(desc_ver);
    status = fdt_setprop(fdt, node, "linux,uefi-mmap-desc-ver",
                         &fdt_val32, sizeof(fdt_val32));
    if ( status )
        goto fdt_set_fail;

    return EFI_SUCCESS;

fdt_set_fail:
    if ( status == -FDT_ERR_NOSPACE )
        return EFI_BUFFER_TOO_SMALL;

    return EFI_LOAD_ERROR;
}

/*
 * Allocates new memory for a larger FDT, and frees existing memory if
 * struct file size is non-zero.  Updates file struct with new memory
 * address/size for later freeing.  If fdtfile.ptr is NULL, an empty FDT
 * is created.
 */
static void __init *fdt_increase_size(struct file *fdtfile, int add_size)
{
    EFI_STATUS status;
    EFI_PHYSICAL_ADDRESS fdt_addr;
    int fdt_size;
    int pages;
    void *new_fdt;

    if ( fdtfile->ptr )
        fdt_size = fdt_totalsize(fdtfile->ptr);
    else
        fdt_size = 0;

    pages = PFN_UP(fdt_size + add_size);
    status = efi_bs->AllocatePages(AllocateAnyPages, EfiLoaderData,
                                   pages, &fdt_addr);

    if ( status != EFI_SUCCESS )
        return NULL;

    new_fdt = (void *)fdt_addr;

    if ( fdt_size )
    {
        if ( fdt_open_into(dtbfile.ptr, new_fdt, pages * EFI_PAGE_SIZE) )
            return NULL;
    }
    else
    {
        /*
         * Create an empty FDT if not provided one, which is the expected case
         * when booted from the UEFI shell on an ACPI only system.  We will use
         * the FDT to pass the EFI information to Xen, as well as nodes for
         * any modules the stub loads.  The ACPI tables are part of the UEFI
         * system table that is passed in the FDT.
         */
        if ( fdt_create_empty_tree(new_fdt, pages * EFI_PAGE_SIZE) )
            return NULL;
    }

    /*
     * Now that we have the new FDT allocated and copied, free the
     * original and update the struct file so that the error handling
     * code will free it.  If the original FDT came from a configuration
     * table, we don't own that memory and can't free it.
     */
    if ( dtbfile.size )
        efi_bs->FreePages(dtbfile.addr, PFN_UP(dtbfile.size));

    /* Update 'file' info for new memory so we clean it up on error exits */
    dtbfile.addr = fdt_addr;
    dtbfile.size = pages * EFI_PAGE_SIZE;
    return new_fdt;
}

static void __init efi_arch_relocate_image(unsigned long delta)
{
}

static void __init efi_arch_process_memory_map(EFI_SYSTEM_TABLE *SystemTable,
                                               void *map,
                                               UINTN map_size,
                                               UINTN desc_size,
                                               UINT32 desc_ver)
{
    EFI_STATUS status;

    status = efi_process_memory_map_bootinfo(map, map_size, desc_size);
    if ( EFI_ERROR(status) )
        blexit(L"EFI memory map processing failed");

    status = fdt_add_uefi_nodes(SystemTable, fdt, map, map_size, desc_size,
                                desc_ver);
    if ( EFI_ERROR(status) )
        PrintErrMesg(L"Updating FDT failed", status);
}

static void __init efi_arch_pre_exit_boot(void)
{
}

static void __init efi_arch_post_exit_boot(void)
{
    efi_xen_start(fdt, fdt_totalsize(fdt));
}

static void __init efi_arch_cfg_file_early(EFI_FILE_HANDLE dir_handle, char *section)
{
    union string name;

    /*
     * The DTB must be processed before any other entries in the configuration
     * file, as the DTB is updated as modules are loaded.
     */
    name.s = get_value(&cfg, section, "dtb");
    if ( name.s )
    {
        split_string(name.s);
        read_file(dir_handle, s2w(&name), &dtbfile, NULL);
        efi_bs->FreePool(name.w);
    }
    fdt = fdt_increase_size(&dtbfile, cfg.size + EFI_PAGE_SIZE);
    if ( !fdt )
        blexit(L"Unable to create new FDT");
}

static void __init efi_arch_cfg_file_late(EFI_FILE_HANDLE dir_handle, char *section)
{
}

static void *__init efi_arch_allocate_mmap_buffer(UINTN map_size)
{
    void *ptr;
    EFI_STATUS status;

    status = efi_bs->AllocatePool(EfiLoaderData, map_size, &ptr);
    if ( status != EFI_SUCCESS )
        return NULL;
    return ptr;
}

static void __init efi_arch_edd(void)
{
}

static void __init efi_arch_memory_setup(void)
{
}

static void __init efi_arch_handle_cmdline(CHAR16 *image_name,
                                           CHAR16 *cmdline_options,
                                           char *cfgfile_options)
{
    union string name;
    char *buf;
    EFI_STATUS status;
    int prop_len;
    int chosen;

    /* locate chosen node, which is where we add Xen module info. */
    chosen = fdt_subnode_offset(fdt, 0, "chosen");
    if ( chosen < 0 )
        blexit(L"Unable to find chosen node");

    status = efi_bs->AllocatePool(EfiBootServicesData, EFI_PAGE_SIZE, (void **)&buf);
    if ( EFI_ERROR(status) )
        PrintErrMesg(L"Unable to allocate string buffer", status);

    if ( image_name )
    {
        name.w = image_name;
        w2s(&name);
    }
    else
        name.s = "xen";

    prop_len = 0;
    prop_len += snprintf(buf + prop_len,
                           EFI_PAGE_SIZE - prop_len, "%s", name.s);
    if ( prop_len >= EFI_PAGE_SIZE )
        blexit(L"FDT string overflow");

    if ( cfgfile_options )
    {
        prop_len += snprintf(buf + prop_len,
                               EFI_PAGE_SIZE - prop_len, " %s", cfgfile_options);
        if ( prop_len >= EFI_PAGE_SIZE )
            blexit(L"FDT string overflow");
    }

    if ( cmdline_options )
    {
        name.w = cmdline_options;
        w2s(&name);
    }
    else
        name.s = NULL;

    if ( name.s )
    {
        prop_len += snprintf(buf + prop_len,
                               EFI_PAGE_SIZE - prop_len, " %s", name.s);
        if ( prop_len >= EFI_PAGE_SIZE )
            blexit(L"FDT string overflow");
    }

    if ( fdt_setprop_string(fdt, chosen, "xen,xen-bootargs", buf) < 0 )
        blexit(L"Unable to set xen,xen-bootargs property.");

    efi_bs->FreePool(buf);
}

static void __init efi_arch_handle_module(struct file *file, const CHAR16 *name,
                                          char *options)
{
    int node;
    int chosen;
    int addr_len, size_len;

    if ( file == &dtbfile )
        return;
    chosen = setup_chosen_node(fdt, &addr_len, &size_len);
    if ( chosen < 0 )
        blexit(L"Unable to setup chosen node");

    if ( file == &ramdisk )
    {
        char ramdisk_compat[] = "multiboot,ramdisk\0multiboot,module";
        node = fdt_add_subnode(fdt, chosen, "ramdisk");
        if ( node < 0 )
            blexit(L"Unable to add ramdisk FDT node.");
        if ( fdt_setprop(fdt, node, "compatible", ramdisk_compat,
                         sizeof(ramdisk_compat)) < 0 )
            blexit(L"Unable to set compatible property.");
        if ( fdt_set_reg(fdt, node, addr_len, size_len, ramdisk.addr,
                    ramdisk.size) < 0 )
            blexit(L"Unable to set reg property.");
    }
    else if ( file == &xsm )
    {
        char xsm_compat[] = "xen,xsm-policy\0multiboot,module";
        node = fdt_add_subnode(fdt, chosen, "xsm");
        if ( node < 0 )
            blexit(L"Unable to add xsm FDT node.");
        if ( fdt_setprop(fdt, node, "compatible", xsm_compat,
                         sizeof(xsm_compat)) < 0 )
            blexit(L"Unable to set compatible property.");
        if ( fdt_set_reg(fdt, node, addr_len, size_len, xsm.addr,
                    xsm.size) < 0 )
            blexit(L"Unable to set reg property.");
    }
    else if ( file == &kernel )
    {
        char kernel_compat[] = "multiboot,kernel\0multiboot,module";
        node = fdt_add_subnode(fdt, chosen, "kernel");
        if ( node < 0 )
            blexit(L"Unable to add dom0 FDT node.");
        if ( fdt_setprop(fdt, node, "compatible", kernel_compat,
                         sizeof(kernel_compat)) < 0 )
            blexit(L"Unable to set compatible property.");
        if ( options && fdt_setprop_string(fdt, node, "bootargs", options) < 0 )
            blexit(L"Unable to set bootargs property.");
        if ( fdt_set_reg(fdt, node, addr_len, size_len, kernel.addr,
                         kernel.size) < 0 )
            blexit(L"Unable to set reg property.");
    }
    else
        blexit(L"Unknown module type");
}

static void __init efi_arch_cpu(void)
{
}

static void __init efi_arch_blexit(void)
{
    if ( dtbfile.addr && dtbfile.size )
        efi_bs->FreePages(dtbfile.addr, PFN_UP(dtbfile.size));
    if ( memmap )
        efi_bs->FreePool(memmap);
}

static void __init efi_arch_halt(void)
{
    stop_cpu();
}

static void __init efi_arch_load_addr_check(EFI_LOADED_IMAGE *loaded_image)
{
    if ( (unsigned long)loaded_image->ImageBase & ((1 << 12) - 1) )
        blexit(L"Xen must be loaded at a 4 KByte boundary.");
}

static bool_t __init efi_arch_use_config_file(EFI_SYSTEM_TABLE *SystemTable)
{
    /*
     * For arm, we may get a device tree from GRUB (or other bootloader)
     * that contains modules that have already been loaded into memory.  In
     * this case, we do not use a configuration file, and rely on the
     * bootloader to have loaded all required modules and appropriate
     * options.
     */

    fdt = lookup_fdt_config_table(SystemTable);
    dtbfile.ptr = fdt;
    dtbfile.size = 0;  /* Config table memory can't be freed, so set size to 0 */
    if ( !fdt || fdt_node_offset_by_compatible(fdt, 0, "multiboot,module") < 0 )
    {
        /*
         * We either have no FDT, or one without modules, so we must have a
         * Xen EFI configuration file to specify modules.  (dom0 required)
         */
        return 1;
    }
    PrintStr(L"Using modules provided by bootloader in FDT\r\n");
    /* We have modules already defined in fdt, just add space. */
    fdt = fdt_increase_size(&dtbfile, EFI_PAGE_SIZE);
    return 0;
}

static void __init efi_arch_console_init(UINTN cols, UINTN rows)
{
}

static void __init efi_arch_video_init(EFI_GRAPHICS_OUTPUT_PROTOCOL *gop,
                                       UINTN info_size,
                                       EFI_GRAPHICS_OUTPUT_MODE_INFORMATION *mode_info)
{
}

static void __init efi_arch_flush_dcache_area(const void *vaddr, UINTN size)
{
    __flush_dcache_area(vaddr, size);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
