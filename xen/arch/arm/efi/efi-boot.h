/*
 * Architecture specific implementation for EFI boot code.  This file
 * is intended to be included by common/efi/boot.c _only_, and
 * therefore can define arch specific global variables.
 */
#include <xen/device_tree.h>
#include <xen/libfdt/libfdt.h>
#include <asm/setup.h>
#include <asm/smp.h>

typedef struct {
    char *name;
    unsigned int name_len;
    EFI_PHYSICAL_ADDRESS addr;
    UINTN size;
} module_info;

/*
 * Binaries will be translated into bootmodules, the maximum number for them is
 * MAX_MODULES where we should remove a unit for Xen and one for Xen DTB
 */
#define MAX_UEFI_MODULES (MAX_MODULES - 2)
static struct file __initdata module_binary;
static module_info __initdata modules[MAX_UEFI_MODULES];
static unsigned int __initdata modules_available = MAX_UEFI_MODULES;
static unsigned int __initdata modules_idx;

#define ERROR_BINARY_FILE_NOT_FOUND (-1)
#define ERROR_ALLOC_MODULE_NO_SPACE (-1)
#define ERROR_ALLOC_MODULE_NAME     (-2)
#define ERROR_MISSING_DT_PROPERTY   (-3)
#define ERROR_RENAME_MODULE_NAME    (-4)
#define ERROR_SET_REG_PROPERTY      (-5)
#define ERROR_CHECK_MODULE_COMPAT   (-6)
#define ERROR_DOM0_ALREADY_FOUND    (-7)
#define ERROR_DOM0_RAMDISK_FOUND    (-8)
#define ERROR_XSM_ALREADY_FOUND     (-9)
#define ERROR_DT_MODULE_DOMU        (-1)
#define ERROR_DT_CHOSEN_NODE        (-2)
#define ERROR_DT_MODULE_DOM0        (-3)

void noreturn efi_xen_start(void *fdt_ptr, uint32_t fdt_size);
void __flush_dcache_area(const void *vaddr, unsigned long size);

static int get_module_file_index(const char *name, unsigned int name_len);
static void PrintMessage(const CHAR16 *s);

#define DEVICE_TREE_GUID \
{0xb1b621d5U, 0xf19c, 0x41a5, {0x83, 0x0b, 0xd9, 0x15, 0x2c, 0x69, 0xaa, 0xe0}}

static struct file __initdata dtbfile;
static void __initdata *fdt_efi;
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

static bool __init meminfo_add_bank(struct membanks *mem,
                                    EFI_MEMORY_DESCRIPTOR *desc)
{
    struct membank *bank;
    paddr_t start = desc->PhysicalStart;
    paddr_t size = desc->NumberOfPages * EFI_PAGE_SIZE;

    if ( mem->nr_banks >= mem->max_banks )
        return false;
#ifdef CONFIG_ACPI
    if ( check_reserved_regions_overlap(start, size, false) )
        return false;
#endif

    bank = &mem->bank[mem->nr_banks];
    bank->start = start;
    bank->size = size;
    bank->type = MEMBANK_DEFAULT;

    mem->nr_banks++;

    return true;
}

static EFI_STATUS __init efi_process_memory_map_bootinfo(EFI_MEMORY_DESCRIPTOR *map,
                                                UINTN mmap_size,
                                                UINTN desc_size)
{
    int Index;
    EFI_MEMORY_DESCRIPTOR *desc_ptr = map;

    for ( Index = 0; Index < (mmap_size / desc_size); Index++ )
    {
        if ( !(desc_ptr->Attribute & EFI_MEMORY_RUNTIME) &&
             (desc_ptr->Attribute & EFI_MEMORY_WB) &&
             (desc_ptr->Type == EfiConventionalMemory ||
              desc_ptr->Type == EfiLoaderCode ||
              desc_ptr->Type == EfiLoaderData ||
              (!map_bs &&
               (desc_ptr->Type == EfiBootServicesCode ||
                desc_ptr->Type == EfiBootServicesData))) )
        {
            if ( !meminfo_add_bank(bootinfo_get_mem(), desc_ptr) )
            {
                PrintStr(L"Warning: All " __stringify(NR_MEM_BANKS)
                          " bootinfo mem banks exhausted.\r\n");
                break;
            }
        }
#ifdef CONFIG_ACPI
        else if ( desc_ptr->Type == EfiACPIReclaimMemory )
        {
            if ( !meminfo_add_bank(bootinfo_get_acpi(), desc_ptr) )
            {
                PrintStr(L"Error: All " __stringify(NR_MEM_BANKS)
                          " acpi meminfo mem banks exhausted.\r\n");
                return EFI_LOAD_ERROR;
            }
        }
#endif
        desc_ptr = NextMemoryDescriptor(desc_ptr, desc_size);
    }

    return EFI_SUCCESS;
}

/*
 * Add the FDT nodes for the standard EFI information, which consist
 * of the System table address, the address of the final EFI memory map,
 * and memory map information.
 */
static EFI_STATUS __init fdt_add_uefi_nodes(EFI_SYSTEM_TABLE *sys_table,
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
    int num_rsv;

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
        {
            efi_bs->FreePages(fdt_addr, pages);
            return NULL;
        }
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
        {
            efi_bs->FreePages(fdt_addr, pages);
            return NULL;
        }
    }

    /*
     * Now that we have the new FDT allocated and copied, free the
     * original and update the struct file so that the error handling
     * code will free it.  If the original FDT came from a configuration
     * table, we don't own that memory and can't free it.
     */
    if ( dtbfile.need_to_free )
        efi_bs->FreePages(dtbfile.addr, PFN_UP(dtbfile.size));

    /* Update 'file' info for new memory so we clean it up on error exits */
    dtbfile.addr = fdt_addr;
    dtbfile.size = pages * EFI_PAGE_SIZE;
    dtbfile.need_to_free = true;
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

    status = fdt_add_uefi_nodes(SystemTable, fdt_efi, map, map_size, desc_size,
                                desc_ver);
    if ( EFI_ERROR(status) )
        PrintErrMesg(L"Updating FDT failed", status);
}

static void __init efi_arch_pre_exit_boot(void)
{
}

static void __init noreturn efi_arch_post_exit_boot(void)
{
    efi_xen_start(fdt_efi, fdt_totalsize(fdt_efi));
}

static void __init efi_arch_cfg_file_early(const EFI_LOADED_IMAGE *image,
                                           EFI_FILE_HANDLE dir_handle,
                                           const char *section)
{
    union string name;

    /*
     * The DTB must be processed before any other entries in the configuration
     * file, as the DTB is updated as modules are loaded.  Prefer the one
     * stored as a PE section in a unified image, and fall back to a file
     * on disk if the section is not present.
     */
    if ( !read_section(image, L"dtb", &dtbfile, NULL) )
    {
        name.s = get_value(&cfg, section, "dtb");
        if ( name.s )
        {
            split_string(name.s);
            read_file(dir_handle, s2w(&name), &dtbfile, NULL);
            efi_bs->FreePool(name.w);
        }
    }
    fdt_efi = fdt_increase_size(&dtbfile, cfg.size + EFI_PAGE_SIZE);
    if ( !fdt_efi )
        blexit(L"Unable to create new FDT");
}

static void __init efi_arch_cfg_file_late(const EFI_LOADED_IMAGE *image,
                                          EFI_FILE_HANDLE dir_handle,
                                          const char *section)
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

static void __init efi_arch_edid(EFI_HANDLE gop_handle)
{
}

static void __init efi_arch_memory_setup(void)
{
}

static void __init efi_arch_handle_cmdline(CHAR16 *cmdline_options,
                                           const char *cfgfile_options)
{
    union string name;
    char *buf;
    EFI_STATUS status;
    int prop_len = 0;
    int chosen;

    /* locate chosen node, which is where we add Xen module info. */
    chosen = fdt_subnode_offset(fdt_efi, 0, "chosen");
    if ( chosen < 0 )
        blexit(L"Unable to find chosen node");

    status = efi_bs->AllocatePool(EfiBootServicesData, EFI_PAGE_SIZE, (void **)&buf);
    if ( EFI_ERROR(status) )
        PrintErrMesg(L"Unable to allocate string buffer", status);

    if ( cfgfile_options )
    {
        PrintMessage(L"Using bootargs from Xen configuration file.");
        prop_len += snprintf(buf + prop_len,
                               EFI_PAGE_SIZE - prop_len, " %s", cfgfile_options);
        if ( prop_len >= EFI_PAGE_SIZE )
            blexit(L"FDT string overflow");
    }
    else
    {
        /* Get xen,xen-bootargs in /chosen if it is specified */
        const char *dt_bootargs_prop = fdt_getprop(fdt_efi, chosen,
                                                   "xen,xen-bootargs", NULL);
        if ( dt_bootargs_prop )
        {
            PrintMessage(L"Using bootargs from device tree.");
            prop_len += snprintf(buf + prop_len, EFI_PAGE_SIZE - prop_len,
                                 " %s", dt_bootargs_prop);
            if ( prop_len >= EFI_PAGE_SIZE )
                blexit(L"FDT string overflow");
        }
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

    if ( fdt_setprop_string(fdt_efi, chosen, "xen,xen-bootargs", buf) < 0 )
        blexit(L"Unable to set xen,xen-bootargs property.");

    efi_bs->FreePool(buf);
}

static void __init efi_arch_handle_module(const struct file *file,
                                          const CHAR16 *name,
                                          const char *options)
{
    int node;
    int chosen;
    int addr_len, size_len;

    if ( file == &dtbfile )
        return;
    chosen = setup_chosen_node(fdt_efi, &addr_len, &size_len);
    if ( chosen < 0 )
        blexit(L"Unable to setup chosen node");

    if ( file == &ramdisk )
    {
        static const char __initconst ramdisk_compat[] = "multiboot,ramdisk\0"
                                                         "multiboot,module";

        node = fdt_add_subnode(fdt_efi, chosen, "ramdisk");
        if ( node < 0 )
            blexit(L"Unable to add ramdisk FDT node.");
        if ( fdt_setprop(fdt_efi, node, "compatible", ramdisk_compat,
                         sizeof(ramdisk_compat)) < 0 )
            blexit(L"Unable to set compatible property.");
        if ( fdt_set_reg(fdt_efi, node, addr_len, size_len, ramdisk.addr,
                    ramdisk.size) < 0 )
            blexit(L"Unable to set reg property.");
    }
    else if ( file == &xsm )
    {
        static const char __initconst xsm_compat[] = "xen,xsm-policy\0"
                                                     "multiboot,module";

        node = fdt_add_subnode(fdt_efi, chosen, "xsm");
        if ( node < 0 )
            blexit(L"Unable to add xsm FDT node.");
        if ( fdt_setprop(fdt_efi, node, "compatible", xsm_compat,
                         sizeof(xsm_compat)) < 0 )
            blexit(L"Unable to set compatible property.");
        if ( fdt_set_reg(fdt_efi, node, addr_len, size_len, xsm.addr,
                    xsm.size) < 0 )
            blexit(L"Unable to set reg property.");
    }
    else if ( file == &kernel )
    {
        static const char __initconst kernel_compat[] = "multiboot,kernel\0"
                                                        "multiboot,module";

        node = fdt_add_subnode(fdt_efi, chosen, "kernel");
        if ( node < 0 )
            blexit(L"Unable to add dom0 FDT node.");
        if ( fdt_setprop(fdt_efi, node, "compatible", kernel_compat,
                         sizeof(kernel_compat)) < 0 )
            blexit(L"Unable to set compatible property.");
        if ( options && fdt_setprop_string(fdt_efi, node, "bootargs", options) < 0 )
            blexit(L"Unable to set bootargs property.");
        if ( fdt_set_reg(fdt_efi, node, addr_len, size_len, kernel.addr,
                         kernel.size) < 0 )
            blexit(L"Unable to set reg property.");
    }
    else if ( file != &module_binary )
        /*
         * If file is not a dom0 module file and it's not a domU module,
         * stop here.
         */
        blexit(L"Unknown module type");

    /*
     * modules_available is decremented here because for each dom0 file added
     * from the configuration file, there will be an additional bootmodule,
     * so the number of available slots will be decremented because there is a
     * maximum amount of bootmodules that can be loaded.
     */
    modules_available--;
}

/*
 * This function checks for a binary previously loaded with a give name, it
 * returns the index of the file in the modules array or a negative number if no
 * file with that name is found.
 */
static int __init get_module_file_index(const char *name,
                                        unsigned int name_len)
{
    unsigned int i;
    int ret = ERROR_BINARY_FILE_NOT_FOUND;

    for ( i = 0; i < modules_idx; i++ )
    {
        module_info *mod = &modules[i];
        if ( (mod->name_len == name_len) &&
             (strncmp(mod->name, name, name_len) == 0) )
        {
            ret = i;
            break;
        }
    }
    return ret;
}

static void __init PrintMessage(const CHAR16 *s)
{
    PrintStr(s);
    PrintStr(newline);
}

/*
 * This function allocates a binary and keeps track of its name, it returns the
 * index of the file in the modules array or a negative number on error.
 */
static int __init allocate_module_file(const EFI_LOADED_IMAGE *loaded_image,
                                       EFI_FILE_HANDLE *dir_handle,
                                       const char *name,
                                       unsigned int name_len)
{
    module_info *file_info;
    CHAR16 *fname;
    union string module_name;
    int ret;

    /*
     * Check if there is any space left for a module, the variable
     * modules_available is updated each time we use read_file(...)
     * successfully.
     */
    if ( !modules_available )
    {
        PrintMessage(L"No space left for modules");
        return ERROR_ALLOC_MODULE_NO_SPACE;
    }

    module_name.cs = name;
    ret = modules_idx;

    /* Save at this index the name of this binary */
    file_info = &modules[ret];

    if ( efi_bs->AllocatePool(EfiLoaderData, (name_len + 1) * sizeof(char),
                              (void**)&file_info->name) != EFI_SUCCESS )
    {
        PrintMessage(L"Error allocating memory for module binary name");
        return ERROR_ALLOC_MODULE_NAME;
    }

    /* Save name and length of the binary in the data structure */
    strlcpy(file_info->name, name, name_len + 1);
    file_info->name_len = name_len;

    /* Get the file system interface. */
    if ( !*dir_handle )
        *dir_handle = get_parent_handle(loaded_image, &fname);

    /* Load the binary in memory */
    read_file(*dir_handle, s2w(&module_name), &module_binary, NULL);

    /* Save address and size */
    file_info->addr = module_binary.addr;
    file_info->size = module_binary.size;

    /* s2w(...) allocates some memory, free it */
    efi_bs->FreePool(module_name.w);

    modules_idx++;

    return ret;
}

/*
 * This function checks for the presence of the xen,uefi-binary property in the
 * module, if found it loads the binary as module and sets the right address
 * for the reg property into the module DT node.
 * Returns 1 if module is multiboot,module, 0 if not, < 0 on error
 */
static int __init handle_module_node(const EFI_LOADED_IMAGE *loaded_image,
                                     EFI_FILE_HANDLE *dir_handle,
                                     int module_node_offset,
                                     int reg_addr_cells,
                                     int reg_size_cells,
                                     bool is_domu_module)
{
    const void *uefi_name_prop;
    char mod_string[24]; /* Placeholder for module@ + a 64-bit number + \0 */
    int uefi_name_len, file_idx, module_compat;
    module_info *file;

    /* Check if the node is a multiboot,module otherwise return */
    module_compat = fdt_node_check_compatible(fdt_efi, module_node_offset,
                                              "multiboot,module");
    if ( module_compat < 0 )
        /* Error while checking the compatible string */
        return ERROR_CHECK_MODULE_COMPAT;

    if ( module_compat != 0 )
        /* Module is not a multiboot,module */
        return 0;

    /* Read xen,uefi-binary property to get the file name. */
    uefi_name_prop = fdt_getprop(fdt_efi, module_node_offset, "xen,uefi-binary",
                                 &uefi_name_len);

    if ( !uefi_name_prop )
        /* Property not found, but signal this is a multiboot,module */
        return 1;

    file_idx = get_module_file_index(uefi_name_prop, uefi_name_len);
    if ( file_idx < 0 )
    {
        file_idx = allocate_module_file(loaded_image, dir_handle,
                                        uefi_name_prop, uefi_name_len);
        if ( file_idx < 0 )
            return file_idx;
    }

    file = &modules[file_idx];

    snprintf(mod_string, sizeof(mod_string), "module@%"PRIx64, file->addr);

    /* Rename the module to be module@{address} */
    if ( fdt_set_name(fdt_efi, module_node_offset, mod_string) < 0 )
    {
        PrintMessage(L"Unable to modify module node name.");
        return ERROR_RENAME_MODULE_NAME;
    }

    if ( fdt_set_reg(fdt_efi, module_node_offset, reg_addr_cells, reg_size_cells,
                     file->addr, file->size) < 0 )
    {
        PrintMessage(L"Unable to set module reg property.");
        return ERROR_SET_REG_PROPERTY;
    }

    if ( !is_domu_module )
    {
        if ( (fdt_node_check_compatible(fdt_efi, module_node_offset,
                                    "multiboot,kernel") == 0) )
        {
            /*
            * This is the Dom0 kernel, wire it to the kernel variable because it
            * will be verified by the shim lock protocol later in the common
            * code.
            */
            if ( kernel.addr )
            {
                PrintMessage(L"Dom0 kernel already found in cfg file.");
                return ERROR_DOM0_ALREADY_FOUND;
            }
            kernel.need_to_free = false; /* Freed using the module array */
            kernel.addr = file->addr;
            kernel.size = file->size;
        }
        else if ( ramdisk.addr &&
                  (fdt_node_check_compatible(fdt_efi, module_node_offset,
                                             "multiboot,ramdisk") == 0) )
        {
            PrintMessage(L"Dom0 ramdisk already found in cfg file.");
            return ERROR_DOM0_RAMDISK_FOUND;
        }
        else if ( xsm.addr &&
                  (fdt_node_check_compatible(fdt_efi, module_node_offset,
                                             "xen,xsm-policy") == 0) )
        {
            PrintMessage(L"XSM policy already found in cfg file.");
            return ERROR_XSM_ALREADY_FOUND;
        }
    }

    return 1;
}

#ifdef CONFIG_DOM0LESS_BOOT
/*
 * This function checks for boot modules under the domU guest domain node
 * in the DT.
 * Returns number of multiboot,module found or negative number on error.
 */
static int __init handle_dom0less_domain_node(const EFI_LOADED_IMAGE *loaded_image,
                                              EFI_FILE_HANDLE *dir_handle,
                                              int domain_node)
{
    int module_node, addr_cells, size_cells, len;
    const struct fdt_property *prop;
    unsigned int mb_modules_found = 0;

    /* Get #address-cells and #size-cells from domain node */
    prop = fdt_get_property(fdt_efi, domain_node, "#address-cells", &len);
    if ( !prop )
    {
        PrintMessage(L"#address-cells not found in domain node.");
        return ERROR_MISSING_DT_PROPERTY;
    }

    addr_cells = fdt32_to_cpu(*((uint32_t *)prop->data));

    prop = fdt_get_property(fdt_efi, domain_node, "#size-cells", &len);
    if ( !prop )
    {
        PrintMessage(L"#size-cells not found in domain node.");
        return ERROR_MISSING_DT_PROPERTY;
    }

    size_cells = fdt32_to_cpu(*((uint32_t *)prop->data));

    /* Check for nodes compatible with multiboot,module inside this node */
    for ( module_node = fdt_first_subnode(fdt_efi, domain_node);
          module_node > 0;
          module_node = fdt_next_subnode(fdt_efi, module_node) )
    {
        int ret = handle_module_node(loaded_image, dir_handle, module_node,
                                     addr_cells, size_cells, true);
        if ( ret < 0 )
            return ret;

        mb_modules_found += ret;
    }

    return mb_modules_found;
}
#endif

/*
 * This function checks for xen domain nodes under the /chosen node for possible
 * dom0 and domU guests to be loaded.
 * Returns the number of multiboot modules found or a negative number for error.
 */
static int __init efi_check_dt_boot(const EFI_LOADED_IMAGE *loaded_image)
{
    int chosen, node, addr_len, size_len;
    unsigned int i = 0, modules_found = 0;
    EFI_FILE_HANDLE dir_handle = NULL;

    /* Check for the chosen node in the current DTB */
    chosen = setup_chosen_node(fdt_efi, &addr_len, &size_len);
    if ( chosen < 0 )
    {
        PrintMessage(L"Unable to setup chosen node");
        return ERROR_DT_CHOSEN_NODE;
    }

    /* Check for nodes compatible with xen,domain under the chosen node */
    for ( node = fdt_first_subnode(fdt_efi, chosen);
          node > 0;
          node = fdt_next_subnode(fdt_efi, node) )
    {
        int ret;

#ifdef CONFIG_DOM0LESS_BOOT
        if ( !fdt_node_check_compatible(fdt_efi, node, "xen,domain") )
        {
            /* Found a node with compatible xen,domain; handle this node. */
            ret = handle_dom0less_domain_node(loaded_image, &dir_handle, node);
            if ( ret < 0 )
                return ERROR_DT_MODULE_DOMU;
        }
        else
#endif
        {
            ret = handle_module_node(loaded_image, &dir_handle, node, addr_len,
                                     size_len, false);
            if ( ret < 0 )
                 return ERROR_DT_MODULE_DOM0;
        }
        modules_found += ret;
    }

    /* dir_handle can be allocated in allocate_module_file, free it if exists */
    if ( dir_handle )
        dir_handle->Close(dir_handle);

    /* Free boot modules file names if any */
    for ( ; i < modules_idx; i++ )
    {
        /* Free boot modules binary names */
        efi_bs->FreePool(modules[i].name);
    }

    return modules_found;
}

static void __init efi_arch_cpu(void)
{
}

static void __init efi_arch_blexit(void)
{
    unsigned int i = 0;

    if ( dtbfile.need_to_free )
        efi_bs->FreePages(dtbfile.addr, PFN_UP(dtbfile.size));
    /* Free boot modules file names if any */
    for ( ; i < modules_idx; i++ )
    {
        /* Free boot modules binary names */
        efi_bs->FreePool(modules[i].name);
        /* Free modules binaries */
        efi_bs->FreePages(modules[i].addr,
                          PFN_UP(modules[i].size));
    }
    if ( memmap )
        efi_bs->FreePool(memmap);
}

static void __init efi_arch_halt(void)
{
    stop_cpu();
}

static void __init efi_arch_load_addr_check(const EFI_LOADED_IMAGE *loaded_image)
{
    if ( (unsigned long)loaded_image->ImageBase & ((1 << 12) - 1) )
        blexit(L"Xen must be loaded at a 4 KByte boundary.");
}

static bool __init efi_arch_use_config_file(EFI_SYSTEM_TABLE *SystemTable)
{
    bool load_cfg_file = true;
    /*
     * For arm, we may get a device tree from GRUB (or other bootloader)
     * that contains modules that have already been loaded into memory.  In
     * this case, we search for the property xen,uefi-cfg-load in the /chosen
     * node to decide whether to skip the UEFI Xen configuration file or not.
     */

    fdt_efi = lookup_fdt_config_table(SystemTable);
    dtbfile.ptr = fdt_efi;
    dtbfile.need_to_free = false; /* Config table memory can't be freed. */

    if ( fdt_efi &&
         (fdt_node_offset_by_compatible(fdt_efi, 0, "multiboot,module") > 0) )
    {
        /* Locate chosen node */
        int node = fdt_subnode_offset(fdt_efi, 0, "chosen");
        const void *cfg_load_prop;
        int cfg_load_len;

        if ( node > 0 )
        {
            /* Check if xen,uefi-cfg-load property exists */
            cfg_load_prop = fdt_getprop(fdt_efi, node, "xen,uefi-cfg-load",
                                        &cfg_load_len);
            if ( !cfg_load_prop )
                load_cfg_file = false;
        }
    }

    if ( !fdt_efi || load_cfg_file )
    {
        /*
         * We either have no FDT, or one without modules, so we must have a
         * Xen EFI configuration file to specify modules.
         */
        return true;
    }
    PrintStr(L"Using modules provided by bootloader in FDT\r\n");
    /* We have modules already defined in fdt, just add space. */
    fdt_efi = fdt_increase_size(&dtbfile, EFI_PAGE_SIZE);

    return false;
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
