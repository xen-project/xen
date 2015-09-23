/*
 * Architecture specific implementation for EFI boot code.  This file
 * is intended to be included by common/efi/boot.c _only_, and
 * therefore can define arch specific global variables.
 */
#include <xen/vga.h>
#include <asm/e820.h>
#include <asm/edd.h>
#include <asm/msr.h>
#include <asm/processor.h>

static struct file __initdata ucode;
static multiboot_info_t __initdata mbi = {
    .flags = MBI_MODULES | MBI_LOADERNAME
};
static module_t __initdata mb_modules[3];

static void __init edd_put_string(u8 *dst, size_t n, const char *src)
{
    while ( n-- && *src )
       *dst++ = *src++;
    if ( *src )
       PrintErrMesg(L"Internal error populating EDD info",
                    EFI_BUFFER_TOO_SMALL);
    while ( n-- )
       *dst++ = ' ';
}
#define edd_put_string(d, s) edd_put_string(d, ARRAY_SIZE(d), s)

extern const intpte_t __page_tables_start[], __page_tables_end[];
#define in_page_tables(v) ((intpte_t *)(v) >= __page_tables_start && \
                           (intpte_t *)(v) < __page_tables_end)

#define PE_BASE_RELOC_ABS      0
#define PE_BASE_RELOC_HIGHLOW  3
#define PE_BASE_RELOC_DIR64   10

extern const struct pe_base_relocs {
    u32 rva;
    u32 size;
    u16 entries[];
} __base_relocs_start[], __base_relocs_end[];

static void __init efi_arch_relocate_image(unsigned long delta)
{
    const struct pe_base_relocs *base_relocs;

    for ( base_relocs = __base_relocs_start; base_relocs < __base_relocs_end; )
    {
        unsigned int i, n;

        n = (base_relocs->size - sizeof(*base_relocs)) /
            sizeof(*base_relocs->entries);
        for ( i = 0; i < n; ++i )
        {
            unsigned long addr = xen_phys_start + base_relocs->rva +
                                 (base_relocs->entries[i] & 0xfff);

            switch ( base_relocs->entries[i] >> 12 )
            {
            case PE_BASE_RELOC_ABS:
                break;
            case PE_BASE_RELOC_HIGHLOW:
                if ( delta )
                {
                    *(u32 *)addr += delta;
                    if ( in_page_tables(addr) )
                        *(u32 *)addr += xen_phys_start;
                }
                break;
            case PE_BASE_RELOC_DIR64:
                if ( delta )
                {
                    *(u64 *)addr += delta;
                    if ( in_page_tables(addr) )
                        *(intpte_t *)addr += xen_phys_start;
                }
                break;
            default:
                blexit(L"Unsupported relocation type");
            }
        }
        base_relocs = (const void *)(base_relocs->entries + i + (i & 1));
    }
}

extern const s32 __trampoline_rel_start[], __trampoline_rel_stop[];
extern const s32 __trampoline_seg_start[], __trampoline_seg_stop[];

static void __init relocate_trampoline(unsigned long phys)
{
    const s32 *trampoline_ptr;

    trampoline_phys = phys;
    /* Apply relocations to trampoline. */
    for ( trampoline_ptr = __trampoline_rel_start;
          trampoline_ptr < __trampoline_rel_stop;
          ++trampoline_ptr )
        *(u32 *)(*trampoline_ptr + (long)trampoline_ptr) += phys;
    for ( trampoline_ptr = __trampoline_seg_start;
          trampoline_ptr < __trampoline_seg_stop;
          ++trampoline_ptr )
        *(u16 *)(*trampoline_ptr + (long)trampoline_ptr) = phys >> 4;
}

static void __init place_string(u32 *addr, const char *s)
{
    static char *__initdata alloc = start;

    if ( s && *s )
    {
        size_t len1 = strlen(s) + 1;
        const char *old = (char *)(long)*addr;
        size_t len2 = *addr ? strlen(old) + 1 : 0;

        alloc -= len1 + len2;
        /*
         * Insert new string before already existing one. This is needed
         * for options passed on the command line to override options from
         * the configuration file.
         */
        memcpy(alloc, s, len1);
        if ( *addr )
        {
            alloc[len1 - 1] = ' ';
            memcpy(alloc + len1, old, len2);
        }
    }
    *addr = (long)alloc;
}

static void __init efi_arch_process_memory_map(EFI_SYSTEM_TABLE *SystemTable,
                                               void *map,
                                               UINTN map_size,
                                               UINTN desc_size,
                                               UINT32 desc_ver)
{
    struct e820entry *e;
    unsigned int i;

    /* Populate E820 table and check trampoline area availability. */
    e = e820map - 1;
    for ( e820nr = i = 0; i < map_size; i += desc_size )
    {
        EFI_MEMORY_DESCRIPTOR *desc = map + i;
        u64 len = desc->NumberOfPages << EFI_PAGE_SHIFT;
        u32 type;

        switch ( desc->Type )
        {
        case EfiBootServicesCode:
        case EfiBootServicesData:
            if ( map_bs )
            {
        default:
                type = E820_RESERVED;
                break;
            }
            /* fall through */
        case EfiConventionalMemory:
            if ( !trampoline_phys && desc->PhysicalStart + len <= 0x100000 &&
                 len >= cfg.size && desc->PhysicalStart + len > cfg.addr )
                cfg.addr = (desc->PhysicalStart + len - cfg.size) & PAGE_MASK;
            /* fall through */
        case EfiLoaderCode:
        case EfiLoaderData:
            if ( desc->Attribute & EFI_MEMORY_WB )
                type = E820_RAM;
            else
        case EfiUnusableMemory:
                type = E820_UNUSABLE;
            break;
        case EfiACPIReclaimMemory:
            type = E820_ACPI;
            break;
        case EfiACPIMemoryNVS:
            type = E820_NVS;
            break;
        }
        if ( e820nr && type == e->type &&
             desc->PhysicalStart == e->addr + e->size )
            e->size += len;
        else if ( !len || e820nr >= E820MAX )
            continue;
        else
        {
            ++e;
            e->addr = desc->PhysicalStart;
            e->size = len;
            e->type = type;
            ++e820nr;
        }
    }

}

static void *__init efi_arch_allocate_mmap_buffer(UINTN map_size)
{
    place_string(&mbi.mem_upper, NULL);
    mbi.mem_upper -= map_size;
    mbi.mem_upper &= -__alignof__(EFI_MEMORY_DESCRIPTOR);
    if ( mbi.mem_upper < xen_phys_start )
        return NULL;
    return (void *)(long)mbi.mem_upper;
}

static void __init efi_arch_pre_exit_boot(void)
{
    if ( !trampoline_phys )
    {
        if ( !cfg.addr )
            blexit(L"No memory for trampoline");
        relocate_trampoline(cfg.addr);
    }
}

static void __init noreturn efi_arch_post_exit_boot(void)
{
    u64 efer;

    efi_arch_relocate_image(__XEN_VIRT_START - xen_phys_start);
    memcpy((void *)trampoline_phys, trampoline_start, cfg.size);

    /* Set system registers and transfer control. */
    asm volatile("pushq $0\n\tpopfq");
    rdmsrl(MSR_EFER, efer);
    efer |= EFER_SCE;
    if ( cpuid_ext_features & (1 << (X86_FEATURE_NX & 0x1f)) )
        efer |= EFER_NX;
    wrmsrl(MSR_EFER, efer);
    write_cr0(X86_CR0_PE | X86_CR0_MP | X86_CR0_ET | X86_CR0_NE | X86_CR0_WP |
              X86_CR0_AM | X86_CR0_PG);
    asm volatile ( "mov    %[cr4], %%cr4\n\t"
                   "mov    %[cr3], %%cr3\n\t"
                   "movabs $__start_xen, %[rip]\n\t"
                   "lgdt   gdt_descr(%%rip)\n\t"
                   "mov    stack_start(%%rip), %%rsp\n\t"
                   "mov    %[ds], %%ss\n\t"
                   "mov    %[ds], %%ds\n\t"
                   "mov    %[ds], %%es\n\t"
                   "mov    %[ds], %%fs\n\t"
                   "mov    %[ds], %%gs\n\t"
                   "movl   %[cs], 8(%%rsp)\n\t"
                   "mov    %[rip], (%%rsp)\n\t"
                   "lretq  %[stkoff]-16"
                   : [rip] "=&r" (efer/* any dead 64-bit variable */)
                   : [cr3] "r" (idle_pg_table),
                     [cr4] "r" (mmu_cr4_features),
                     [cs] "ir" (__HYPERVISOR_CS),
                     [ds] "r" (__HYPERVISOR_DS),
                     [stkoff] "i" (STACK_SIZE - sizeof(struct cpu_info)),
                     "D" (&mbi)
                   : "memory" );
    for( ; ; ); /* not reached */
}

static void __init efi_arch_cfg_file_early(EFI_FILE_HANDLE dir_handle, char *section)
{
}

static void __init efi_arch_cfg_file_late(EFI_FILE_HANDLE dir_handle, char *section)
{
    union string name;

    name.s = get_value(&cfg, section, "ucode");
    if ( !name.s )
        name.s = get_value(&cfg, "global", "ucode");
    if ( name.s )
    {
        microcode_set_module(mbi.mods_count);
        split_string(name.s);
        read_file(dir_handle, s2w(&name), &ucode, NULL);
        efi_bs->FreePool(name.w);
    }
}

static void __init efi_arch_handle_cmdline(CHAR16 *image_name,
                                           CHAR16 *cmdline_options,
                                           char *cfgfile_options)
{
    union string name;

    if ( cmdline_options )
    {
        name.w = cmdline_options;
        w2s(&name);
        place_string(&mbi.cmdline, name.s);
    }
    if ( cfgfile_options )
        place_string(&mbi.cmdline, cfgfile_options);
    /* Insert image name last, as it gets prefixed to the other options. */
    if ( image_name )
    {
        name.w = image_name;
        w2s(&name);
    }
    else
        name.s = "xen";
    place_string(&mbi.cmdline, name.s);

    if ( mbi.cmdline )
        mbi.flags |= MBI_CMDLINE;
    /*
     * These must not be initialized statically, since the value must
     * not get relocated when processing base relocations later.
     */
    mbi.boot_loader_name = (long)"EFI";
    mbi.mods_addr = (long)mb_modules;
}

static void __init efi_arch_edd(void)
{
    static EFI_GUID __initdata bio_guid = BLOCK_IO_PROTOCOL;
    static EFI_GUID __initdata devp_guid = DEVICE_PATH_PROTOCOL;
    EFI_HANDLE *handles = NULL;
    unsigned int i;
    UINTN size;
    EFI_STATUS status;

    /* Collect EDD info. */
    BUILD_BUG_ON(offsetof(struct edd_info, edd_device_params) != EDDEXTSIZE);
    BUILD_BUG_ON(sizeof(struct edd_device_params) != EDDPARMSIZE);
    size = 0;
    status = efi_bs->LocateHandle(ByProtocol, &bio_guid, NULL, &size, NULL);
    if ( status == EFI_BUFFER_TOO_SMALL )
        status = efi_bs->AllocatePool(EfiLoaderData, size, (void **)&handles);
    if ( !EFI_ERROR(status) )
        status = efi_bs->LocateHandle(ByProtocol, &bio_guid, NULL, &size,
                                      handles);
    if ( EFI_ERROR(status) )
        size = 0;
    for ( i = 0; i < size / sizeof(*handles); ++i )
    {
        EFI_BLOCK_IO *bio;
        EFI_DEV_PATH_PTR devp;
        struct edd_info *info = boot_edd_info + boot_edd_info_nr;
        struct edd_device_params *params = &info->edd_device_params;
        enum { root, acpi, pci, ctrlr } state = root;

        status = efi_bs->HandleProtocol(handles[i], &bio_guid, (void **)&bio);
        if ( EFI_ERROR(status) ||
             bio->Media->RemovableMedia ||
             bio->Media->LogicalPartition )
            continue;
        if ( boot_edd_info_nr < EDD_INFO_MAX )
        {
            info->device = 0x80 + boot_edd_info_nr; /* fake */
            info->version = 0x11;
            params->length = offsetof(struct edd_device_params, dpte_ptr);
            params->number_of_sectors = bio->Media->LastBlock + 1;
            params->bytes_per_sector = bio->Media->BlockSize;
            params->dpte_ptr = ~0;
        }
        ++boot_edd_info_nr;
        status = efi_bs->HandleProtocol(handles[i], &devp_guid,
                                        (void **)&devp);
        if ( EFI_ERROR(status) )
            continue;
        for ( ; !IsDevicePathEnd(devp.DevPath);
              devp.DevPath = NextDevicePathNode(devp.DevPath) )
        {
            switch ( DevicePathType(devp.DevPath) )
            {
                const u8 *p;

            case ACPI_DEVICE_PATH:
                if ( state != root || boot_edd_info_nr > EDD_INFO_MAX )
                    break;
                switch ( DevicePathSubType(devp.DevPath) )
                {
                case ACPI_DP:
                    if ( devp.Acpi->HID != EISA_PNP_ID(0xA03) &&
                         devp.Acpi->HID != EISA_PNP_ID(0xA08) )
                        break;
                    params->interface_path.pci.bus = devp.Acpi->UID;
                    state = acpi;
                    break;
                case EXPANDED_ACPI_DP:
                    /* XXX */
                    break;
                }
                break;
            case HARDWARE_DEVICE_PATH:
                if ( state != acpi ||
                     DevicePathSubType(devp.DevPath) != HW_PCI_DP ||
                     boot_edd_info_nr > EDD_INFO_MAX )
                    break;
                state = pci;
                edd_put_string(params->host_bus_type, "PCI");
                params->interface_path.pci.slot = devp.Pci->Device;
                params->interface_path.pci.function = devp.Pci->Function;
                break;
            case MESSAGING_DEVICE_PATH:
                if ( state != pci || boot_edd_info_nr > EDD_INFO_MAX )
                    break;
                state = ctrlr;
                switch ( DevicePathSubType(devp.DevPath) )
                {
                case MSG_ATAPI_DP:
                    edd_put_string(params->interface_type, "ATAPI");
                    params->interface_path.pci.channel =
                        devp.Atapi->PrimarySecondary;
                    params->device_path.atapi.device = devp.Atapi->SlaveMaster;
                    params->device_path.atapi.lun = devp.Atapi->Lun;
                    break;
                case MSG_SCSI_DP:
                    edd_put_string(params->interface_type, "SCSI");
                    params->device_path.scsi.id = devp.Scsi->Pun;
                    params->device_path.scsi.lun = devp.Scsi->Lun;
                    break;
                case MSG_FIBRECHANNEL_DP:
                    edd_put_string(params->interface_type, "FIBRE");
                    params->device_path.fibre.wwid = devp.FibreChannel->WWN;
                    params->device_path.fibre.lun = devp.FibreChannel->Lun;
                    break;
                case MSG_1394_DP:
                    edd_put_string(params->interface_type, "1394");
                    params->device_path.i1394.eui = devp.F1394->Guid;
                    break;
                case MSG_USB_DP:
                case MSG_USB_CLASS_DP:
                    edd_put_string(params->interface_type, "USB");
                    break;
                case MSG_I2O_DP:
                    edd_put_string(params->interface_type, "I2O");
                    params->device_path.i2o.identity_tag = devp.I2O->Tid;
                    break;
                default:
                    continue;
                }
                info->version = 0x30;
                params->length = sizeof(struct edd_device_params);
                params->key = 0xbedd;
                params->device_path_info_length =
                    sizeof(struct edd_device_params) -
                    offsetof(struct edd_device_params, key);
                for ( p = (const u8 *)&params->key; p < &params->checksum; ++p )
                    params->checksum -= *p;
                break;
            case MEDIA_DEVICE_PATH:
                if ( DevicePathSubType(devp.DevPath) == MEDIA_HARDDRIVE_DP &&
                     devp.HardDrive->MBRType == MBR_TYPE_PCAT &&
                     boot_mbr_signature_nr < EDD_MBR_SIG_MAX )
                {
                    struct mbr_signature *sig = boot_mbr_signature +
                                                boot_mbr_signature_nr;

                    sig->device = 0x80 + boot_edd_info_nr; /* fake */
                    memcpy(&sig->signature, devp.HardDrive->Signature,
                           sizeof(sig->signature));
                    ++boot_mbr_signature_nr;
                }
                break;
            }
        }
    }
    if ( handles )
        efi_bs->FreePool(handles);
    if ( boot_edd_info_nr > EDD_INFO_MAX )
        boot_edd_info_nr = EDD_INFO_MAX;
}

static void __init efi_arch_console_init(UINTN cols, UINTN rows)
{
    vga_console_info.video_type = XEN_VGATYPE_TEXT_MODE_3;
    vga_console_info.u.text_mode_3.columns = cols;
    vga_console_info.u.text_mode_3.rows = rows;
    vga_console_info.u.text_mode_3.font_height = 16;
}

static void __init efi_arch_video_init(EFI_GRAPHICS_OUTPUT_PROTOCOL *gop,
                                       UINTN info_size,
                                       EFI_GRAPHICS_OUTPUT_MODE_INFORMATION *mode_info)
{
    int bpp = 0;

    switch ( mode_info->PixelFormat )
    {
    case PixelRedGreenBlueReserved8BitPerColor:
        vga_console_info.u.vesa_lfb.red_pos = 0;
        vga_console_info.u.vesa_lfb.red_size = 8;
        vga_console_info.u.vesa_lfb.green_pos = 8;
        vga_console_info.u.vesa_lfb.green_size = 8;
        vga_console_info.u.vesa_lfb.blue_pos = 16;
        vga_console_info.u.vesa_lfb.blue_size = 8;
        vga_console_info.u.vesa_lfb.rsvd_pos = 24;
        vga_console_info.u.vesa_lfb.rsvd_size = 8;
        bpp = 32;
        break;
    case PixelBlueGreenRedReserved8BitPerColor:
        vga_console_info.u.vesa_lfb.red_pos = 16;
        vga_console_info.u.vesa_lfb.red_size = 8;
        vga_console_info.u.vesa_lfb.green_pos = 8;
        vga_console_info.u.vesa_lfb.green_size = 8;
        vga_console_info.u.vesa_lfb.blue_pos = 0;
        vga_console_info.u.vesa_lfb.blue_size = 8;
        vga_console_info.u.vesa_lfb.rsvd_pos = 24;
        vga_console_info.u.vesa_lfb.rsvd_size = 8;
        bpp = 32;
        break;
    case PixelBitMask:
        bpp = set_color(mode_info->PixelInformation.RedMask, bpp,
                        &vga_console_info.u.vesa_lfb.red_pos,
                        &vga_console_info.u.vesa_lfb.red_size);
        bpp = set_color(mode_info->PixelInformation.GreenMask, bpp,
                        &vga_console_info.u.vesa_lfb.green_pos,
                        &vga_console_info.u.vesa_lfb.green_size);
        bpp = set_color(mode_info->PixelInformation.BlueMask, bpp,
                        &vga_console_info.u.vesa_lfb.blue_pos,
                        &vga_console_info.u.vesa_lfb.blue_size);
        bpp = set_color(mode_info->PixelInformation.ReservedMask, bpp,
                        &vga_console_info.u.vesa_lfb.rsvd_pos,
                        &vga_console_info.u.vesa_lfb.rsvd_size);
        if ( bpp > 0 )
            break;
        /* fall through */
    default:
        PrintErr(L"Current graphics mode is unsupported!\r\n");
        bpp  = 0;
        break;
    }
    if ( bpp > 0 )
    {
        vga_console_info.video_type = XEN_VGATYPE_EFI_LFB;
        vga_console_info.u.vesa_lfb.gbl_caps = 2; /* possibly non-VGA */
        vga_console_info.u.vesa_lfb.width =
            mode_info->HorizontalResolution;
        vga_console_info.u.vesa_lfb.height = mode_info->VerticalResolution;
        vga_console_info.u.vesa_lfb.bits_per_pixel = bpp;
        vga_console_info.u.vesa_lfb.bytes_per_line =
            (mode_info->PixelsPerScanLine * bpp + 7) >> 3;
        vga_console_info.u.vesa_lfb.lfb_base = gop->Mode->FrameBufferBase;
        vga_console_info.u.vesa_lfb.lfb_size =
            (gop->Mode->FrameBufferSize + 0xffff) >> 16;
    }
}

static void __init efi_arch_memory_setup(void)
{
    unsigned int i;
    EFI_STATUS status;

    /* Allocate space for trampoline (in first Mb). */
    cfg.addr = 0x100000;
    cfg.size = trampoline_end - trampoline_start;
    status = efi_bs->AllocatePages(AllocateMaxAddress, EfiLoaderData,
                                   PFN_UP(cfg.size), &cfg.addr);
    if ( status == EFI_SUCCESS )
        relocate_trampoline(cfg.addr);
    else
    {
        cfg.addr = 0;
        PrintStr(L"Trampoline space cannot be allocated; will try fallback.\r\n");
    }

    /* Initialise L2 identity-map and boot-map page table entries (16MB). */
    for ( i = 0; i < 8; ++i )
    {
        unsigned int slot = (xen_phys_start >> L2_PAGETABLE_SHIFT) + i;
        paddr_t addr = slot << L2_PAGETABLE_SHIFT;

        l2_identmap[slot] = l2e_from_paddr(addr, PAGE_HYPERVISOR|_PAGE_PSE);
        slot &= L2_PAGETABLE_ENTRIES - 1;
        l2_bootmap[slot] = l2e_from_paddr(addr, __PAGE_HYPERVISOR|_PAGE_PSE);
    }
    /* Initialise L3 boot-map page directory entries. */
    l3_bootmap[l3_table_offset(xen_phys_start)] =
        l3e_from_paddr((UINTN)l2_bootmap, __PAGE_HYPERVISOR);
    l3_bootmap[l3_table_offset(xen_phys_start + (8 << L2_PAGETABLE_SHIFT) - 1)] =
        l3e_from_paddr((UINTN)l2_bootmap, __PAGE_HYPERVISOR);
}

static void __init efi_arch_handle_module(struct file *file, const CHAR16 *name,
                                          char *options)
{
    union string local_name;
    void *ptr;

    /*
     * Make a copy, as conversion is destructive, and caller still wants
     * wide string available after this call returns.
     */
    if ( efi_bs->AllocatePool(EfiLoaderData, (wstrlen(name) + 1) * sizeof(*name),
                              &ptr) != EFI_SUCCESS )
        blexit(L"Unable to allocate string buffer");

    local_name.w = ptr;
    wstrcpy(local_name.w, name);
    w2s(&local_name);

    /*
     * If options are provided, put them in
     * mb_modules[mbi.mods_count].string after the filename, with a space
     * separating them.  place_string() prepends strings and adds separating
     * spaces, so the call order is reversed.
     */
    if ( options )
        place_string(&mb_modules[mbi.mods_count].string, options);
    place_string(&mb_modules[mbi.mods_count].string, local_name.s);
    mb_modules[mbi.mods_count].mod_start = file->addr >> PAGE_SHIFT;
    mb_modules[mbi.mods_count].mod_end = file->size;
    ++mbi.mods_count;
    efi_bs->FreePool(ptr);
}

static void __init efi_arch_cpu(void)
{
    if ( cpuid_eax(0x80000000) > 0x80000000 )
    {
        cpuid_ext_features = cpuid_edx(0x80000001);
        boot_cpu_data.x86_capability[1] = cpuid_ext_features;
    }
}

static void __init efi_arch_blexit(void)
{
    if ( ucode.addr )
        efi_bs->FreePages(ucode.addr, PFN_UP(ucode.size));
}

static void __init efi_arch_halt(void)
{
    local_irq_disable();
    for ( ; ; )
        halt();
}

static void __init efi_arch_load_addr_check(EFI_LOADED_IMAGE *loaded_image)
{
    xen_phys_start = (UINTN)loaded_image->ImageBase;
    if ( (xen_phys_start + loaded_image->ImageSize - 1) >> 32 )
        blexit(L"Xen must be loaded below 4Gb.");
    if ( xen_phys_start & ((1 << L2_PAGETABLE_SHIFT) - 1) )
        blexit(L"Xen must be loaded at a 2Mb boundary.");
    trampoline_xen_phys_start = xen_phys_start;
}

static bool_t __init efi_arch_use_config_file(EFI_SYSTEM_TABLE *SystemTable)
{
    return 1; /* x86 always uses a config file */
}

static void efi_arch_flush_dcache_area(const void *vaddr, UINTN size) { }

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
