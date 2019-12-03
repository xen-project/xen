/******************************************************************************
 * arch/x86/guest/pvh-boot.c
 *
 * PVH boot time support
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright (c) 2017 Citrix Systems Ltd.
 */
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/mm.h>

#include <asm/e820.h>
#include <asm/guest.h>

#include <public/arch-x86/hvm/start_info.h>

/* Initialised in head.S, before .bss is zeroed. */
bool __initdata pvh_boot;
uint32_t __initdata pvh_start_info_pa;

static multiboot_info_t __initdata pvh_mbi;
static module_t __initdata pvh_mbi_mods[8];
static const char *__initdata pvh_loader = "PVH Directboot";

static void __init convert_pvh_info(multiboot_info_t **mbi,
                                    module_t **mod)
{
    const struct hvm_start_info *pvh_info = __va(pvh_start_info_pa);
    const struct hvm_modlist_entry *entry;
    unsigned int i;

    if ( pvh_info->magic != XEN_HVM_START_MAGIC_VALUE )
        panic("Magic value is wrong: %x\n", pvh_info->magic);

    /*
     * Temporary module array needs to be at least one element bigger than
     * required. The extra element is used to aid relocation. See
     * arch/x86/setup.c:__start_xen().
     */
    if ( ARRAY_SIZE(pvh_mbi_mods) <= pvh_info->nr_modules )
        panic("The module array is too small, size %zu, requested %u\n",
              ARRAY_SIZE(pvh_mbi_mods), pvh_info->nr_modules);

    /*
     * Turn hvm_start_info into mbi. Luckily all modules are placed under 4GB
     * boundary on x86.
     */
    pvh_mbi.flags = MBI_CMDLINE | MBI_MODULES | MBI_LOADERNAME;

    BUG_ON(pvh_info->cmdline_paddr >> 32);
    pvh_mbi.cmdline = pvh_info->cmdline_paddr;
    pvh_mbi.boot_loader_name = __pa(pvh_loader);

    BUG_ON(pvh_info->nr_modules >= ARRAY_SIZE(pvh_mbi_mods));
    pvh_mbi.mods_count = pvh_info->nr_modules;
    pvh_mbi.mods_addr = __pa(pvh_mbi_mods);

    entry = __va(pvh_info->modlist_paddr);
    for ( i = 0; i < pvh_info->nr_modules; i++ )
    {
        BUG_ON(entry[i].paddr >> 32);
        BUG_ON(entry[i].cmdline_paddr >> 32);

        pvh_mbi_mods[i].mod_start = entry[i].paddr;
        pvh_mbi_mods[i].mod_end   = entry[i].paddr + entry[i].size;
        pvh_mbi_mods[i].string    = entry[i].cmdline_paddr;
    }

    rsdp_hint = pvh_info->rsdp_paddr;

    *mbi = &pvh_mbi;
    *mod = pvh_mbi_mods;
}

static void __init get_memory_map(void)
{
    struct xen_memory_map memmap = {
        .nr_entries = E820MAX,
    };

    set_xen_guest_handle(memmap.buffer, e820_raw.map);
    BUG_ON(xen_hypercall_memory_op(XENMEM_memory_map, &memmap));
    e820_raw.nr_map = memmap.nr_entries;

    /* :( Various toolstacks don't sort the memory map. */
    sanitize_e820_map(e820_raw.map, &e820_raw.nr_map);
}

void __init pvh_init(multiboot_info_t **mbi, module_t **mod)
{
    convert_pvh_info(mbi, mod);

    hypervisor_probe();
    ASSERT(xen_guest);

    get_memory_map();
}

void __init pvh_print_info(void)
{
    const struct hvm_start_info *pvh_info = __va(pvh_start_info_pa);
    const struct hvm_modlist_entry *entry;
    unsigned int i;

    ASSERT(pvh_info->magic == XEN_HVM_START_MAGIC_VALUE);

    printk("PVH start info: (pa %08x)\n", pvh_start_info_pa);
    printk("  version:    %u\n", pvh_info->version);
    printk("  flags:      %#"PRIx32"\n", pvh_info->flags);
    printk("  nr_modules: %u\n", pvh_info->nr_modules);
    printk("  modlist_pa: %016"PRIx64"\n", pvh_info->modlist_paddr);
    printk("  cmdline_pa: %016"PRIx64"\n", pvh_info->cmdline_paddr);
    if ( pvh_info->cmdline_paddr )
        printk("  cmdline:    '%s'\n", (char *)__va(pvh_info->cmdline_paddr));
    printk("  rsdp_pa:    %016"PRIx64"\n", pvh_info->rsdp_paddr);

    entry = __va(pvh_info->modlist_paddr);
    for ( i = 0; i < pvh_info->nr_modules; i++ )
    {
        printk("    mod[%u].pa:         %016"PRIx64"\n", i, entry[i].paddr);
        printk("    mod[%u].size:       %016"PRIu64"\n", i, entry[i].size);
        printk("    mod[%u].cmdline_pa: %016"PRIx64"\n",
               i, entry[i].cmdline_paddr);
        if ( entry[i].cmdline_paddr )
            printk("    mod[%1u].cmdline:    '%s'\n", i,
                   (char *)__va(entry[i].cmdline_paddr));
    }
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
