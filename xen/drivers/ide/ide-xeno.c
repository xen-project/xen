#include <xeno/config.h>
#include <xeno/types.h>
#include <xeno/lib.h>
#include <xeno/ide.h>
#include <xeno/segment.h>
#include <hypervisor-ifs/block.h>
#include <asm/domain_page.h>
#include <asm/io.h>

void ide_probe_devices(xen_disk_info_t* xdi)
{
    int loop;
    unsigned int unit;
    xen_disk_info_t *xen_xdi = map_domain_mem(virt_to_phys(xdi));
    unsigned long capacity;
    ide_drive_t *drive;
    
    for ( loop = 0; loop < MAX_HWIFS; loop++ )
    {
	ide_hwif_t *hwif = &ide_hwifs[loop];
	if ( !hwif->present ) continue;

        for ( unit = 0; unit < MAX_DRIVES; unit++ )
        {
            drive = &hwif->drives[unit];
            if ( !drive->present ) continue;
            
            capacity = current_capacity(drive);
            xen_xdi->disks[xen_xdi->count].device =
                MK_IDE_XENDEV((loop * MAX_DRIVES) + unit);
            xen_xdi->disks[xen_xdi->count].capacity = capacity;
            xen_xdi->count++;

            printk("Disk %d: IDE-XENO capacity %ldkB (%ldMB)\n",
                   xen_xdi->count, capacity>>1, capacity>>11);
        }
    }

    unmap_domain_mem(xen_xdi);
}
