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
    unsigned short device, type; 
    ide_drive_t *drive;
    
    for ( loop = 0; loop < MAX_HWIFS; loop++ )
    {
	ide_hwif_t *hwif = &ide_hwifs[loop];
	if ( !hwif->present ) continue;

        for ( unit = 0; unit < MAX_DRIVES; unit++ )
        {
            drive = &hwif->drives[unit];

            if ( !drive->present ) continue;
            
	    /* 
	    ** NB: we use the ide 'media' field (ide_disk, ide_cdrom, etc) 
	    ** as our 'type' field (XD_TYPE_DISK, XD_TYPE_CDROM, etc). 
	    ** Hence must ensure these are kept in sync. 
	    */
	    type     = drive->media; 
            device   = MK_IDE_XENDEV((loop * MAX_DRIVES) + unit);
            capacity = current_capacity(drive);

            xen_xdi->disks[xen_xdi->count].device   = device; 
            xen_xdi->disks[xen_xdi->count].type     = type; 
            xen_xdi->disks[xen_xdi->count].capacity = capacity;
            xen_xdi->count++;

            printk("Device %d: IDE-XENO (%s) capacity %ldkB (%ldMB)\n",
                   xen_xdi->count, (type == XD_TYPE_DISK) ? "disk" : 
		   ((type == XD_TYPE_CDROM) ? "cdrom" : "unknown"), 
		   capacity>>1, capacity>>11);
        }
    }

    unmap_domain_mem(xen_xdi);
}
