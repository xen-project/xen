#include <xeno/config.h>
#include <xeno/types.h>
#include <xeno/lib.h>
#include <xeno/ide.h>
#include <xeno/vbd.h>
#include <asm/domain_page.h>
#include <asm/io.h>

void ide_probe_devices(xen_disk_info_t* xdi)
{
    int loop;
    unsigned int unit;
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

            xdi->disks[xdi->count].device   = device; 
            xdi->disks[xdi->count].type     = type; 
            xdi->disks[xdi->count].capacity = capacity;
            xdi->count++;

            printk("Device %d: IDE-XENO (%s) capacity %ldkB (%ldMB)\n",
                   xdi->count, (type == XD_TYPE_DISK) ? "disk" : 
		   ((type == XD_TYPE_CDROM) ? "cdrom" : "unknown"), 
		   capacity>>1, capacity>>11);
        }
    }
    
    return;
}
