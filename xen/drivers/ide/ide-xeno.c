#include <xeno/config.h>
#include <xeno/types.h>
#include <xeno/lib.h>
#include <xeno/ide.h>
#include <xeno/vbd.h>
#include <asm/domain_page.h>
#include <asm/io.h>

#define NR_IDE_DEVS  20

static kdev_t ide_devs[NR_IDE_DEVS] = { 
    MKDEV(IDE0_MAJOR, 0), MKDEV(IDE0_MAJOR, 64),                /* hda, hdb */
    MKDEV(IDE1_MAJOR, 0), MKDEV(IDE1_MAJOR, 64),                /* hdc, hdd */
    MKDEV(IDE2_MAJOR, 0), MKDEV(IDE2_MAJOR, 64),                /* hde, hdf */
    MKDEV(IDE3_MAJOR, 0), MKDEV(IDE3_MAJOR, 64),                /* hdg, hdh */
    MKDEV(IDE4_MAJOR, 0), MKDEV(IDE4_MAJOR, 64),                /* hdi, hdj */
    MKDEV(IDE5_MAJOR, 0), MKDEV(IDE5_MAJOR, 64),                /* hdk, hdl */
    MKDEV(IDE6_MAJOR, 0), MKDEV(IDE6_MAJOR, 64),                /* hdm, hdn */
    MKDEV(IDE7_MAJOR, 0), MKDEV(IDE7_MAJOR, 64),                /* hdo, hdp */
    MKDEV(IDE8_MAJOR, 0), MKDEV(IDE8_MAJOR, 64),                /* hdq, hdr */
    MKDEV(IDE9_MAJOR, 0), MKDEV(IDE9_MAJOR, 64)                 /* hds, hdt */
};




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

	    /* SMH: we export 'raw' linux device numbers to domain 0 */
            device   = ide_devs[(loop * MAX_DRIVES) + unit]; 
	    type     = drive->media; 
            capacity = current_capacity(drive);

            xdi->disks[xdi->count].device   = device; 
            xdi->disks[xdi->count].info     = type; 
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
