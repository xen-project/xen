#include <xen/config.h>
#include <xen/types.h>
#include <xen/lib.h>
#include <xen/ide.h>
#include <xen/vbd.h>
#include <asm/domain_page.h>
#include <asm/io.h>

static kdev_t ide_devs[] = { 
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
    int i, unit;
    ide_drive_t *drive;
    xen_disk_t *xd = &xdi->disks[xdi->count];

    for ( i = 0; i < MAX_HWIFS; i++ )
    {
	ide_hwif_t *hwif = &ide_hwifs[i];
	if ( !hwif->present ) continue;

        for ( unit = 0; unit < MAX_DRIVES; unit++ )
        {
            drive = &hwif->drives[unit];

            if ( !drive->present )
                continue;

	    if ( xdi->count == xdi->max )
                BUG();

	    /* We export 'raw' linux device numbers to domain 0. */
	    xd->device = ide_devs[(i * MAX_DRIVES) + unit]; 

	    /*
	     * NB: we use the ide 'media' field (ide_disk, ide_cdrom, etc) as 
	     * our 'type' field (XD_TYPE_DISK, XD_TYPE_CDROM, etc). Hence must 
	     * ensure these are kept in sync.
	     */
	    if ( (xd->info = drive->media) == XD_TYPE_CDROM ) 
		xd->info |= XD_FLAG_RO; 

	    xd->capacity = current_capacity(drive);
	    xd->domain   = 0;
		
            xdi->count++;
            xd++;
        }
    }
}
