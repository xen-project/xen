#include <xeno/config.h>
#include <xeno/types.h>
#include <xeno/lib.h>
#include <xeno/ide.h>
#include <hypervisor-ifs/block.h>


void ide_probe_devices (xen_disk_info_t* xdi)
{
    int loop;
    unsigned int unit;
    
    for (loop = 0; loop < MAX_HWIFS; ++loop) {

	ide_hwif_t *hwif = &ide_hwifs[loop];
	if (hwif->present) {

	    for (unit = 0; unit < MAX_DRIVES; ++unit) {
		unsigned long capacity;
		ide_drive_t *drive = &hwif->drives[unit];

		if (drive->present) {
		    capacity = current_capacity (drive);
		    xdi->disks[xdi->count].type = XEN_DISK_IDE;
		    xdi->disks[xdi->count].capacity = capacity;
		    xdi->count++;

		    printk (KERN_ALERT "IDE-XENO %d\n", xdi->count);
		    printk (KERN_ALERT "  capacity  0x%lx\n", capacity);
		    printk (KERN_ALERT "  head      0x%x\n",  drive->bios_head);
		    printk (KERN_ALERT "  sector    0x%x\n",  drive->bios_sect);
		    printk (KERN_ALERT "  cylinder  0x%x\n",  drive->bios_cyl);
		}
	    }
	}
    }

  return;
}
