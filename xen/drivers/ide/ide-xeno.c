#include <xeno/config.h>
#include <xeno/types.h>
#include <xeno/lib.h>
#include <xeno/ide.h>
#include <xeno/segment.h>
#include <hypervisor-ifs/block.h>
#include <asm/domain_page.h>
#include <asm/io.h>

void ide_probe_devices (xen_disk_info_t* xdi, int *count, drive_t xdrives[])
{
    int loop;
    unsigned int unit;
    xen_disk_info_t *xen_xdi = map_domain_mem(virt_to_phys(xdi));
    
    for (loop = 0; loop < MAX_HWIFS; ++loop) {

	ide_hwif_t *hwif = &ide_hwifs[loop];
	if (hwif->present) {

	    for (unit = 0; unit < MAX_DRIVES; ++unit) {
		unsigned long capacity;
		ide_drive_t *drive = &hwif->drives[unit];

		/* only count drives with capacity > 0. this excludes cdroms */
		if (drive->present && (capacity = current_capacity(drive)))
		{
		    xen_xdi->disks[xen_xdi->count].type = XEN_DISK_IDE;
		    xen_xdi->disks[xen_xdi->count].capacity = capacity;
		    xdrives[xen_xdi->count].major = hwif->major;
		    xen_xdi->count++;

		    /*
		    printk (KERN_ALERT "IDE-XENO %d\n", xen_xdi->count);
		    printk (KERN_ALERT "  capacity 0x%lx\n", capacity);
		    printk (KERN_ALERT "  head     0x%x\n",  drive->bios_head);
		    printk (KERN_ALERT "  sector   0x%x\n",  drive->bios_sect);
		    printk (KERN_ALERT "  cylinder 0x%x\n",  drive->bios_cyl);
		    printk (KERN_ALERT "  major    0x%x\n",  hwif->major);
		    */
		}
	    }
	}
    }
    *count = xen_xdi->count;

    unmap_domain_mem(xen_xdi);
}
