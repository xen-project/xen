/*
 *  Author:  Daniel De Graaf <dgdegra@tycho.nsa.gov>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2,
 *  as published by the Free Software Foundation.
 */

#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <xenctrl.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>

/* Pulled from linux/include/linux/ioport.h */
#define IORESOURCE_TYPE_BITS    0x00001f00  /* Resource type */
#define IORESOURCE_IO       0x00000100
#define IORESOURCE_MEM      0x00000200
#define IORESOURCE_IRQ      0x00000400
#define IORESOURCE_DMA      0x00000800
#define IORESOURCE_BUS      0x00001000


static void usage (int argCnt, char *argv[])
{
	fprintf(stderr, "Usage: %s SBDF label\n", argv[0]);
	exit(1);
}

int main (int argCnt, char *argv[])
{
	int ret, err = 0;
	xc_interface *xch = 0;
	int seg, bus, dev, fn;
	uint32_t sbdf;
	uint64_t start, end, flags;
	char buf[1024];
	FILE *f;

	if (argCnt != 3)
		usage(argCnt, argv);

	xch = xc_interface_open(0,0,0);
	if ( !xch )
	{
		fprintf(stderr, "Unable to create interface to xenctrl: %s\n",
				strerror(errno));
		err = 1;
		goto done;
	}

	sscanf(argv[1], "%x:%x:%x.%d", &seg, &bus, &dev, &fn);
	sbdf = (seg << 16) | (bus << 8) | (dev << 3) | fn;

	snprintf(buf, sizeof(buf), "/sys/bus/pci/devices/%04x:%02x:%02x.%d/resource",
			seg, bus, dev, fn);

	f = fopen(buf, "r");
	if (!f) {
		fprintf(stderr, "Unable to find device %s: %s\n", argv[1],
				strerror(errno));
		err = 1;
		goto done;
	}

	ret = xc_flask_add_device(xch, sbdf, argv[2]);
	if (ret) {
		fprintf(stderr, "xc_flask_add_device: Unable to set context of PCI device %s (0x%x) to %s: %d\n",
			argv[1], sbdf, argv[2], ret);
		err = 2;
		goto done;
	}

	while (fscanf(f, "0x%"SCNx64" 0x%"SCNx64" 0x%"SCNx64"\n", &start, &end, &flags) == 3) {
		if (flags & IORESOURCE_IO) {
			// printf("Port %"PRIx64"-%"PRIx64"\n", start, end);
			ret = xc_flask_add_ioport(xch, start, end, argv[2]);
			if (ret) {
				fprintf(stderr, "xc_flask_add_ioport %"PRIx64"-%"PRIx64" failed: %d\n",
						start, end, ret);
				err = 2;
			}
		} else if (flags & IORESOURCE_MEM) {
			start >>= 12;
			end >>= 12;
			// printf("IOMEM %"PRIx64"-%"PRIx64"\n", start, end);
			ret = xc_flask_add_iomem(xch, start, end, argv[2]);
			if (ret) {
				fprintf(stderr, "xc_flask_add_iomem %"PRIx64"-%"PRIx64" failed: %d\n",
						start, end, ret);
				err = 2;
			}
		}
	}
	fclose(f);

	snprintf(buf, sizeof(buf), "/sys/bus/pci/devices/%04x:%02x:%02x.%d/irq",
			seg, bus, dev, fn);
	f = fopen(buf, "r");
	if (!f)
		goto done;
	if (fscanf(f, "%" SCNu64, &start) != 1)
		start = 0;
	if (start) {
		ret = xc_flask_add_pirq(xch, start, argv[2]);
		if (ret) {
			fprintf(stderr, "xc_flask_add_pirq %"PRIu64" failed: %d\n",
					start, ret);
			err = 2;
		}
	}
	fclose(f);
done:
	if ( xch )
		xc_interface_close(xch);

	return err;
}
