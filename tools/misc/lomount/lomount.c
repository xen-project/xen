/*
 * lomount - utility to mount partitions in a hard disk image
 *
 * Copyright (c) 2004 Jim Brown
 * Copyright (c) 2004 Brad Watson
 * Copyright (c) 2004 Mulyadi Santosa
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>

#define BUF 4096

//#define SECSIZE 4096    /* arbitrarilly large (it's probably just 512) */
#define SECSIZE 512

struct pentry 
{
	unsigned char bootable; 
	unsigned char start_head;
	unsigned int start_cylinder;
	unsigned char start_sector;
	unsigned char system;
	unsigned char end_head;
	unsigned int  end_cylinder;
	unsigned char end_sector;
	unsigned long start_sector_abs;
	unsigned long no_of_sectors_abs;
};

char * progname;

int loadptable(const char *argv, struct pentry parttbl[], struct pentry **exttbl)
{
	FILE *fd; 
	int i, valid, total_known_sectors = 0;
	unsigned char *pi; 
	unsigned char data [SECSIZE]; 
	unsigned long extent = 0, old_extent = 0, e_count = 1;
	struct pentry exttbls[4];

	fd = fopen(argv, "r");
	if (fd == NULL)
	{
		perror ("lomount"); 
		return 1;
	}
	i = fread (&data, 1, sizeof (data), fd); 
	if (i < SECSIZE)
	{
		fprintf (stderr, "%s: could not read the entire first sector\n", progname); 
		return 1;
	}
	for (i = 0;i < 4;i++)
	{
		pi = &data [446 + 16 * i];
		parttbl [i].bootable = *pi; 
		parttbl [i].start_head  = *(pi + 1); 
		parttbl [i].start_cylinder = *(pi + 3) | ((*(pi + 2) << 2) & 0x300);
		parttbl [i].start_sector = *(pi + 2) & 0x3f;
		parttbl [i].system = *(pi + 4);
		parttbl [i].end_head = *(pi + 5);
		parttbl [i].end_cylinder = *(pi + 7) | ((*(pi + 6) << 2) & 0x300);
		parttbl [i].end_sector = *(pi + 6) & 0x3f;
		parttbl [i].start_sector_abs = 
			(unsigned long) *(pi + 8) | ((unsigned long) *(pi + 9) << 8) | ((unsigned long) *(pi + 10) << 16) | ((unsigned long) *(pi + 11) << 24);
		parttbl [i].no_of_sectors_abs = 
			(unsigned long) *(pi + 12) | ((unsigned long) *(pi + 13) << 8) | ((unsigned long) *(pi + 14) << 16) | ((unsigned long) *(pi + 15) << 24);
		if (parttbl[i].system == 0xF || parttbl[i].system == 0x5)
		{
			extent = parttbl[i].start_sector_abs * SECSIZE;
			/* save the location of the "real" extended partition */
			old_extent = extent;
		}
	}
	valid = (data [510] == 0x55 && data [511] == 0xaa) ? 1 : 0;
	for (i = 0; i < 4; i++)
	{
		total_known_sectors += parttbl[i].no_of_sectors_abs;
	}
	/* Extended Partition layout format was obtained from
	http://wigner.cped.ornl.gov/the-gang/att-0520/03-Partition.htm */
#ifdef DEBUG
	if (extent != 0)
	{
		printf("extended partition detected at offset %d\n", extent);
	}
#endif
	while (extent != 0)
	{
/* according to realloc(3) passing NULL as pointer is same as calling malloc() */
		exttbl[0] = realloc(exttbl[0], e_count * sizeof(struct pentry));
		fseek(fd, extent, SEEK_SET);
		i = fread (&data, 1, sizeof (data), fd); 
		if (i < SECSIZE)
		{
			fprintf (stderr, "%s: could not read the entire first sector\n", progname); 
			return 1;
		}
	/* only first 2 entrys are used in extented partition tables */
		for (i = 0;i < 2;i++)
		{
			pi = &data [446 + 16 * i];
			exttbls [i].bootable = *pi; 
			exttbls [i].start_head  = *(pi + 1); 
			exttbls [i].start_cylinder = *(pi + 3) | ((*(pi + 2) << 2) & 0x300);
			exttbls [i].start_sector = *(pi + 2) & 0x3f;
			exttbls [i].system = *(pi + 4);
			exttbls [i].end_head = *(pi + 5);
			exttbls [i].end_cylinder = *(pi + 7) | ((*(pi + 6) << 2) & 0x300);
			exttbls [i].end_sector = *(pi + 6) & 0x3f;
			exttbls [i].start_sector_abs = 
				(unsigned long) *(pi + 8) | ((unsigned long) *(pi + 9) << 8) | ((unsigned long) *(pi + 10) << 16) | ((unsigned long) *(pi + 11) << 24);
			exttbls [i].no_of_sectors_abs = 
				(unsigned long) *(pi + 12) | ((unsigned long) *(pi + 13) << 8) | ((unsigned long) *(pi + 14) << 16) | ((unsigned long) *(pi + 15) << 24);
			if (i == 0)
			{
				//memmove((void *)exttbl[e_count-1], (void *)exttbls[i], sizeof(struct pentry));
				//memmove() seems broken!
				exttbl[0][e_count-1].bootable = exttbls [i].bootable;
				exttbl[0][e_count-1].start_head  = exttbls [i].start_head;
				exttbl[0][e_count-1].start_cylinder = exttbls [i].start_cylinder;
				exttbl[0][e_count-1].start_sector = exttbls [i].start_sector;
				exttbl[0][e_count-1].system = exttbls [i].system;
				exttbl[0][e_count-1].end_head = exttbls [i].end_head;
				exttbl[0][e_count-1].end_cylinder = exttbls [i].end_cylinder;
				exttbl[0][e_count-1].end_sector = exttbls [i].end_sector;
				exttbl[0][e_count-1].start_sector_abs = exttbls [i].start_sector_abs;
				exttbl[0][e_count-1].no_of_sectors_abs = exttbls [i].no_of_sectors_abs;
			/* adjust for start of image instead of start of ext partition */
				exttbl[0][e_count-1].start_sector_abs += (extent/SECSIZE);
#ifdef DEBUG
				printf("extent %d start_sector_abs %d\n", extent, exttbl[0][e_count-1].start_sector_abs);
#endif
			//else if (parttbl[i].system == 0x5)
			}
			else if (i == 1)
			{
				extent = (exttbls[i].start_sector_abs * SECSIZE);
				if (extent)
					extent += old_extent;
			}
		}
		e_count ++;
	}
	//fclose (fd);
	//the above segfaults (?!!!)
#ifdef DEBUG
	printf("e_count = %d\n", e_count);
#endif
	return valid;
}

int main(int argc, char ** argv)
{
	struct pentry perttbl [4];
	struct pentry *exttbl[1], *parttbl;
	char buf[BUF], argv2[BUF], diskimage[BUF];
	int partition = 1, sec, num = 0, pnum = 0, len = BUF, i, f = 0, valid;
	progname = argv[0];
	exttbl[0] = NULL;
	for (i = 1; i < argc; i ++)
	{
		if (strncmp(argv[i], "-diskimage", BUF)==0)
		{
			strncpy(diskimage, argv[i+1], BUF);
			i++; f = 1;
		}
		else if (strncmp(argv[i], "-partition", BUF)==0)
		{
			partition = atoi(argv[i+1]);
			i++;
			if (partition < 1) partition = 1;
		}
		else
		{
			strncat(argv2, argv[i], len);
			strncat(argv2, " ", len-1);
			len -= strlen(argv[i]);
			len--;
		}
	}
	if (!f)
	{
		printf("You must specify -diskimage and -partition\n");
		printf("ex. lomount -t fs-type -diskimage hda.img -partition 1 /mnt\n");
		return 0;
	}
	valid = loadptable(diskimage, perttbl, exttbl);
	if (!valid)
	{
		printf("Warning: disk image does not appear to describe a valid partition table.\n");
	}
	/* NOTE: need to make sure this always rounds down */
	//sec = total_known_sectors / sizeof_diskimage;
/* The above doesn't work unless the disk image is completely filled by
partitions ... unused space will thrown off the sector size. The calculation
assumes the disk image is completely filled, and that the few sectors used
to store the partition table/MBR are few enough that the calculated value is
off by (larger than) a value less than one. */
	sec = 512; /* TODO: calculate real sector size */
#ifdef DEBUG
	printf("sec: %d\n", sec);
#endif
	if (partition > 4)
	{
		if (exttbl[0] == NULL)
		{
		    printf("No extended partitions were found in %s.\n", diskimage);
		    return 2;
		}
		parttbl = exttbl[0];
		if (parttbl[partition-5].no_of_sectors_abs == 0)
		{
			printf("Partition %d was not found in %s.\n", partition, diskimage);
			return 3;
		}
		partition -= 4;
	}
	else
	{
		parttbl = perttbl;
		if (parttbl[partition-1].no_of_sectors_abs == 0)
		{
			printf("Partition %d was not found in %s.\n", partition, diskimage);
			return 3;
		}
	}
	num = parttbl[partition-1].start_sector_abs;
	pnum = sec * num;
#ifdef DEBUG
	printf("offset = %d\n", pnum);
#endif
	snprintf(buf, BUF, "mount -oloop,offset=%d %s %s", pnum, diskimage, argv2);
#ifdef DEBUG
	printf("%s\n", buf);
#endif
	system(buf);
	return 0;
}
