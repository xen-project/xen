/*
 * lomount - utility to mount partitions in a hard disk image
 *
 * Copyright (c) 2004 Jim Brown
 * Copyright (c) 2004 Brad Watson
 * Copyright (c) 2004 Mulyadi Santosa
 * Major rewrite by Tristan Gingold:
 *  - Handle GPT partitions
 *  - Handle large files 
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

/*
 *  Return code:
 *
 *  bit 7 set:		lomount wrapper failed
 *  bit 7 clear:	lomount wrapper ok; mount's return code in low 7 bits
 *  0			success
 */

enum
{
	ERR_USAGE = 0x80,	// Incorrect usage
	ERR_PART_PARSE,		// Failed to parse partition table
	ERR_NO_PART,		// No such partition
	ERR_NO_EPART,		// No such extended partition
	ERR_MOUNT		// Other failure of mount command
};

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/wait.h>
#include <errno.h>

#define BUF 4096

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
	unsigned long long start_sector_abs;
	unsigned long long no_of_sectors_abs;
};

static void
disp_entry (struct pentry *p)
{
	printf ("%10llu - %10llu: %02x %x\n",
		SECSIZE * p->start_sector_abs,
		SECSIZE * (p->start_sector_abs + p->no_of_sectors_abs - 1),
		p->system,
		p->bootable);
}

static unsigned long
read_le4 (unsigned char *p)
{
	return (unsigned long) p[0]
		| ((unsigned long) p[1] << 8)
		| ((unsigned long) p[2] << 16)
		| ((unsigned long) p[3] << 24);
}

static unsigned long long
read_le8 (unsigned char *p)
{
	return (unsigned long long) p[0]
		| ((unsigned long long) p[1] << 8)
		| ((unsigned long long) p[2] << 16)
		| ((unsigned long long) p[3] << 24)
		| ((unsigned long long) p[4] << 32)
		| ((unsigned long long) p[5] << 40)
		| ((unsigned long long) p[6] << 48)
		| ((unsigned long long) p[7] << 56);
}

/* Return true if the partition table is a GPT protective MBR.  */
static int
check_gpt (struct pentry *part, int nbr_part)
{
	if (nbr_part != 4)
		return 0;
	if (part[0].system == 0xee
	    && part[1].no_of_sectors_abs == 0
	    && part[2].no_of_sectors_abs == 0
	    && part[3].no_of_sectors_abs == 0)
		return 1;
	return 0;
}

static int
load_gpt (const char *diskimage, struct pentry *parttbl[])
{
	FILE *fd;
	size_t size;
	int fail = -1;
	unsigned char data[SECSIZE];
	unsigned long long entries_lba;
	unsigned long entry_size;
	struct pentry *part;
	int nbr_part;
	unsigned long long off;
	int i;

	fd = fopen(diskimage, "r");
	if (fd == NULL)
	{
		perror(diskimage);
		goto done;
	}
	fseeko (fd, SECSIZE, SEEK_SET);
	size = fread (&data, 1, sizeof(data), fd);
	if (size < (size_t)sizeof(data))
	{
		fprintf(stderr, "Could not read the GPT header of %s.\n",
			diskimage);
		goto done;
	}

	if (memcmp (data, "EFI PART", 8) != 0)
	{
		fprintf (stderr, "Bad GPT signature\n");
		goto done;
	}

	entries_lba = read_le8 (&data[72]);
	nbr_part = read_le4 (&data[80]);
	entry_size = read_le4 (&data[84]);

#ifdef DEBUG
	fprintf(stderr, "lba entries: %llu, nbr_part: %u, entry_size: %lu\n",
		entries_lba, nbr_part, entry_size);
#endif
	part = malloc (nbr_part * sizeof (struct pentry));
	if (part == NULL)
	{
		fprintf(stderr,"Cannot allocate memory\n");
		goto done;
	}
	memset (part, 0, nbr_part * sizeof (struct pentry));
	*parttbl = part;

	off = entries_lba * SECSIZE;
	for (i = 0; i < nbr_part; i++)
	{
		static const char unused_guid[16] = {0};
		fseeko (fd, off, SEEK_SET);
		size = fread (&data, 1, 128, fd);
		if (size < 128)
		{
			fprintf(stderr, "Could not read a GPT entry of %s.\n",
				diskimage);
			goto done;
		}
		if (memcmp (&data[0], unused_guid, 16) == 0)
		{
			part[i].start_sector_abs = 0;
			part[i].no_of_sectors_abs = 0;
		}
		else
		{
			part[i].start_sector_abs = read_le8 (&data[32]);
			part[i].no_of_sectors_abs = read_le8 (&data[40]);
#ifdef DEBUG
			fprintf (stderr, "%d: %llu - %llu\n", i,
				 part[i].start_sector_abs,
				 part[i].no_of_sectors_abs);
#endif
			/* Convert end to a number.  */
			part[i].no_of_sectors_abs -=
				part[i].start_sector_abs - 1;
		}
		off += entry_size;
	}
		
	fail = nbr_part;

done:
	if (fd)
		fclose(fd);
	return fail;
}

/* Read an MBR entry.  */
static void
read_mbr_record (unsigned char pi[16], struct pentry *res)
{
	res->bootable = *pi; 
	res->start_head  = *(pi + 1); 
	res->start_cylinder = *(pi + 3) | ((*(pi + 2) << 2) & 0x300);
	res->start_sector = *(pi + 2) & 0x3f;
	res->system = *(pi + 4);
	res->end_head = *(pi + 5);
	res->end_cylinder = *(pi + 7) | ((*(pi + 6) << 2) & 0x300);
	res->end_sector = *(pi + 6) & 0x3f;
	res->start_sector_abs = read_le4 (&pi[8]);
	res->no_of_sectors_abs = read_le4 (&pi[12]);
}

/* Returns the number of partitions, -1 in case of failure.  */
int load_mbr(const char *diskimage, struct pentry *parttbl[])
{
	FILE *fd;
	size_t size;
	int fail = -1;
	int nbr_part;
	int i;
	unsigned char *pi; 
	unsigned char data [SECSIZE]; 
	unsigned long long extent;
	struct pentry *part;

	nbr_part = 0;

	fd = fopen(diskimage, "r");
	if (fd == NULL)
	{
		perror(diskimage);
		goto done;
	}
	size = fread (&data, 1, sizeof(data), fd);
	if (size < (size_t)sizeof(data))
	{
		fprintf(stderr, "Could not read the entire first sector of %s.\n", diskimage);
		goto done;
	}

	if (data [510] != 0x55 || data [511] != 0xaa)
	{
		fprintf(stderr,"MBR signature mismatch (invalid partition table?)\n");
		goto done;
	}

	/* There is at most 4*4 + 4 = 20 entries, also there should be only
	   one extended partition.  */
	part = malloc (20 * sizeof (struct pentry));
	if (part == NULL)
	{
		fprintf(stderr,"Cannot allocate memory\n");
		goto done;
	}
	*parttbl = part;

	/* Read MBR.  */
	nbr_part = 4;
	for (i = 0; i < 4; i++)
	{
		pi = &data [446 + 16 * i];
		read_mbr_record (pi, &part[i]);
	}

	/* Read extended partitions.  */
	for (i = 0; i < 4; i++)
	{
		if (part[i].system == 0xF || part[i].system == 0x5)
		{
			int j;

			extent = part[i].start_sector_abs * SECSIZE;

			fseeko (fd, extent, SEEK_SET);
			size = fread (&data, 1, sizeof(data), fd);
			if (size < (size_t)sizeof(data))
			{
				fprintf(stderr, "Could not read extended partition of %s.", diskimage);
				goto done;
			}

			for (j = 0; j < 4; j++)
			{
				int n;
				pi = &data [446 + 16 * j];
				n = nbr_part + j;
				read_mbr_record (pi, &part[n]);
			}

			nbr_part += 4;
		}
	}

	fail = nbr_part;

done:
	if (fd)
		fclose(fd);
	return fail;
}

void usage(void)
{
	fprintf(stderr, "Usage: lomount [-verbose] [OPTIONS] -diskimage FILE -partition NUM [OPTIONS]\n");
	fprintf(stderr, "All OPTIONS are passed through to 'mount'.\n");
	fprintf(stderr, "ex. lomount -t fs-type -diskimage hda.img -partition 1 /mnt\n");
	exit(ERR_USAGE);
}

int main(int argc, char ** argv)
{
	int status;
	int nbr_part;
	struct pentry *parttbl;
	char buf[BUF], argv2[BUF];
	const char * diskimage = NULL;
	int partition = 0;
	unsigned long long sec, num, pnum;
	int i;
	size_t argv2_len = sizeof(argv2);
	int verbose = 0;

	argv2[0] = '\0';

	for (i = 1; i < argc; i ++)
	{
		if (strcmp(argv[i], "-diskimage")==0)
		{
			if (i == argc-1)
				usage();
			i++;
			diskimage = argv[i];
		}
		else if (strcmp(argv[i], "-partition")==0)
		{
			if (i == argc-1)
				usage();
			i++;
			partition = atoi(argv[i]);
		}
		else if (strcmp(argv[i], "-verbose")==0)
		{
			verbose++;
		}
		else
		{
			size_t len = strlen(argv[i]);
			if (len >= argv2_len-1)
				usage();
			strcat(argv2, argv[i]);
			strcat(argv2, " ");
			len -= (len+1);
		}
	}
	if (! diskimage || partition < 0)
		usage();

	nbr_part = load_mbr(diskimage, &parttbl);
	if (check_gpt (parttbl, nbr_part)) {
		free (parttbl);
		nbr_part = load_gpt (diskimage, &parttbl);
	}
	if (nbr_part < 0)
		return ERR_PART_PARSE;
	if (partition == 0)
	{
		printf("Please specify a partition number.  Table is:\n");
		printf("Num      Start -        End  OS Bootable\n");
		for (i = 0; i < nbr_part; i++)
		{
			if (parttbl[i].no_of_sectors_abs != 0)
			{
				printf ("%2d: ", i + 1);
				disp_entry (&parttbl[i]);
			}
		}
		if (partition == 0)
			return 0;
	}
	/* NOTE: need to make sure this always rounds down */
	//sec = total_known_sectors / sizeof_diskimage;
	/* The above doesn't work unless the disk image is completely
	   filled by partitions ... unused space will thrown off the
	   sector size. The calculation assumes the disk image is
	   completely filled, and that the few sectors used to store
	   the partition table/MBR are few enough that the calculated
	   value is off by (larger than) a value less than one. */
	sec = 512; /* TODO: calculate real sector size */
#ifdef DEBUG
	printf("sec: %llu\n", sec);
#endif
	if (partition > nbr_part)
	{
		fprintf(stderr, "Bad partition number\n");
		return ERR_NO_EPART;
	}
	num = parttbl[partition-1].start_sector_abs;
	if (num == 0)
	{
		fprintf(stderr, "Partition %d was not found in %s.\n",
			partition, diskimage);
		return ERR_NO_PART;
	}

	pnum = sec * num;
#ifdef DEBUG
	printf("offset = %llu\n", pnum);
#endif
	snprintf(buf, sizeof(buf), "mount -oloop,offset=%lld %s %s",
		 pnum, diskimage, argv2);
	if (verbose)
		printf("%s\n", buf);

	status = system(buf);
	if (WIFEXITED(status))
		status = WEXITSTATUS(status);
	else
		status = ERR_MOUNT;
	return status;
}
