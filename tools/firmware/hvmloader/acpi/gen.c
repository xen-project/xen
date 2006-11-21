/*
 * Copyright (c) 2004, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 *
 */
#include "acpi2_0.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define USAGE	"Usage: acpi_gen filename \n"				\
		"       generage acpitable and write to the binary \n"	\
		"       filename - the binary name\n"

#define ACPI_TABLE_SIZE (8*1024)

int main(int argc, char **argv)
{
	char *filename;
	char  buf[ACPI_TABLE_SIZE] = { 0 };
	FILE *f;

	if (argc < 2) {
		fprintf(stderr,"%s",USAGE);
		exit(1);
	}

	filename = argv[1];
		
	if ((f = fopen(filename, "w+")) == NULL) {
		fprintf(stderr,"Can not open %s", filename);
		exit(1);
	}

	AcpiBuildTable((uint8_t *)buf);

	if (fwrite(buf, ACPI_TABLE_SIZE, 1, f) < 1) {
		fprintf(stderr,"Can not write to %s\n", filename);
		exit(1);
	}

	return 0;
}
