/*
 * Binary translate privilege-sensitive ops to privileged
 *
 * Copyright (C) 2004 Hewlett-Packard Co.
 *      Dan Magenheimer (dan.magenheimer@hp.com)
 *
 */

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#define ELFSIZE 64
#include <linux/elf.h>

#define MAX_FILSIZ (32*1024*1024)
unsigned long buf[MAX_FILSIZ/sizeof(unsigned long)];

static void
usage (FILE *fp)
{
	fprintf(fp, "Usage: privify elf64filein elf64fileout\n");
}

static void
panic (char *s)
{
	fprintf(stderr, "panic: %s\n",s);
	exit(1);
}

static int
read_file(const char *in_path, char *buf, int maxsize)
{
	ssize_t nread, totread = 0, ssize_inc = 8192;
	int from;

	if ((from = open (in_path, O_RDONLY)) < 0) return -1;
	maxsize -= ssize_inc; // create safety zone
	if (maxsize < 0) panic("input file exceeds max size");
	while ((nread = read(from, buf, ssize_inc)) > 0) {
		if (nread < 0) return -1; // problem
		totread += nread;
		if (nread < ssize_inc) return totread; // done
		buf += ssize_inc;
		if (totread > maxsize) // buffer too small
			panic("file exceeds max size\n");
	}
	return totread;
}

static int
write_file(const char *out_path, char *buf, int size)
{
	int to;

	if ((to = open(out_path, O_WRONLY|O_CREAT|O_EXCL,0644)) < 0)
		return -1;

	if (write(to,buf,size) < 0) return -1;

	return 0;
}

#define IS_ELF(ehdr) ((ehdr).e_ident[EI_MAG0] == ELFMAG0 && \
                      (ehdr).e_ident[EI_MAG1] == ELFMAG1 && \
                      (ehdr).e_ident[EI_MAG2] == ELFMAG2 && \
                      (ehdr).e_ident[EI_MAG3] == ELFMAG3)


static void
privify_elf(char *elfbase)
{
	Elf64_Ehdr *ehdr = (Elf64_Ehdr *)elfbase;
	Elf64_Phdr *phdr;
	Elf64_Shdr *shdr;
	char *elfaddr;
	unsigned long size;
	int h;

	if ( !IS_ELF(*ehdr) )
		panic("Kernel image does not have an ELF header.\n");
	for ( h = 0; h < ehdr->e_phnum; h++ ) {
		phdr = (Elf64_Phdr *)(elfbase +
			ehdr->e_phoff + (h*ehdr->e_phentsize));
		printf("h=%d, phdr=%p,phdr->p_type=%lx",h,phdr,phdr->p_type);
		if ((phdr->p_type != PT_LOAD)) {
			printf("\n");
			continue;
		}
		size = phdr->p_filesz;
		elfaddr = elfbase + phdr->p_offset;
		printf(",elfaddr=%p,size=%d,phdr->p_flags=%lx\n",
			elfaddr,size,phdr->p_flags);
		if (phdr->p_flags & PF_X) privify_memory(elfaddr,size);
    	}
}

int
main(int argc, char **argv)
{
	char *in_path, *out_path;
	int fsize;

	if (argc != 3) {
		usage(stdout);
		exit(1);
	}
	in_path = argv[1];
	out_path = argv[2];
	if ((fsize = read_file(in_path,(char *)buf,MAX_FILSIZ)) < 0) {
		perror("read_file");
		panic("failed");
	}
	privify_elf((char *)buf);
	fflush(stdout);
	if (write_file(out_path,(char *)buf,fsize) < 0) {
		perror("write_file");
		panic("failed");
	}
}
