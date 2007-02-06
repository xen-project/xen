#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include <xg_private.h>
#include <xc_dom.h> /* gunzip bits */

#include <xen/libelf.h>

static void print_string_note(const char *prefix, struct elf_binary *elf,
			      const elf_note *note)
{
	printf("%s: %s\n", prefix, (char*)elf_note_desc(elf, note));
}

static void print_numeric_note(const char *prefix, struct elf_binary *elf,
			       const elf_note *note)
{
	uint64_t value = elf_note_numeric(elf, note);
	int descsz = elf_uval(elf, note, descsz);

	printf("%s: %#*" PRIx64 " (%d bytes)\n",
	       prefix, 2+2*descsz, value, descsz);
}

int main(int argc, char **argv)
{
	const char *f;
	int fd,h,size,usize,count;
	void *image,*tmp;
	struct stat st;
	struct elf_binary elf;
	const elf_shdr *shdr;
	const elf_note *note, *end;

	if (argc != 2)
	{
		fprintf(stderr, "Usage: readnotes <elfimage>\n");
		return 1;
	}
	f = argv[1];

	fd = open(f, O_RDONLY);
	if (fd == -1)
	{
		fprintf(stderr, "Unable to open %s: %s\n", f, strerror(errno));
		return 1;
	}
	if (fstat(fd, &st) == -1)
	{
		fprintf(stderr, "Unable to determine size of %s: %s\n",
			f, strerror(errno));
		return 1;
	}

	image = mmap(0, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (image == MAP_FAILED)
	{
		fprintf(stderr, "Unable to map %s: %s\n", f, strerror(errno));
		return 1;
	}
	size = st.st_size;

	usize = xc_dom_check_gzip(image, st.st_size);
	if (usize)
	{
		tmp = malloc(usize);
		xc_dom_do_gunzip(image, st.st_size, tmp, usize);
		image = tmp;
		size = usize;
	}

	if (0 != elf_init(&elf, image, size))
	{
		fprintf(stderr, "File %s is not an ELF image\n", f);
		return 1;
	}
	elf_set_logfile(&elf, stderr, 0);

	count = elf_shdr_count(&elf);
	for ( h=0; h < count; h++)
	{
		shdr = elf_shdr_by_index(&elf, h);
		if (elf_uval(&elf, shdr, sh_type) != SHT_NOTE)
			continue;
		end = elf_section_end(&elf, shdr);
		for (note = elf_section_start(&elf, shdr);
		     note < end;
		     note = elf_note_next(&elf, note))
		{
			if (0 != strcmp(elf_note_name(&elf, note), "Xen"))
				continue;
			switch(elf_uval(&elf, note, type))
			{
			case XEN_ELFNOTE_INFO:
				print_string_note("INFO", &elf , note);
				break;
			case XEN_ELFNOTE_ENTRY:
				print_numeric_note("ENTRY", &elf , note);
				break;
			case XEN_ELFNOTE_HYPERCALL_PAGE:
				print_numeric_note("HYPERCALL_PAGE", &elf , note);
				break;
			case XEN_ELFNOTE_VIRT_BASE:
				print_numeric_note("VIRT_BASE", &elf , note);
				break;
			case XEN_ELFNOTE_PADDR_OFFSET:
				print_numeric_note("PADDR_OFFSET", &elf , note);
				break;
			case XEN_ELFNOTE_XEN_VERSION:
				print_string_note("XEN_VERSION", &elf , note);
				break;
			case XEN_ELFNOTE_GUEST_OS:
				print_string_note("GUEST_OS", &elf , note);
				break;
			case XEN_ELFNOTE_GUEST_VERSION:
				print_string_note("GUEST_VERSION", &elf , note);
				break;
			case XEN_ELFNOTE_LOADER:
				print_string_note("LOADER", &elf , note);
				break;
			case XEN_ELFNOTE_PAE_MODE:
				print_string_note("PAE_MODE", &elf , note);
				break;
			case XEN_ELFNOTE_FEATURES:
				print_string_note("FEATURES", &elf , note);
				break;
			default:
				printf("unknown note type %#x\n",
				       (int)elf_uval(&elf, note, type));
				break;
			}
		}
	}

	shdr = elf_shdr_by_name(&elf, "__xen_guest");
	if (shdr)
		printf("__xen_guest: %s\n", (char*)elf_section_start(&elf, shdr));

	return 0;
}


