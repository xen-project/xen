#include <elf.h>
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

#include <xen/elfnote.h>

#define ELFNOTE_NAME(_n_) ((void*)(_n_) + sizeof(*(_n_)))
#define ELFNOTE_DESC(_n_) (ELFNOTE_NAME(_n_) + (((_n_)->n_namesz+3)&~3))
#define ELFNOTE_NEXT(_n_) (ELFNOTE_DESC(_n_) + (((_n_)->n_descsz+3)&~3))

#if defined(__i386__)
typedef Elf32_Ehdr Elf_Ehdr;
typedef Elf32_Nhdr Elf_Nhdr;
typedef Elf32_Half Elf_Half;
typedef Elf32_Word Elf_Word;
#elif defined(__x86_64__)
typedef Elf64_Ehdr Elf_Ehdr;
typedef Elf64_Nhdr Elf_Nhdr;
typedef Elf64_Half Elf_Half;
typedef Elf64_Word Elf_Word;
#else
#error "Unknown architecture"
#endif

static void print_string_note(const char *prefix, Elf_Nhdr *note)
{
	printf("%s: %s\n", prefix, (const char *)ELFNOTE_DESC(note));
}

static void print_numeric_note(const char *prefix,Elf_Nhdr *note)
{
	switch (note->n_descsz)
	{
	case 4:
		printf("%s: %#010" PRIx32 " (4 bytes)\n",
		       prefix, *(uint32_t *)ELFNOTE_DESC(note));
		break;
	case 8:
		printf("%s: %#018" PRIx64 " (8 bytes)\n",
		       prefix, *(uint64_t *)ELFNOTE_DESC(note));
		break;
	default:
		printf("%s: unknown data size %#x\n", prefix, note->n_descsz);
		break;
	}
}

static inline unsigned char ehdr_class(void *image)
{
	Elf_Ehdr *ehdr = image;
	switch (ehdr->e_ident[EI_CLASS])
	{
	case ELFCLASS32:
	case ELFCLASS64:
		return ehdr->e_ident[EI_CLASS];
		break;
	default:
		fprintf(stderr, "Unknown ELF class %d\n",
			ehdr->e_ident[EI_CLASS]);
		exit(1);
	}
}

static inline Elf_Half ehdr_shnum(void *image)
{
	switch (ehdr_class(image))
	{
	case ELFCLASS32:
		return ((Elf32_Ehdr *)image)->e_shnum;
	case ELFCLASS64:
		return ((Elf64_Ehdr *)image)->e_shnum;
	default:
		exit(1);
	}
}

static inline Elf_Word shdr_type(void *image, int shnum)
{
	switch (ehdr_class(image))
	{
	case ELFCLASS32:
	{
		Elf32_Ehdr *ehdr = (Elf32_Ehdr *)image;
		Elf32_Shdr *shdr = (Elf32_Shdr*)(image + ehdr->e_shoff +
						 (shnum*ehdr->e_shentsize));
		return shdr->sh_type;
	}
	case ELFCLASS64:
	{
		Elf64_Ehdr *ehdr = (Elf64_Ehdr *)image;
		Elf64_Shdr *shdr = (Elf64_Shdr*)(image + ehdr->e_shoff +
						 (shnum*ehdr->e_shentsize));
		return shdr->sh_type;
	}
	default:
		exit(1);
	}
}

static inline const char *shdr_name(void *image, int shnum)
{
	const char *shstrtab;

	switch (ehdr_class(image))
	{
	case ELFCLASS32:
	{
		Elf32_Ehdr *ehdr = (Elf32_Ehdr *)image;
		Elf32_Shdr *shdr;
		/* Find the section-header strings table. */
		if ( ehdr->e_shstrndx == SHN_UNDEF )
			return NULL;
		shdr = (Elf32_Shdr *)(image + ehdr->e_shoff +
				      (ehdr->e_shstrndx*ehdr->e_shentsize));
		shstrtab = image + shdr->sh_offset;

		shdr= (Elf32_Shdr*)(image + ehdr->e_shoff +
				    (shnum*ehdr->e_shentsize));
		return &shstrtab[shdr->sh_name];
	}
	case ELFCLASS64:
	{
		Elf64_Ehdr *ehdr = (Elf64_Ehdr *)image;
		Elf64_Shdr *shdr;
		/* Find the section-header strings table. */
		if ( ehdr->e_shstrndx == SHN_UNDEF )
			return NULL;
		shdr = (Elf64_Shdr *)(image + ehdr->e_shoff +
				      (ehdr->e_shstrndx*ehdr->e_shentsize));
		shstrtab = image + shdr->sh_offset;

		shdr= (Elf64_Shdr*)(image + ehdr->e_shoff +
				    (shnum*ehdr->e_shentsize));
		return &shstrtab[shdr->sh_name];
	}
	default:
		exit(1);
	}
}
static inline void *shdr_start(void *image, int shnum)
{
	switch (ehdr_class(image))
	{
	case ELFCLASS32:
	{
		Elf32_Ehdr *ehdr = (Elf32_Ehdr *)image;
		Elf32_Shdr *shdr = (Elf32_Shdr*)(image + ehdr->e_shoff +
						 (shnum*ehdr->e_shentsize));
		return image + shdr->sh_offset;
	}
	case ELFCLASS64:
	{
		Elf64_Ehdr *ehdr = (Elf64_Ehdr *)image;
		Elf64_Shdr *shdr = (Elf64_Shdr*)(image + ehdr->e_shoff +
						 (shnum*ehdr->e_shentsize));
		return image + shdr->sh_offset;
	}
	default:
		exit(1);
	}
}

static inline void *shdr_end(void *image, int shnum)
{
	switch (ehdr_class(image))
	{
	case ELFCLASS32:
	{
		Elf32_Ehdr *ehdr = (Elf32_Ehdr *)image;
		Elf32_Shdr *shdr = (Elf32_Shdr*)(image + ehdr->e_shoff +
						 (shnum*ehdr->e_shentsize));
		return image + shdr->sh_offset + shdr->sh_size;
	}
	case ELFCLASS64:
	{
		Elf64_Ehdr *ehdr = (Elf64_Ehdr *)image;
		Elf64_Shdr *shdr = (Elf64_Shdr*)(image + ehdr->e_shoff +
						 (shnum*ehdr->e_shentsize));
		return image + shdr->sh_offset + shdr->sh_size;
	}
	default:
		exit(1);
	}
}

int main(int argc, char **argv)
{
	const char *f;
	int fd,h;
	void *image;
	struct stat st;
	Elf_Ehdr *ehdr;
	Elf_Nhdr *note;

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

	ehdr = image;
	if (ehdr->e_ident[EI_MAG0] != ELFMAG0 ||
	    ehdr->e_ident[EI_MAG1] != ELFMAG1 ||
	    ehdr->e_ident[EI_MAG2] != ELFMAG2 ||
	    ehdr->e_ident[EI_MAG3] != ELFMAG3)
	{
		fprintf(stderr, "File %s is not an ELF image\n", f);
		return 1;
	}

	for ( h=0; h < ehdr_shnum(image); h++)
	{
		if (shdr_type(image,h) != SHT_NOTE)
			continue;
		for (note = (Elf_Nhdr*)shdr_start(image,h);
		     note < (Elf_Nhdr*)shdr_end(image,h);
		     note = (Elf_Nhdr*)(ELFNOTE_NEXT(note)))
		{
			switch(note->n_type)
			{
			case XEN_ELFNOTE_INFO:
				print_string_note("INFO", note);
				break;
			case XEN_ELFNOTE_ENTRY:
				print_numeric_note("ENTRY", note);
				break;
			case XEN_ELFNOTE_HYPERCALL_PAGE:
				print_numeric_note("HYPERCALL_PAGE", note);
				break;
			case XEN_ELFNOTE_VIRT_BASE:
				print_numeric_note("VIRT_BASE", note);
				break;
			case XEN_ELFNOTE_PADDR_OFFSET:
				print_numeric_note("PADDR_OFFSET", note);
				break;
			case XEN_ELFNOTE_XEN_VERSION:
				print_string_note("XEN_VERSION", note);
				break;
			case XEN_ELFNOTE_GUEST_OS:
				print_string_note("GUEST_OS", note);
				break;
			case XEN_ELFNOTE_GUEST_VERSION:
				print_string_note("GUEST_VERSION", note);
				break;
			case XEN_ELFNOTE_LOADER:
				print_string_note("LOADER", note);
				break;
			case XEN_ELFNOTE_PAE_MODE:
				print_string_note("PAE_MODE", note);
				break;
			case XEN_ELFNOTE_FEATURES:
				print_string_note("FEATURES", note);
				break;
			default:
				printf("unknown note type %#x\n", note->n_type);
				break;
			}
		}
	}

	for ( h=0; h < ehdr_shnum(image); h++)
	{
		const char *name = shdr_name(image,h);

		if ( name == NULL )
			continue;
		if ( strcmp(name, "__xen_guest") != 0 )
			continue;

		printf("__xen_guest: %s\n", (const char *)shdr_start(image, h));
		break;
	}

	return 0;
}


