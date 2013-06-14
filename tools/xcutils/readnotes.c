#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include <xg_private.h>
#include <xc_dom.h> /* gunzip bits */

#include <xen/libelf/libelf.h>

static xc_interface *xch;

/* According to the implemation of xc_dom_probe_bzimage_kernel() function */
/* We add support of bzImage kernel */
/* Copied from tools/libxc/xc_doom_bzImageloader.c */
struct setup_header {
	uint8_t  _pad0[0x1f1];  /* skip uninteresting stuff */
	uint8_t  setup_sects;
	uint16_t root_flags;
	uint32_t syssize;
	uint16_t ram_size;
	uint16_t vid_mode;
	uint16_t root_dev;
	uint16_t boot_flag;
	uint16_t jump;
	uint32_t header;
#define HDR_MAGIC  "HdrS"
#define HDR_MAGIC_SZ 4
	uint16_t version;
#define VERSION(h,l) (((h)<<8) | (l))
	uint32_t realmode_swtch;
	uint16_t start_sys;
	uint16_t kernel_version;
	uint8_t  type_of_loader;
	uint8_t  loadflags;
	uint16_t setup_move_size;
	uint32_t code32_start;
	uint32_t ramdisk_image;
	uint32_t ramdisk_size;
	uint32_t bootsect_kludge;
	uint16_t heap_end_ptr;
	uint16_t _pad1;
	uint32_t cmd_line_ptr;
	uint32_t initrd_addr_max;
	uint32_t kernel_alignment;
	uint8_t  relocatable_kernel;
	uint8_t  _pad2[3];
	uint32_t cmdline_size;
	uint32_t hardware_subarch;
	uint64_t hardware_subarch_data;
	uint32_t payload_offset;
	uint32_t payload_length;
} __attribute__((packed));

static void print_string_note(const char *prefix, struct elf_binary *elf,
			      ELF_HANDLE_DECL(elf_note) note)
{
	printf("%s: %s\n", prefix, elf_strfmt(elf, elf_note_desc(elf, note)));
}

static void print_numeric_note(const char *prefix, struct elf_binary *elf,
			       ELF_HANDLE_DECL(elf_note) note)
{
	uint64_t value = elf_note_numeric(elf, note);
	unsigned descsz = elf_uval(elf, note, descsz);

	printf("%s: %#*" PRIx64 " (%d bytes)\n",
	       prefix, 2+2*descsz, value, descsz);
}

static void print_l1_mfn_valid_note(const char *prefix, struct elf_binary *elf,
				    ELF_HANDLE_DECL(elf_note) note)
{
	unsigned descsz = elf_uval(elf, note, descsz);
	elf_ptrval desc = elf_note_desc(elf, note);

	/* XXX should be able to cope with a list of values. */
	switch ( descsz / 2 )
	{
	case 8:
		printf("%s: mask=%#"PRIx64" value=%#"PRIx64"\n", prefix,
		       elf_access_unsigned(elf, desc, 0, 8),
		       elf_access_unsigned(elf, desc, 8, 8));
		break;
	case 4:
		printf("%s: mask=%#"PRIx32" value=%#"PRIx32"\n", prefix,
		       (uint32_t)elf_access_unsigned(elf, desc, 0, 4),
		       (uint32_t)elf_access_unsigned(elf, desc, 4, 4));
		break;
	}

}

static unsigned print_notes(struct elf_binary *elf, ELF_HANDLE_DECL(elf_note) start, ELF_HANDLE_DECL(elf_note) end)
{
	ELF_HANDLE_DECL(elf_note) note;
	unsigned notes_found = 0;
	const char *this_note_name;

	for ( note = start; ELF_HANDLE_PTRVAL(note) < ELF_HANDLE_PTRVAL(end); note = elf_note_next(elf, note) )
	{
		this_note_name = elf_note_name(elf, note);
		if (NULL == this_note_name)
			continue;
		if (0 != strcmp(this_note_name, "Xen"))
			continue;

		notes_found++;

		switch(elf_uval(elf, note, type))
		{
		case XEN_ELFNOTE_INFO:
			print_string_note("INFO", elf , note);
			break;
		case XEN_ELFNOTE_ENTRY:
			print_numeric_note("ENTRY", elf , note);
			break;
		case XEN_ELFNOTE_HYPERCALL_PAGE:
			print_numeric_note("HYPERCALL_PAGE", elf , note);
			break;
		case XEN_ELFNOTE_VIRT_BASE:
			print_numeric_note("VIRT_BASE", elf , note);
			break;
		case XEN_ELFNOTE_PADDR_OFFSET:
			print_numeric_note("PADDR_OFFSET", elf , note);
			break;
		case XEN_ELFNOTE_XEN_VERSION:
			print_string_note("XEN_VERSION", elf , note);
			break;
		case XEN_ELFNOTE_GUEST_OS:
			print_string_note("GUEST_OS", elf , note);
			break;
		case XEN_ELFNOTE_GUEST_VERSION:
			print_string_note("GUEST_VERSION", elf , note);
			break;
		case XEN_ELFNOTE_LOADER:
			print_string_note("LOADER", elf , note);
			break;
		case XEN_ELFNOTE_PAE_MODE:
			print_string_note("PAE_MODE", elf , note);
			break;
		case XEN_ELFNOTE_FEATURES:
			print_string_note("FEATURES", elf , note);
			break;
		case XEN_ELFNOTE_HV_START_LOW:
			print_numeric_note("HV_START_LOW", elf , note);
			break;
		case XEN_ELFNOTE_SUSPEND_CANCEL:
			print_numeric_note("SUSPEND_CANCEL", elf, note);
			break;
		case XEN_ELFNOTE_L1_MFN_VALID:
			print_l1_mfn_valid_note("L1_MFN_VALID", elf , note);
			break;
		default:
			printf("unknown note type %#x\n",
			       (unsigned)elf_uval(elf, note, type));
			break;
		}
	}
	return notes_found;
}

int main(int argc, char **argv)
{
	const char *f;
	int fd;
	unsigned h,size,usize,count;
	void *image,*tmp;
	struct stat st;
	struct elf_binary elf;
	ELF_HANDLE_DECL(elf_shdr) shdr;
	unsigned notes_found = 0;

	struct setup_header *hdr;
	uint64_t payload_offset, payload_length;

	if (argc != 2)
	{
		fprintf(stderr, "Usage: readnotes <elfimage>\n");
		return 1;
	}
	f = argv[1];

        xch = xc_interface_open(0,0,XC_OPENFLAG_DUMMY);

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
	
	/* Check the magic of bzImage kernel */
	hdr = (struct setup_header *)image;
	if ( memcmp(&hdr->header, HDR_MAGIC, HDR_MAGIC_SZ) == 0 )
	{
		if ( hdr->version < VERSION(2,8) )
		{
			printf("%s: boot protocol too old (%04x)", __FUNCTION__, hdr->version);
			return 1;
		}

		/* upcast to 64 bits to avoid overflow */
		/* setup_sects is u8 and so cannot overflow */
		payload_offset = (hdr->setup_sects + 1) * 512;
		payload_offset += hdr->payload_offset;
		payload_length = hdr->payload_length;
		
		if ( payload_offset >= st.st_size )
		{
			printf("%s: payload offset overflow", __FUNCTION__);
			return 1;
		}
		if ( (payload_offset + payload_length) > st.st_size )
		{
			printf("%s: payload length overflow", __FUNCTION__);
			return 1;
		}

		image = image + payload_offset;
		size = payload_length;
	} else {
		size = st.st_size;
	}

	usize = xc_dom_check_gzip(xch, image, size);
	if (usize)
	{
		tmp = malloc(usize);
		xc_dom_do_gunzip(xch, image, size, tmp, usize);
		image = tmp;
		size = usize;
	}

	if (0 != elf_init(&elf, image, size))
	{
		fprintf(stderr, "File %s is not an ELF image\n", f);
		return 1;
	}
	xc_elf_set_logfile(xch, &elf, 0);

	count = elf_phdr_count(&elf);
	for ( h=0; h < count; h++)
	{
		ELF_HANDLE_DECL(elf_phdr) phdr;
		phdr = elf_phdr_by_index(&elf, h);
		if (elf_uval(&elf, phdr, p_type) != PT_NOTE)
			continue;

		/* Some versions of binutils do not correctly set
		 * p_offset for note segments.
		 */
		if (elf_uval(&elf, phdr, p_offset) == 0)
			continue;

		notes_found = print_notes(&elf,
					  ELF_MAKE_HANDLE(elf_note, elf_segment_start(&elf, phdr)),
					  ELF_MAKE_HANDLE(elf_note, elf_segment_end(&elf, phdr)));
	}

	if ( notes_found == 0 )
	{
		count = elf_shdr_count(&elf);
		for ( h=0; h < count; h++)
		{
			ELF_HANDLE_DECL(elf_shdr) shdr;
			shdr = elf_shdr_by_index(&elf, h);
			if (elf_uval(&elf, shdr, sh_type) != SHT_NOTE)
				continue;
			notes_found = print_notes(&elf,
						  ELF_MAKE_HANDLE(elf_note, elf_section_start(&elf, shdr)),
						  ELF_MAKE_HANDLE(elf_note, elf_section_end(&elf, shdr)));
			if ( notes_found )
				fprintf(stderr, "using notes from SHT_NOTE section\n");

		}
	}

	shdr = elf_shdr_by_name(&elf, "__xen_guest");
	if (ELF_HANDLE_VALID(shdr))
		printf("__xen_guest: %s\n",
                       elf_strfmt(&elf, elf_section_start(&elf, shdr)));

	if (elf_check_broken(&elf))
		printf("warning: broken ELF: %s\n", elf_check_broken(&elf));

	return 0;
}


