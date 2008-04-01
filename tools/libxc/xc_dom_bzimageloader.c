/*
 * Xen domain builder -- bzImage bits
 *
 * Parse and load bzImage kernel images.
 *
 * This relies on version 2.08 of the boot protocol, which contains an
 * ELF file embedded in the bzImage.  The loader extracts this ELF
 * image and passes it off to the standard ELF loader.
 *
 * This code is licenced under the GPL.
 * written 2006 by Gerd Hoffmann <kraxel@suse.de>.
 * written 2007 by Jeremy Fitzhardinge <jeremy@xensource.com>
 * written 2008 by Ian Campbell <ijc@hellion.org.uk>
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

#include "xg_private.h"
#include "xc_dom.h"

struct setup_header {
	uint8_t		_pad0[0x1f1];		/* skip uninteresting stuff */
	uint8_t		setup_sects;
	uint16_t	root_flags;
	uint32_t	syssize;
	uint16_t	ram_size;
	uint16_t	vid_mode;
	uint16_t	root_dev;
	uint16_t	boot_flag;
	uint16_t	jump;
	uint32_t	header;
#define HDR_MAGIC		"HdrS"
#define HDR_MAGIC_SZ	4
	uint16_t	version;
#define VERSION(h,l)	(((h)<<8) | (l))
	uint32_t	realmode_swtch;
	uint16_t	start_sys;
	uint16_t	kernel_version;
	uint8_t		type_of_loader;
	uint8_t		loadflags;
	uint16_t	setup_move_size;
	uint32_t	code32_start;
	uint32_t	ramdisk_image;
	uint32_t	ramdisk_size;
	uint32_t	bootsect_kludge;
	uint16_t	heap_end_ptr;
	uint16_t	_pad1;
	uint32_t	cmd_line_ptr;
	uint32_t	initrd_addr_max;
	uint32_t	kernel_alignment;
	uint8_t		relocatable_kernel;
	uint8_t		_pad2[3];
	uint32_t	cmdline_size;
	uint32_t	hardware_subarch;
	uint64_t	hardware_subarch_data;
	uint32_t	payload_offset;
	uint32_t	payload_length;
} __attribute__((packed));

extern struct xc_dom_loader elf_loader;

static unsigned int payload_offset(struct setup_header *hdr)
{
    unsigned int off;

    off = (hdr->setup_sects + 1) * 512;
    off += hdr->payload_offset;
    return off;
}

static int check_bzimage_kernel(struct xc_dom_image *dom, int verbose)
{
    struct setup_header *hdr;

    if ( dom->kernel_blob == NULL )
    {
        if ( verbose )
            xc_dom_panic(XC_INTERNAL_ERROR, "%s: no kernel image loaded\n",
                         __FUNCTION__);
        return -EINVAL;
    }
    if ( dom->kernel_size < sizeof(struct setup_header) )
    {
        if ( verbose )
            xc_dom_panic(XC_INTERNAL_ERROR, "%s: kernel image too small\n",
                         __FUNCTION__);
        return -EINVAL;
    }

    hdr = dom->kernel_blob;

    if ( memcmp(&hdr->header, HDR_MAGIC, HDR_MAGIC_SZ) != 0 )
    {
        if ( verbose )
            xc_dom_panic(XC_INVALID_KERNEL, "%s: kernel is not a bzImage\n",
                         __FUNCTION__);
        return -EINVAL;
    }

    if ( hdr->version < VERSION(2,8) )
    {
        if ( verbose )
            xc_dom_panic(XC_INVALID_KERNEL, "%s: boot protocol too old (%04x)\n",
                         __FUNCTION__, hdr->version);
        return -EINVAL;
    }

    dom->kernel_blob = dom->kernel_blob + payload_offset(hdr);
    dom->kernel_size = hdr->payload_length;

    if ( xc_dom_try_gunzip(dom, &dom->kernel_blob, &dom->kernel_size) == -1 )
    {
        if ( verbose )
            xc_dom_panic(XC_INVALID_KERNEL, "%s: unable to decompress kernel\n",
                         __FUNCTION__);
        return -EINVAL;
    }

    return elf_loader.probe(dom);
}

static int xc_dom_probe_bzimage_kernel(struct xc_dom_image *dom)
{
    return check_bzimage_kernel(dom, 0);
}

static int xc_dom_parse_bzimage_kernel(struct xc_dom_image *dom)
{
    return elf_loader.parser(dom);
}

static int xc_dom_load_bzimage_kernel(struct xc_dom_image *dom)
{
    return elf_loader.loader(dom);
}

static struct xc_dom_loader bzimage_loader = {
    .name = "Linux bzImage",
    .probe = xc_dom_probe_bzimage_kernel,
    .parser = xc_dom_parse_bzimage_kernel,
    .loader = xc_dom_load_bzimage_kernel,
};

static void __init register_loader(void)
{
    xc_dom_register_loader(&bzimage_loader);
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
