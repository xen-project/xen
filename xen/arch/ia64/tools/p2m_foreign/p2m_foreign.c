/*
 * Foreign p2m exposure test.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Copyright (c) 2007 Isaku Yamahata <yamahata at valinux co jp>
 *                    VA Linux Systems Japan K.K.
 *
 */

#include <sys/mman.h>
#include <err.h>
#include <errno.h>
#include <assert.h>

#include <xc_private.h>
#include <xenctrl.h>
#include <xenguest.h>
#include <xc_efi.h>
#include <ia64/xc_ia64.h>

#if 1
# define printd(fmt, args...)	printf(fmt, ##args)
#else
# define printd(fmt, args...)	((void)0)
#endif

/* xc_memory_op() in xc_private.c doesn't support translate_gpfn_list */
static int
__xc_memory_op(int xc_handle, int cmd, void *arg)
{
	DECLARE_HYPERCALL;
	struct xen_translate_gpfn_list* translate = arg;

	xen_ulong_t* gpfns;
	xen_ulong_t* mfns;
	size_t len;

	long ret = -EINVAL;

	hypercall.op     = __HYPERVISOR_memory_op;
	hypercall.arg[0] = (unsigned long)cmd;
	hypercall.arg[1] = (unsigned long)arg;

	assert(cmd == XENMEM_translate_gpfn_list);

	get_xen_guest_handle(gpfns, translate->gpfn_list);
	get_xen_guest_handle(mfns, translate->mfn_list);
	len = sizeof(gpfns[0]) * translate->nr_gpfns;
	if (lock_pages(translate, sizeof(*translate)) ||
	    lock_pages(gpfns, len) ||
	    lock_pages(mfns, len))
		goto out;

	ret = do_xen_hypercall(xc_handle, &hypercall);

out:
	unlock_pages(mfns, len);
	unlock_pages(gpfns, len);
	unlock_pages(translate, sizeof(*translate));

	return ret;
}

int
xc_translate_gpfn_list(int xc_handle, uint32_t domid, xen_ulong_t nr_gpfns,
		       xen_ulong_t* gpfns, xen_ulong_t* mfns)
{
	struct xen_translate_gpfn_list translate = {
		.domid = domid,
		.nr_gpfns = nr_gpfns,
	};
	set_xen_guest_handle(translate.gpfn_list, gpfns);
	set_xen_guest_handle(translate.mfn_list, mfns);

	return __xc_memory_op(xc_handle,
			      XENMEM_translate_gpfn_list, &translate);
}

int
main(int argc, char** argv)
{
	uint32_t domid;
	int xc_handle;

	xc_dominfo_t info;
	shared_info_t* shinfo;

	unsigned long map_size;
	xen_ia64_memmap_info_t* memmap_info;
	struct xen_ia64_p2m_table p2m_table;

	char* p;
	char* start;
	char* end;
	xen_ulong_t nr_gpfns;

	xen_ulong_t* gpfns;
	xen_ulong_t* mfns;

	unsigned long i;

	if (argc != 2)
		errx(EXIT_FAILURE, "usage: %s <domid>", argv[0]);
	domid = atol(argv[1]);

	printd("xc_interface_open()\n");
	xc_handle = xc_interface_open();
	if (xc_handle < 0)
		errx(EXIT_FAILURE, "can't open control interface");

	printd("xc_domain_getinfo\n");
	if (xc_domain_getinfo(xc_handle, domid, 1, &info) != 1)
		errx(EXIT_FAILURE, "Could not get info for domain");


	printd("shared info\n");
	shinfo = xc_map_foreign_range(xc_handle, domid, PAGE_SIZE,
				      PROT_READ, info.shared_info_frame);
	if (shinfo == NULL)
		errx(EXIT_FAILURE, "can't map shared info");

	printd("memmap_info\n");
	map_size = PAGE_SIZE * shinfo->arch.memmap_info_num_pages;
	memmap_info = xc_map_foreign_range(xc_handle, info.domid,
					   map_size, PROT_READ,
					   shinfo->arch.memmap_info_pfn);
	if (memmap_info == NULL)
		errx(EXIT_FAILURE, "can't map memmap_info");

#if 1
	start = (char*)&memmap_info->memdesc;
	end = start + memmap_info->efi_memmap_size;
	i = 0;
	for (p = start; p < end; p += memmap_info->efi_memdesc_size) {
		efi_memory_desc_t* md = (efi_memory_desc_t*)p;
		printd("%ld [0x%lx, 0x%lx) 0x%lx pages\n",
		       i, md->phys_addr,
		       md->phys_addr + (md->num_pages << EFI_PAGE_SHIFT),
		       md->num_pages >> (PAGE_SHIFT - EFI_PAGE_SHIFT));
		i++;
	}
#endif


	printd("p2m map\n");
	if (xc_ia64_p2m_map(&p2m_table, xc_handle, domid, memmap_info, 0) < 0)
		errx(EXIT_FAILURE, "can't map foreign p2m table");
	printd("p2m map done\n");

	start = (char*)&memmap_info->memdesc;
	end = start + memmap_info->efi_memmap_size;
	nr_gpfns = 0;
	i = 0;
	for (p = start; p < end; p += memmap_info->efi_memdesc_size) {
		efi_memory_desc_t* md = (efi_memory_desc_t*)p;
		if ( md->type != EFI_CONVENTIONAL_MEMORY ||
		     md->attribute != EFI_MEMORY_WB ||
		     md->num_pages == 0 )
			continue;

		printd("%ld [0x%lx, 0x%lx) 0x%lx pages\n",
		       i, md->phys_addr,
		       md->phys_addr + (md->num_pages << EFI_PAGE_SHIFT),
		       md->num_pages >> (PAGE_SHIFT - EFI_PAGE_SHIFT));
		nr_gpfns += md->num_pages >> (PAGE_SHIFT - EFI_PAGE_SHIFT);
		i++;
	}

	printd("total 0x%lx gpfns\n", nr_gpfns);
	gpfns = malloc(sizeof(gpfns[0]) * nr_gpfns);
	mfns = malloc(sizeof(mfns[0]) * nr_gpfns);
	if (gpfns == NULL || mfns == NULL)
		err(EXIT_FAILURE, "can't allocate memory for gpfns/mfns");

	i = 0;
	for (p = start; p < end; p += memmap_info->efi_memdesc_size) {
		efi_memory_desc_t* md = (efi_memory_desc_t*)p;
		unsigned long j;
		if ( md->type != EFI_CONVENTIONAL_MEMORY ||
		     md->attribute != EFI_MEMORY_WB ||
		     md->num_pages == 0 )
			continue;

		for (j = 0;
		     j < md->num_pages >> (PAGE_SHIFT - EFI_PAGE_SHIFT);
		     j++) {
			gpfns[i] = (md->phys_addr >> PAGE_SHIFT) + j;
			i++;
		}
	}
	for (i = 0; i < nr_gpfns; i++)
		mfns[i] = INVALID_MFN;

	printd("issue translate gpfn list hypercall. "
	       "this may take a while\n");
	if (xc_translate_gpfn_list(xc_handle,
				   domid, nr_gpfns, gpfns, mfns) < 0)
		err(EXIT_FAILURE, "translate gpfn list hypercall failure");
	printd("translate gpfn list hypercall done\n");

	printd("checking p2m table\n");
	for (i = 0; i < nr_gpfns; i++) {
		unsigned long mfn_by_translated = mfns[i];
		unsigned long mfn_by_p2m =
			xc_ia64_p2m_mfn(&p2m_table, gpfns[i]);
		if (mfn_by_translated != mfn_by_p2m &&
		    !(mfn_by_translated == 0 && mfn_by_p2m == INVALID_MFN)) {
			printf("ERROR! i 0x%lx gpfn "
			       "0x%lx trnslated 0x%lx p2m 0x%lx\n",
			       i, gpfns[i], mfn_by_translated, mfn_by_p2m);
		}
	}
	printd("checking p2m table done\n");

	xc_ia64_p2m_unmap(&p2m_table);
	munmap(memmap_info, map_size);
	munmap(shinfo, PAGE_SIZE);

	return EXIT_SUCCESS;
}
