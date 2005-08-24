/* Test introduction of domain 0 */
#include <linux/ioctl.h>
#include <sys/ioctl.h>
#include "xs.h"
#include "utils.h"
#include <xenctrl.h>
#include <xen/linux/privcmd.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>

int main()
{
	int h, local = 0, kernel = 0;
	long err;
	void *page;

	h = xc_interface_open();
	if (h < 0)
		barf_perror("Failed to open xc");

	if (xc_evtchn_bind_interdomain(h, DOMID_SELF, 0, &local, &kernel) != 0)
		barf_perror("Failed to bind interdomain");

	printf("Got ports %i & %i\n", local, kernel);

	err = ioctl(h, IOCTL_PRIVCMD_INITDOMAIN_STORE, kernel);
	if (err < 0)
		barf_perror("Failed to initialize store");
	printf("Got mfn %li\n", err);

	page = xc_map_foreign_range(h, 0, getpagesize(), PROT_READ|PROT_WRITE,
				    err);
	if (!page)
		barf_perror("Failed to map page %li", err);
	printf("Mapped page at %p\n", page);
	printf("Page says %s\n", (char *)page);
	munmap(page, getpagesize());
	printf("unmapped\n");
	
	return 0;
}
	
