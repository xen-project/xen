/*
 * drivers/xen/core/machine_kexec.c 
 * handle transition of Linux booting another kernel
 */

#include <linux/kexec.h>
#include <xen/interface/kexec.h>
#include <linux/mm.h>
#include <linux/bootmem.h>

extern void machine_kexec_setup_load_arg(xen_kexec_image_t *xki, 
					 struct kimage *image);

int xen_max_nr_phys_cpus;
struct resource xen_hypervisor_res;
struct resource *xen_phys_cpus;

void xen_machine_kexec_setup_resources(void)
{
	xen_kexec_range_t range;
	struct resource *res;
	int k = 0;

	if (!is_initial_xendomain())
		return;

	/* determine maximum number of physical cpus */

	while (1) {
		memset(&range, 0, sizeof(range));
		range.range = KEXEC_RANGE_MA_CPU;
		range.nr = k;

		if(HYPERVISOR_kexec_op(KEXEC_CMD_kexec_get_range, &range))
			break;

		k++;
	}

	if (k == 0)
		return;

	xen_max_nr_phys_cpus = k;

	/* allocate xen_phys_cpus */

	xen_phys_cpus = alloc_bootmem_low(k * sizeof(struct resource));
	BUG_ON(xen_phys_cpus == NULL);

	/* fill in xen_phys_cpus with per-cpu crash note information */

	for (k = 0; k < xen_max_nr_phys_cpus; k++) {
		memset(&range, 0, sizeof(range));
		range.range = KEXEC_RANGE_MA_CPU;
		range.nr = k;

		if (HYPERVISOR_kexec_op(KEXEC_CMD_kexec_get_range, &range))
			goto err;

		res = xen_phys_cpus + k;

		memset(res, 0, sizeof(*res));
		res->name = "Crash note";
		res->start = range.start;
		res->end = range.start + range.size - 1;
		res->flags = IORESOURCE_BUSY | IORESOURCE_MEM;
	}

	/* fill in xen_hypervisor_res with hypervisor machine address range */

	memset(&range, 0, sizeof(range));
	range.range = KEXEC_RANGE_MA_XEN;

	if (HYPERVISOR_kexec_op(KEXEC_CMD_kexec_get_range, &range))
		goto err;

	xen_hypervisor_res.name = "Hypervisor code and data";
	xen_hypervisor_res.start = range.start;
	xen_hypervisor_res.end = range.start + range.size - 1;
	xen_hypervisor_res.flags = IORESOURCE_BUSY | IORESOURCE_MEM;

	/* fill in crashk_res if range is reserved by hypervisor */

	memset(&range, 0, sizeof(range));
	range.range = KEXEC_RANGE_MA_CRASH;

	if (HYPERVISOR_kexec_op(KEXEC_CMD_kexec_get_range, &range))
		return;

	if (range.size) {
		crashk_res.start = range.start;
		crashk_res.end = range.start + range.size - 1;
	}

	return;

 err:
	/*
	 * It isn't possible to free xen_phys_cpus this early in the
	 * boot. Failure at this stage is unexpected and the amount of
	 * memory is small therefore we tolerate the potential leak.
         */
	xen_max_nr_phys_cpus = 0;
	return;
}

void xen_machine_kexec_register_resources(struct resource *res)
{
	int k;

	request_resource(res, &xen_hypervisor_res);

	for (k = 0; k < xen_max_nr_phys_cpus; k++)
		request_resource(&xen_hypervisor_res, xen_phys_cpus + k);

}

static void setup_load_arg(xen_kexec_image_t *xki, struct kimage *image)
{
	machine_kexec_setup_load_arg(xki, image);

	xki->indirection_page = image->head;
	xki->start_address = image->start;
}

/*
 * Load the image into xen so xen can kdump itself
 * This might have been done in prepare, but prepare
 * is currently called too early. It might make sense
 * to move prepare, but for now, just add an extra hook.
 */
int xen_machine_kexec_load(struct kimage *image)
{
	xen_kexec_load_t xkl;

	memset(&xkl, 0, sizeof(xkl));
	xkl.type = image->type;
	setup_load_arg(&xkl.image, image);
	return HYPERVISOR_kexec_op(KEXEC_CMD_kexec_load, &xkl);
}

/*
 * Unload the image that was stored by machine_kexec_load()
 * This might have been done in machine_kexec_cleanup() but it
 * is called too late, and its possible xen could try and kdump
 * using resources that have been freed.
 */
void xen_machine_kexec_unload(struct kimage *image)
{
	xen_kexec_load_t xkl;

	memset(&xkl, 0, sizeof(xkl));
	xkl.type = image->type;
	HYPERVISOR_kexec_op(KEXEC_CMD_kexec_unload, &xkl);
}

/*
 * Do not allocate memory (or fail in any way) in machine_kexec().
 * We are past the point of no return, committed to rebooting now.
 *
 * This has the hypervisor move to the prefered reboot CPU, 
 * stop all CPUs and kexec. That is it combines machine_shutdown()
 * and machine_kexec() in Linux kexec terms.
 */
NORET_TYPE void machine_kexec(struct kimage *image)
{
	xen_kexec_exec_t xke;

	memset(&xke, 0, sizeof(xke));
	xke.type = image->type;
	HYPERVISOR_kexec_op(KEXEC_CMD_kexec, &xke);
	panic("KEXEC_CMD_kexec hypercall should not return\n");
}

void machine_shutdown(void)
{
	/* do nothing */
}


/*
 * Local variables:
 *  c-file-style: "linux"
 *  indent-tabs-mode: t
 *  c-indent-level: 8
 *  c-basic-offset: 8
 *  tab-width: 8
 * End:
 */
