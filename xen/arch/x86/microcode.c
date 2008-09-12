/*
 *      Intel CPU Microcode Update Driver for Linux
 *
 *      Copyright (C) 2000-2006 Tigran Aivazian <tigran@aivazian.fsnet.co.uk>
 *                    2006      Shaohua Li <shaohua.li@intel.com> *
 *      This driver allows to upgrade microcode on Intel processors
 *      belonging to IA-32 family - PentiumPro, Pentium II,
 *      Pentium III, Xeon, Pentium 4, etc.
 *
 *      Reference: Section 8.11 of Volume 3a, IA-32 Intel? Architecture
 *      Software Developer's Manual
 *      Order Number 253668 or free download from:
 *
 *      http://developer.intel.com/design/pentium4/manuals/253668.htm
 *
 *      For more information, go to http://www.urbanmyth.org/microcode
 *
 *      This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 *
 *      1.0     16 Feb 2000, Tigran Aivazian <tigran@sco.com>
 *              Initial release.
 *      1.01    18 Feb 2000, Tigran Aivazian <tigran@sco.com>
 *              Added read() support + cleanups.
 *      1.02    21 Feb 2000, Tigran Aivazian <tigran@sco.com>
 *              Added 'device trimming' support. open(O_WRONLY) zeroes
 *              and frees the saved copy of applied microcode.
 *      1.03    29 Feb 2000, Tigran Aivazian <tigran@sco.com>
 *              Made to use devfs (/dev/cpu/microcode) + cleanups.
 *      1.04    06 Jun 2000, Simon Trimmer <simon@veritas.com>
 *              Added misc device support (now uses both devfs and misc).
 *              Added MICROCODE_IOCFREE ioctl to clear memory.
 *      1.05    09 Jun 2000, Simon Trimmer <simon@veritas.com>
 *              Messages for error cases (non Intel & no suitable microcode).
 *      1.06    03 Aug 2000, Tigran Aivazian <tigran@veritas.com>
 *              Removed ->release(). Removed exclusive open and status bitmap.
 *              Added microcode_rwsem to serialize read()/write()/ioctl().
 *              Removed global kernel lock usage.
 *      1.07    07 Sep 2000, Tigran Aivazian <tigran@veritas.com>
 *              Write 0 to 0x8B msr and then cpuid before reading revision,
 *              so that it works even if there were no update done by the
 *              BIOS. Otherwise, reading from 0x8B gives junk (which happened
 *              to be 0 on my machine which is why it worked even when I
 *              disabled update by the BIOS)
 *              Thanks to Eric W. Biederman <ebiederman@lnxi.com> for the fix.
 *      1.08    11 Dec 2000, Richard Schaal <richard.schaal@intel.com> and
 *                           Tigran Aivazian <tigran@veritas.com>
 *              Intel Pentium 4 processor support and bugfixes.
 *      1.09    30 Oct 2001, Tigran Aivazian <tigran@veritas.com>
 *              Bugfix for HT (Hyper-Threading) enabled processors
 *              whereby processor resources are shared by all logical processors
 *              in a single CPU package.
 *      1.10    28 Feb 2002 Asit K Mallick <asit.k.mallick@intel.com> and
 *              Tigran Aivazian <tigran@veritas.com>,
 *              Serialize updates as required on HT processors due to
 *              speculative nature of implementation.
 *      1.11    22 Mar 2002 Tigran Aivazian <tigran@veritas.com>
 *              Fix the panic when writing zero-length microcode chunk.
 *      1.12    29 Sep 2003 Nitin Kamble <nitin.a.kamble@intel.com>,
 *              Jun Nakajima <jun.nakajima@intel.com>
 *              Support for the microcode updates in the new format.
 *      1.13    10 Oct 2003 Tigran Aivazian <tigran@veritas.com>
 *              Removed ->read() method and obsoleted MICROCODE_IOCFREE ioctl
 *              because we no longer hold a copy of applied microcode
 *              in kernel memory.
 *      1.14    25 Jun 2004 Tigran Aivazian <tigran@veritas.com>
 *              Fix sigmatch() macro to handle old CPUs with pf == 0.
 *              Thanks to Stuart Swales for pointing out this bug.
 */

#include <xen/config.h>
#include <xen/lib.h>
#include <xen/kernel.h>
#include <xen/init.h>
#include <xen/sched.h>
#include <xen/smp.h>
#include <xen/spinlock.h>
#include <xen/guest_access.h>

#include <asm/current.h>
#include <asm/msr.h>
#include <asm/uaccess.h>
#include <asm/processor.h>
#include <asm/microcode.h>

static int verbose;
boolean_param("microcode.verbose", verbose);

const struct microcode_ops *microcode_ops;

static DEFINE_SPINLOCK(microcode_mutex);

struct ucode_cpu_info ucode_cpu_info[NR_CPUS];

struct microcode_buffer {
	void *buf;
	size_t size;
};

static struct microcode_buffer microcode_buffer;
static bool_t microcode_error;

static void microcode_fini_cpu(int cpu)
{
	struct ucode_cpu_info *uci = ucode_cpu_info + cpu;

	spin_lock(&microcode_mutex);
	microcode_ops->microcode_fini_cpu(cpu);
	uci->valid = 0;
	spin_unlock(&microcode_mutex);
}

static int collect_cpu_info(int cpu)
{
	int err = 0;
	struct ucode_cpu_info *uci = ucode_cpu_info + cpu;

	memset(uci, 0, sizeof(*uci));
	err = microcode_ops->collect_cpu_info(cpu, &uci->cpu_sig);
	if (!err)
		uci->valid = 1;

	return err;
}

static int microcode_resume_cpu(int cpu)
{
	int err = 0;
	struct ucode_cpu_info *uci = ucode_cpu_info + cpu;
	struct cpu_signature nsig;

	gdprintk(XENLOG_INFO, "microcode: CPU%d resumed\n", cpu);

	if (!uci->mc.valid_mc)
		return -EIO;

	/*
	 * Let's verify that the 'cached' ucode does belong
	 * to this cpu (a bit of paranoia):
	 */
	err = microcode_ops->collect_cpu_info(cpu, &nsig);
	if (err) {
		microcode_fini_cpu(cpu);
		return err;
	}

	if (memcmp(&nsig, &uci->cpu_sig, sizeof(nsig))) {
		microcode_fini_cpu(cpu);
		/* Should we look for a new ucode here? */
		return -EIO;
	}

	err = microcode_ops->apply_microcode(cpu);

	return err;
}

static int microcode_update_cpu(int cpu, const void *buf, size_t size)
{
	int err = 0;
	struct ucode_cpu_info *uci = ucode_cpu_info + cpu;

	/* We should bind the task to the CPU */
	BUG_ON(raw_smp_processor_id() != cpu);

	spin_lock(&microcode_mutex);
	/*
	 * Check if the system resume is in progress (uci->valid != NULL),
	 * otherwise just request a firmware:
	 */
	if (uci->valid) {
		err = microcode_resume_cpu(cpu);
	} else {
		err = collect_cpu_info(cpu);
		if (err)
			goto out;
		if (uci->valid) {
			err = microcode_ops->cpu_request_microcode(cpu, buf, size);
		}
	}

out:
	spin_unlock(&microcode_mutex);

	return err;
}

static void do_microcode_update_one(void *info)
{
	int error = 0;

	error = microcode_update_cpu(smp_processor_id(),
			microcode_buffer.buf, microcode_buffer.size);

	if (error)
		microcode_error = error;	
}

static int do_microcode_update(void)
{
	int error = 0;

	microcode_error = 0;

	if (on_each_cpu(do_microcode_update_one, NULL, 1, 1) != 0) {
		printk(KERN_ERR "microcode: Error! Could not run on all processors\n");
		error = -EIO;
		goto out;
	}

	if (microcode_error) {
		error = microcode_error;
		goto out;
	}

out:
	return error;
}

int microcode_update(XEN_GUEST_HANDLE(const_void) buf, unsigned long len)
{
	int ret;
	struct cpuinfo_x86 *c = &boot_cpu_data;

	if (len != (typeof(microcode_buffer.size))len) {
		printk(KERN_ERR "microcode: too much data\n");
		return -E2BIG;
	}

	switch (c->x86_vendor) {
	case X86_VENDOR_AMD:
		ret = microcode_init_amd(c);
		break;

	case X86_VENDOR_INTEL:
		ret = microcode_init_intel(c);
		break;
	default:
		printk(KERN_ERR "microcode: CPU vendor not supported\n");
		ret = -EINVAL;
		break;
	}

	if (ret != 0)
		return ret;

	microcode_buffer.buf = xmalloc_array(uint8_t, len);
	if (!microcode_buffer.buf)
		return -ENOMEM;

	ret = copy_from_guest(microcode_buffer.buf, buf, len);
	if (ret != 0)
		return ret;

	microcode_buffer.size = len;
	wmb();

	ret = do_microcode_update();

	xfree(microcode_buffer.buf);
	microcode_buffer.buf = NULL;
	microcode_buffer.size = 0;

	return ret;
}
