**************
RTDS Scheduler
**************

- Status: **Experimental**
- Component: Hypervisor

========
Overview
========

RTDS is one of the virtual CPU (vCPU) scheduler available in the Xen
hypervisor.

RTDS is a real-time scheduler, so its purpose is enabling
**deterministic** scheduling of the virtual machine's vCPUs. It has
been originally developed in the context of the RT-Xen project.

============
User Details
============

RTDS is not in use by default. In order to use it as the Xen scheduler
the following parameter should be passed to the hypervisor at boot:

    `sched=rtds`

Once the system is live, for creating a cpupool with RTDS as its
scheduler, either compile a cpupool configuration file, as described
in `docs/man/xlcpupool.cfg.pod.5` (and as exemplified in
`tools/examples/cpupool`), or use just `xl` directly:

    xl cpupool-create name=\"pool-rt\" sched=\"rtds\" cpus=[4,5,6,8]

For checking or changing a VM's scheduling parameters from xl, do
as follows:
    * `xl sched-rtds -d vm-rt -v all`
    * `xl sched-rtds -d vm-rt -v all -p 10000 -b 2500`

It is possible, for a multiple vCPUs VM, to change the parameters of
each vCPU individually:
    * `xl sched-rtds -d vm-rt -v 0 -p 20000 -b 10000 -e 1 -v 1 -p 45000 -b 12000 -e 0`

=================
Technical Details
=================

Implementation entirely lives in the hypervisor. Xen has a pluggable,
hook based, architecture for schedulers. Thanks to this, RTDS code
is all contained in `xen/common/sched_rtds.c`.

In libxl, the availability of the RTDS scheduler is advertised by
the presence of the LIBXL_HAVE_SCHED_RTDS symbol. The ability of
specifying different scheduling parameters for each vcpu has been
introduced later, and is available if the following symbols are defined:
    * LIBXL_HAVE_VCPU_SCHED_PARAMS,
    * LIBXL_HAVE_SCHED_RTDS_VCPU_PARAMS,
    * LIBXL_HAVE_SCHED_RTDS_VCPU_EXTRA.

===========
Limitations
===========

RTDS is a special purpose scheduling. This is by design, and not at
all a limitation, but it is certainly something to keep in mind when
thinking about using it. The purpose of the scheduler is enabling
deterministic and statically analyzable behavior (as per the
real-time academic literature), according to the scheduling parameters
assigned to each vCPU.

Using RTDS a the Xen scheduler, and/or for general purpose workloads
is definitely possible, but the vCPU scheduling parameters (of both
Domain0 and of the various VMs) would probably require tweaking, with
respect to their default values.

=======
Testing
=======

Any change done in RTDS must be tested by doing the following:

* create a cpupool with RTDS as its scheduler,
* create a few virtual machines a move them in and out of the pool,
* create a few virtual machines, directly inside the pool, and verify
  that they boot and can run some basic workload (e.g., login into them
  and run simple commands),
* shutdown/reboot the virtual machines,

The fact that the system boots fine when passing `sched=rtds` to Xen
should also be verified.

Finally, to check that the scheduler is working properly (although only
at a macroscopic level), the following should be done:

* create a VM with 1 vCPU and put it in the RTDS cpupool,
* set the scheduling parameters such as it has a 50% reservation, with
  `xl sched-rtds -d vm -v all -p 100000 -b 50000`,
* run a CPU-burning process inside the VM (e.g., `yes`),
* check with `xentop` (in Domain0) that the VM is getting no more than
  50% pCPU time.

=====================
Areas for Improvement
=====================

* performance assessment, especially focusing on what level of real-time
  behavior the scheduler enables.

============
Known Issues
============

* OSSTest reports occasional failures on ARM.

==========
References
==========

* `"RT-Xen: Real-Time Virtualization" [XPDS14 Presentation] <http://events.linuxfoundation.org/sites/events/files/slides/2014_Xen_Developer_Summit_0.pdf>`__ 
* `"Scheduling in Xen" [XPDS15 Presentation] <http://events.linuxfoundation.org/sites/events/files/slides/Faggioli_XenSummit.pdf>`__
* `[RT-Xen Project] <https://sites.google.com/site/realtimexen/>`__
* `[RTDS-Based-Scheduler] <https://wiki.xenproject.org/wiki/RTDS-Based-Scheduler>`__
* `"The RTDS Scheduler" [on the Xen-Project wiki] <https://wiki.xenproject.org/wiki/RTDS-Based-Scheduler>`__
* `"Xen Project Schedulers" [on the Xen-Project wiki] <https://wiki.xenproject.org/wiki/Xen_Project_Schedulers>`__

=========
Changelog
=========

+--------+-------+-------+--------------------------------------+
| Date   | Rev   | Ve    | Notes                                |
|        | ision | rsion |                                      |
+========+=======+=======+======================================+
| 2016   | 1     | Xen   | Document written                     |
| -10-14 |       | 4.8   |                                      |
+--------+-------+-------+--------------------------------------+
| 2017   | 2     | Xen   | Revise for work conserving feature   |
| -08-31 |       | 4.10  |                                      |
+--------+-------+-------+--------------------------------------+
