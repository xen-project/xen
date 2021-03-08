*****************
Credit2 Scheduler
*****************

- Status: **Supported**
- Component: Hypervisor

========
Overview
========

Credit2 is the default virtual CPU (vCPU) scheduler available in the
Xen hypervisor.

Credit2 was designed as a general purpose scheduler, with particular
focus on improving handling of mixed workloads, scalability and
support for low latency applications inside VMs.

============
User Details
============

Xen supports multiple schedulers. As said, Credit2 is the default, so
it is used automatically, unless the `sched=$SCHED` (with `$SCHED`
different than `credit2`) parameter is passed to Xen via the
bootloader.

Other parameters are available for tuning the behavior of Credit2
(see `docs/misc/xen-command-line.markdown` for a complete list and
for their meaning).

Once the system is live, for creating a cpupool with Credit2 as
its scheduler, either compile a cpupool configuration file, as
described in `docs/man/xlcpupool.cfg.pod.5` (and as exemplified
in `tools/examples/cpupool`), or use just `xl` directly:

    xl cpupool-create name=\"pool1\" sched=\"credit2\" cpus=[1,2]

Two kind of interactions with the scheduler are possible:

* checking or changing the global parameters, via, e.g.:
    * `xl sched-credit2 -s`
    * `xl sched-credit2 -s -p pool1`
    * `xl sched-credit2 -s -r 100`
* checking or changing a VM scheduling parameters, via, e.g.:
    * `xl sched-credit2 -d vm1`
    * `xl sched-credit2 -d vm1 -w 1024`

=================
Technical Details
=================

Implementation entirely lives in the hypervisor. Xen has a pluggable,
hook based, architecture for schedulers. Thanks to this, Credit2 code
is all contained in `xen/common/sched_credit2.c`.

Global scheduling parameters, such as context switching rate
limiting, is only available from Xen 4.8 onward. In libxl, the
LIBXL_HAVE_SCHED_CREDIT2_PARAMS symbol is introduced to
indicate their availability.

=======
Testing
=======

Any change done in Credit2 wants to be tested by doing at least the
following:

* boot the system with `sched=credit2`,
* create a few virtual machine and verify that they boot and can
  run some basic workload (e.g., login into them and run simple commands),
* shutdown/reboot the virtual machines,
* shutdown/reboot the system.

Ideally, all the above steps should **also** be performed in a configuration
where Credit2 is used as the scheduler of a cpupool, and by also doing the
following:

* move a virtual machine inside and outside a Credit2 cpupool.

# Areas for improvement

* vCPUs' reservations (similar to caps, but providing a vCPU with guarantees
  about some pCPU time it will always be able to execute for);
* benchmarking for assessing the best combination of values for the various
  parameters (`sched_credit2_migrate_resist`, `credit2_balance_over`,
  `credit2_balance_under`)

============
Known Issues
============

* I/O oriented benchmarks (like network and disk throughput) have given
  contradictory and non-conclusive results so far. Need to run more of
  those.

==========
References
==========

* `"Scheduler development update", XenSummit Asia 2009 [whitepaper] <http://www-archive.xenproject.org/files/xensummit_intel09/George_Dunlap.pdf>`__
* `"Scheduling in Xen" [XPDS15 Presentation] <http://events.linuxfoundation.org/sites/events/files/slides/Faggioli_XenSummit.pdf>`__
* `"Scope and Performance of Credit-2 Scheduler" [XPDS16 Presentation] <http://www.slideshare.net/xen_com_mgr/xpds16-scope-and-performance-of-credit2-scheduler-anshul-makkar-ctirix-systems-uk-ltd>`__
* `"The Credit2 Scheduler" [on the Xen-Project wiki] <https://wiki.xenproject.org/wiki/Credit2_Scheduler_Development>`__
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
| 201    | 2     | Xen   | Soft-affinity and caps implemented   |
| 7-11-6 |       | 4.10  |                                      |
+--------+-------+-------+--------------------------------------+
| 201    | 3     | Xen   | Made the default scheduler           |
| 9-02-7 |       | 4.12  |                                      |
+--------+-------+-------+--------------------------------------+
