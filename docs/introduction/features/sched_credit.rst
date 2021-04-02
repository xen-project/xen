****************
Credit Scheduler
****************

- Status: **Supported**
- Component: Hypervisor

========
Overview
========

Credit (also known as Credit1) is the old virtual CPU (vCPU) scheduler
of the Xen hypervisor.

It is a general purpose, weighted fair-share scheduler.

============
User Details
============

Xen supports multiple schedulers. Credit is no longer the default.  In
order to use it as the Xen scheduler the following parameter should be
passed to the hypervisor at boot:

    `sched=credit`

Once the system is live, for creating a cpupool with Credit as its
scheduler, either compile a cpupool configuration file, as described
in `docs/man/xlcpupool.cfg.pod.5` (and as exemplified in
`tools/examples/cpupool`), or use just `xl` directly:

    xl cpupool-create name=\"pool1\" sched=\"credit\" cpus=[4,8]

Two kind of interactions with the scheduler are possible:

* checking or changing the global parameters, via, e.g.:
    * `xl sched-credit -s`
    * `xl sched-credit -s -p pool1`
    * `xl sched-credit -s -t 20`
* checking or changing a VM's scheduling parameters, via, e.g.:
    * `xl sched-credit -d vm1`
    * `xl sched-credit -d vm1 -w 512`

=================
Technical Details
=================

Implementation entirely lives in the hypervisor. Xen has a pluggable,
hook based, architecture for schedulers. Thanks to this, Credit code
is all contained in `xen/common/sched_credit.c`.

===========
Limitations
===========

In Credit, a vCPU has a priority, a status (i.e., active or inactive),
a weight and some credits... and all these things interact in a rather
involved way. Also, with years of use, things have gotten even more
complex (due to, e.g., the introduction of boosting, caps and vCPU
soft-affinity).

Dealing with such complexity is starting to be an issue. Odd behavior
or subtle scheduling anomalies, that is not always possible to act upon,
have been identified already. [1][2][3]

A certain lack of scalability and difficulties and weakness in dealing
with mixed workloads and VMs with low latency requirements are other
known problems. [4] For all these reasons, effort is ongoing to have
Credit2 become the new default scheduler.

=======
Testing
=======

Any change to Credit code must to be tested by doing at least the following:

* create a few virtual machine and verify that they boot and can
  run some basic workload (e.g., login into them and run simple commands),
* shutdown/reboot the virtual machines,
* shutdown the system.

Ideally, all the above steps should **also** be performed in a configuration
that includes cpupools, better if with pools using different schedulers, and
by also doing the following:

* move the virtual machines between cpupools.

==========
References
==========

- `Potential non-ideal behavior on hyperthreaded systems <https://lists.xenproject.org/archives/html/xen-devel/2014-07/msg01848.html>`__
- `Long standing BOOST vs. migration bug <https://lists.xen.org/archives/html/xen-devel/2015-10/msg02851.html>`__
- `Priority handling issues <https://lists.xenproject.org/archives/html/xen-devel/2016-05/msg01362.html>`__
- `"Scheduler development update", XenSummit Asia 2009 [whitepaper] <http://www-archive.xenproject.org/files/xensummit_intel09/George_Dunlap.pdf>`__
- `"Scheduling in Xen" [XPDS15 Presentation] <http://events.linuxfoundation.org/sites/events/files/slides/Faggioli_XenSummit.pdf>`__
- `"The Credit Scheduler" [on the Xen-Project wiki] <https://wiki.xenproject.org/wiki/Credit_Scheduler>`__
- `"Xen Project Schedulers" [on the Xen-Project wiki] <https://wiki.xenproject.org/wiki/Xen_Project_Schedulers>`__

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
| 201    | 3     | Xen   | No longer default scheduler          |
| 9-02-7 |       | 4.12  |                                      |
+--------+-------+-------+--------------------------------------+
