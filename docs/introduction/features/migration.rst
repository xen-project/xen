*********
Migration
*********

- Status: **Supported**
- Architecture: x86
- Component: Toolstack

========
Overview
========

Migration is a mechanism to move a virtual machine while the VM is
running.  Live migration moves a running virtual machine between two
physical servers, but the same mechanism can be used for non-live
migration (pause and copy) and suspend/resume from disk.

============
User Details
============

No hardware requirements, although hypervisor logdirty support is
required for live migration.

From the command line, `xl migrate/save/restore` are the top level
interactions. For example:

    xl create my-vm.cfg
    xl migrate my-vm localhost

or

    xl create my-vm.cfg
    xl save my-vm /path/to/save/file
    xl restore /path/to/save/file

Xen 4.6 sees the introduction of Migration v2.  There is no change for
people using `xl`, although the `libxl` API has had an extension.

=================
Technical Details
=================

Migration is formed of several layers. `libxc` is responsible for the
contents of the VM (ram, vcpus, etc) and the live migration loop, while
`libxl` is responsible for items such as emulator state.

The format of the migration v2 stream is specified in two documents, and
is architecture neutral.  Compatibility with legacy streams is
maintained via the `convert-legacy-stream` script which transforms a
legacy stream into a migration v2 stream.

* Documents
    * `docs/specs/libxc-migration-stream.pandoc`
    * `docs/specs/libxl-migration-stream.pandoc`
* `libxc`
    * `tools/libxc/xc_sr_*.[hc]`
* `libxl`
    * `tools/libxl/libxl_stream_{read,write}.c`
    * `tools/libxl/libxl_convert_callout.c`
* Scripts
    * `tools/python/xen/migration/*.py`
    * `tools/python/scripts/convert-legacy-stream`
    * `tools/python/scripts/verify-stream-v2`

libxl
~~~~~

With migration v2 support, LIBXL_HAVE_SRM_V2 and LIBXL_HAVE_SRM_V1
are introduced to indicate support.  `domain_restore_params` gains a new
parameter, `stream_version`, which is used to distinguish between legacy and
v2 migration streams, and hence whether legacy conversion is required.

===========
Limitations
===========

Hypervisor logdirty support is incompatible with hardware passthrough,
as IOMMU faults cannot be used to track writes.

While not a bug in migration specifically, VMs are very sensitive to
changes in cpuid information, and cpuid levelling support currently has
its issues.  Extreme care should be taken when migrating VMs between
non-identical CPUs until the cpuid levelling improvements are complete.

=======
Testing
=======

Changes in libxc should be tested with every guest type (32bit PV, 64bit
PV, HVM), while changes in libxl should test HVM guests with both
qemu-traditional and qemu-upstream.

In general, testing can be done on a single host using `xl save/restore` or `xl migrate $VM localhost`.

Any changes to the conversion script should be tested in all upgrade
scenarios, which will involve starting with VMs from Xen 4.5

=====================
Areas for Improvement
=====================

* Arm support
* Live looping parameters

============
Known Issues
============

* x86 HVM guest physmap operations (not reflected in logdirty bitmap)
* x86 HVM with PoD pages (attempts to map cause PoD allocations)
* x86 HVM with nested-virt (no relevant information included in the
  stream)
* x86 PV ballooning (P2M marked dirty, target frame not marked)
* x86 PV P2M structure changes (not noticed, stale mappings used) for
  guests not using the linear p2m layout

==========
References
==========

- `Xen Developer Summit 2015 Presentation [video] <https://www.youtube.com/watch?v=RwiDeG21lrc>`__
- `Xen Developer Summit 2015 Presentation [slides](http://events.linuxfoundation.org/sites/events/files/slides/migv2.pdf)>`__

=========
Changelog
=========

+--------+-------+-------+--------------------------------------+
| Date   | Rev   | Ve    | Notes                                |
|        | ision | rsion |                                      |
+========+=======+=======+======================================+
| 2015   | 1     | Xen   | Document written                     |
| -10-24 |       | 4.6   |                                      |
+--------+-------+-------+--------------------------------------+
| 2015   | 2     | Xen   | Support of linear p2m list           |
| -12-11 |       | 4.7   |                                      |
+--------+-------+-------+--------------------------------------+
