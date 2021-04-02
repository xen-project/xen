*************
Hypervisor FS
*************

- Status: **Supported**
- Architectures: all
- Components: Hypervisor, toolstack

========
Overview
========

The Hypervisor FS is a hierarchical name-value store for reporting
information to guests, especially dom0. It is similar to the Linux
kernel's sysfs. Entries and directories are created by the hypervisor,
while the toolstack is able to use a hypercall to query the entry
values or (if allowed by the hypervisor) to modify them.

============
User Details
============

With:

    xenhypfs ls <path>

the user can list the entries of a specific path of the FS. Using:

    xenhypfs cat <path>

the content of an entry can be retrieved. Using:

    xenhypfs write <path> <string>

a writable entry can be modified. With:

    xenhypfs tree

the complete Hypervisor FS entry tree can be printed.

The FS paths are documented in `docs/misc/hypfs-paths.pandoc`.

=================
Technical Details
=================

Access to the hypervisor filesystem is done via the stable new hypercall
__HYPERVISOR_filesystem_op. This hypercall supports a sub-command
XEN_HYPFS_OP_get_version which will return the highest version of the
interface supported by the hypervisor. Additions to the interface need
to bump the interface version. The hypervisor is required to support the
previous interface versions, too (this implies that additions will always
require new sub-commands in order to allow the hypervisor to decide which
version of the interface to use).

* hypercall interface specification
    * `xen/include/public/hypfs.h`
* hypervisor internal files
    * `xen/include/xen/hypfs.h`
    * `xen/common/hypfs.c`
* `libxenhypfs`
    * `tools/libs/libxenhypfs/*`
* `xenhypfs`
    * `tools/misc/xenhypfs.c`
* path documentation
    * `docs/misc/hypfs-paths.pandoc`

=======
Testing
=======

Any new parameters or hardware mitigations should be verified to show up
correctly in the filesystem.

Areas for Improvement
~~~~~~~~~~~~~~~~~~~~~

* More detailed access rights
* Entries per domain and/or per cpupool

============
Known Issues
============

* None

==========
References
==========

* None

=========
Changelog
=========

+-------------+----------------------------+-------------------------------------+
|  Date       |  Revision Version          |   Notes                             |
+=============+============================+=====================================+
| 2020-01-23  |     Xen 4.14               |        Document written             |
+-------------+----------------------------+-------------------------------------+
