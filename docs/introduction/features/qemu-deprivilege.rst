********************************
QEMU Deprivileging / dm_restrict
********************************

- Status: **Tech Preview**
- Architecture(s): x86
- Component(s): toolstack

========
Overview
========

By default, the QEMU device model is run in domain 0.  If an attacker
can gain control of a QEMU process, it could easily take control of a
system.

dm_restrict is a set of operations to restrict QEMU running in domain
0.  It consists of two halves:

 1. Mechanisms to restrict QEMU to only being able to affect its own
domain
 2. Mechanisms to restruct QEMU's ability to interact with domain 0.

============
User Details
============

Getting the Right Versions of Software
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- Linux: 4.11+
- Qemu: 3.0+ (Or the version that comes with Xen 4.12+)

Setting up a Group and UserID Range
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For maximum security, libxl needs to run the devicemodel for each
domain under a user id (UID) corresponding to its domain id.  There
are 32752 possible domain IDs, and so libxl needs 32752 user ids set
aside for it.  Setting up a group for all devicemodels to run at is
also recommended.

The simplest and most effective way to do this is to allocate a
contiguous block of UIDs, and create a single user named
`xen-qemuuser-range-base` with the first UID.  For example, under
Debian:

    adduser --system --uid 131072 --group --no-create-home xen-qemuuser-range-base

Two comments on this method:

  1. Most modern systems have 32-bit UIDs, and so can in theory go up
to 2^31 (or 2^32 if uids are unsigned).  POSIX only guarantees 16-bit
UIDs however; UID 65535 is reserved for an invalid value, and 65534 is
normally allocated to "nobody".
  2. Additionally, some container systems have proposed using the
upper 16 bits of the uid for a container ID.  Using a multiple of 2^16
for the range base (as is done above) will result in all UIDs being
interpreted by such systems as a single container ID.

Another, less-secure way is to run all QEMUs as the same UID.  To do
this, create a user named `xen-qemuuser-shared`; for example:

::
    adduser --no-create-home --system xen-qemuuser-shared

A final way to set up a separate process for qemus is to allocate one
UID per VM, and set the UID in the domain config file with the
`device_model_user` argument.  For example, suppose you have a VM
named `c6-01`.  You might do the following:

::
    adduser --system --no-create-home --group xen-qemuuser-c6-01

And then in your config file, the following line:

::
    device_model_user="xen-qemuuser-c6-01"

If you use this method, you should also allocate one "reaper" user to
be used for killing device models:

::
    adduser --system --no-create-home --group xen-qemuuser-reaper

.. note:: It is important when using `device_model_user` that EACH VM HAVE
A SEPARATE UID, and that none of these UIDs map to root.  xl will
throw an error a uid maps to zero, but not if multiple VMs have the
same uid.  Multiple VMs with the same device model uid will cause
problems.

It is also important that `xen-qemuuser-reaper` not have any processes
associated with it, as they will be destroyed when deprivileged qemu
processes are destroyed.

Domain Config Changes
~~~~~~~~~~~~~~~~~~~~~

The core domain config change is to add the following line to the
domain configuration:

    dm_restrict=1

This will perform a number of restrictions, outlined below in the
'Technical details' section.

=================
Technical Details
=================

See docs/design/qemu-deprivilege.md for technical details.

===========
Limitations
===========

The following features still need to be implemented:

* Inserting a new cdrom while the guest is running (xl cdrom-insert)
* Support for qdisk backends

A number of restrictions still need to be implemented.  A compromised
device model may be able to do the following:

* Delay or exploit weaknesses in the toolstack
* Launch "fork bombs" or other resource exhaustion attacks
* Make network connections on the management network
* Break out of the restrictions after migration

Additionally, getting PCI passthrough to work securely would require a
significant rework of how passthrough works at the moment.  It may be
implemented at some point but is not a near-term priority.

See SUPPORT.md for security support status.

=========
Changelog
=========

+--------+-------+-------+--------------------------------------+
| Date   | Rev   | Ve    | Notes                                |
|        | ision | rsion |                                      |
+========+=======+=======+======================================+
| 2018   | 1     | Xen   | Imported from docs/misc              |
| -09-14 |       | 4.12  |                                      |
+--------+-------+-------+--------------------------------------+
