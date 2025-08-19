.. SPDX-License-Identifier: CC-BY-4.0

Version hypercall
=================

First Parameter
---------------

`XenProd~version_hyp_first_param~1`

Description:
Xen shall treat the value stored in x0 as the command number for the hypercall.

Rationale:

Comments:

Covers:
 - `XenMkt~version_hypercall~1`

Needs:
 - XenSwdgn

Second Parameter
----------------

`XenProd~version_hyp_second_param~1`

Description:
Xen shall treat the value stored in x1 as a domain virtual address (mapped as
Normal Inner Write-Back Outer Write-Back Inner-Shareable) to buffer in domain's
memory.

Rationale:

Comments:

Covers:
 - `XenMkt~version_hypercall~1`

Needs:
 - XenSwdgn

Version command
---------------

`XenProd~version_hyp_version_cmd~1`

Description:
Xen shall provide a command (num 0) for  hypercall (num 17) to retrieve Xen's
version in the domain's register 0.

Rationale:

Comments:
Xen version is composed of major (ie version) and minor (ie subversion) number.
The minor number is encoded in the 16 least significant bits and the major number
is encoded in the top remaining bits.

Covers:
 - `XenMkt~version_hypercall~1`

Needs:
 - XenSwdgn

Extraversion command
--------------------

`XenProd~version_hyp_extraversion_cmd~1`

Description:
Xen shall provide a command (num 1) for hypercall (num 17) to copy its
extraversion in the domain's buffer.

Rationale:

Comments:
Xen's extra version consists of a string passed with 'XEN_VENDORVERSION' command
line parameter while building Xen.

Covers:
 - `XenMkt~version_hypercall~1`

Needs:
 - XenSwdgn

Capabilities command
--------------------

`XenProd~version_hyp_capabilities_cmd~1`

Description:
Xen shall provide a command (num 3) for hypercall (num 17) to copy its
capabilities to the domain's buffer.

Rationale:

Comments:
Capabilities related information is represented by char[1024].
For Arm64, the capabilities should contain "xen-3.0-aarch64" string.

Covers:
 - `XenMkt~version_hypercall~1`

Needs:
 - XenSwdgn

Changeset command
-----------------

`XenProd~version_hyp_changeset_cmd~1`

Description:
Xen shall provide a command (num 4) for hypercall (num 17) to copy changeset
to the domain's buffer.

Rationale:

Comments:
Changeset is string denoting the date, time and git hash of the last change
made to Xen's codebase.

Covers:
 - `XenMkt~version_hypercall~1`

Needs:
 - XenSwdgn
