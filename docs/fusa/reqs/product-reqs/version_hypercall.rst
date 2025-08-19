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
