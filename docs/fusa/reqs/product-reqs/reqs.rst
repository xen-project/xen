.. SPDX-License-Identifier: CC-BY-4.0

Domain Creation And Runtime
===========================

Kernel command line arguments
-----------------------------

`XenProd~kernel_cmd_line_args~1`

Description:
Xen shall pass kernel command line arguments to a domain via a device tree.

Rationale:

Comments:
Device tree is a data structure and language for describing hardware which is
readable by an operating system [1].

Covers:
 - `XenMkt~run_arm64_domains~1`

Needs:
 - XenSwdgn

Ramdisk
-------

`XenProd~ramdisk~1`

Description:
Xen shall provide the address of an initial ramdisk to a domain via a device
tree.

Rationale:

Comments:
The initial ramdisk is contained in memory.

Covers:
 - `XenMkt~run_arm64_domains~1`

Needs:
 - XenSwdgn

Memory
------

`XenProd~memory~1`

Description:
Xen shall create a domain with the amount of memory specified in a device tree.

Rationale:

Comments:

Covers:
 - `XenMkt~run_arm64_domains~1`

Needs:
 - XenSwdgn

vCPUs
-----

`XenProd~vcpus~1`

Description:
A domain shall have a configurable number of virtual CPUs (1 to 128).

Rationale:

Comments:

Covers:
 - `XenMkt~run_arm64_domains~1`

Needs:
 - XenSwdgn

Credit2 CPU pool scheduler
--------------------------

`XenProd~credit2_cpu_pool_scheduler~1`

Description:
Xen shall have a credit2 scheduler where a physical cpu can be shared between
more than one virtual cpu.

Rationale:

Comments:

Covers:
 - `XenMkt~run_arm64_domains~1`
 - `XenMkt~multiple_schedulers~1`

Needs:
 - XenSwdgn

NUL CPU pool scheduler
----------------------

`XenProd~nul_cpu_pool_scheduler~1`

Description:
Xen shall have a nul scheduler where the domain virtual cpu is always running on
its dedicated physical cpu.

Rationale:

Comments:
A NUL CPU pool scheduler maps a virtual cpu to a unique physical cpu.

Covers:
 - `XenMkt~run_arm64_domains~1`
 - `XenMkt~multiple_schedulers~1`

Needs:
 - XenSwdgn

Assign iomem
------------

`XenProd~assign_iomem~1`

Description:
Xen shall support assigning pages of iomem (address and size aligned to a page)
to a domain.

Rationale:

Comments:

Covers:
 - `XenMkt~static_vm_definition~1`

Needs:
 - XenSwdgn

Forward interrupts
------------------

`XenProd~forward_irqs~1`

Description:
Xen shall support forwarding hardware interrupts to a domain.

Rationale:

Comments:

Covers:
 - `XenMkt~static_vm_definition~1`

Needs:
 - XenSwdgn

| [1] https://docs.kernel.org/devicetree/usage-model.html
