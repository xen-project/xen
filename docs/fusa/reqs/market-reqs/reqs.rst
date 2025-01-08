.. SPDX-License-Identifier: CC-BY-4.0

Functional Requirements
=======================

Run Arm64 domains
-----------------

`XenMkt~run_arm64_domains~1`

Description:
Xen shall run Arm64 domains.

Rationale:

Comments:

Needs:
 - XenProd

Provide timer to the domains
----------------------------

`XenMkt~provide_timer_domains~1`

Description:
Xen shall provide a timer to a domain.

Rationale:

Comments:

Needs:
 - XenProd

Provide console to the domains
------------------------------

`XenMkt~provide_console_domains~1`

Description:
Xen shall provide a console to a domain.

Rationale:

Comments:

Needs:
 - XenProd

Static VM definition
--------------------

`XenMkt~static_vm_definition~1`

Description:
Xen shall support assigning peripherals to a domain.

Rationale:

Comments:
Peripheral implies an iomem (input output memory) and/or interrupts.

Needs:
 - XenProd

Multiple schedulers
-------------------

`XenMkt~multiple_schedulers~1`

Description:
Xen shall have configurable scheduling strategies of virtual cpus onto physical
cpus.

Rationale:

Comments:

Needs:
 - XenProd
