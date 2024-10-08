.. SPDX-License-Identifier: CC-BY-4.0

Domain Creation And Runtime
===========================

Emulated Timer
--------------

`XenProd~emulated_timer~1`

Description:
Xen shall grant access to "Arm Generic Timer" for the domains.

Rationale:

Comments:

Covers:
 - `XenMkt~run_arm64_domains~1`
 - `XenMkt~provide_timer_domains~1`

Needs:
 - XenSwdgn

Emulated UART
-------------

`XenProd~emulated_uart~1`

Description:
Xen shall provide an "Arm SBSA UART" compliant device to the domains.

Rationale:

Comments:

Covers:
 - `XenMkt~run_arm64_domains~1`
 - `XenMkt~provide_console_domains~1`

Needs:
 - XenSwdgn
