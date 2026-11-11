.. SPDX-License-Identifier: CC-BY-4.0

Domain Creation And Runtime
===========================

Emulated UART
-------------

`XenProd~emul_ns16x50~1`

Description:
Xen shall provide an NS16550-compatible UART device to the domains.

Rationale:

Comments:
The device is exposed to a domain as a set of I/O ports at one of the legacy
PC COM port base addresses.

Covers:
 - `XenMkt~provide_console_domains~1`

Needs:
 - XenSwdgn
