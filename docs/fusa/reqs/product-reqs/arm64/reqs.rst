.. SPDX-License-Identifier: CC-BY-4.0

Domain Creation And Runtime
===========================

Emulated Timer
--------------

`XenProd~arm64_emulated_timer~1`

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

`XenProd~arm64_emulated_uart~1`

Description:
Xen shall provide an "Arm SBSA UART" compliant device to the domains.

Rationale:

Comments:

Covers:
 - `XenMkt~run_arm64_domains~1`
 - `XenMkt~provide_console_domains~1`

Needs:
 - XenSwdgn

Linux kernel image
------------------

`XenProd~arm64_linux_kernel_image~1`

Description:
Xen shall create a domain with a binary containing header compliant with Arm64
Linux kernel image [1].

Rationale:

Comments:

Covers:
 - `XenMkt~run_arm64_domains~1`

Needs:
 - XenSwdgn

Gzip Linux kernel image
-----------------------

`XenProd~arm64_linux_kernel_gzip_image~1`

Description:
Xen shall create a domain with a Gzip compressed binary containing header
compliant with Arm64 Linux kernel image [1].

Rationale:

Comments:

Covers:
 - `XenMkt~run_arm64_domains~1`

Needs:
 - XenSwdgn

Kernel with uImage header
-------------------------

`XenProd~arm64_kernel_uimage~1`

Description:
Xen shall create a domain with a binary containing uImage header [2].

Rationale:

Comments:

Covers:
 - `XenMkt~run_arm64_domains~1`

Needs:
 - XenSwdgn

Gzip kernel with uImage header
------------------------------

`XenProd~arm64_gzip_kernel_uimage~1`

Description:
Xen shall create a domain with a Gzip compressed binary containing uImage
header [2].

Rationale:

Comments:

Covers:
 - `XenMkt~run_arm64_domains~1`

Needs:
 - XenSwdgn

SPIs
----

`XenProd~arm64_spis~1`

Description:
Xen shall assign hardware shared peripheral interrupts specified in the device
tree to a domain.

Rationale:

Comments:
Device tree is a data structure and language for describing hardware which is
readable by an operating system [3].
A shared peripheral interrupt is a peripheral interrupt that the Arm Generic
Interrupt Controller's Distributor interface can route to any combination of
processors [4].

Covers:
 - `XenMkt~run_arm64_domains~1`
 - `XenMkt~static_vm_definition~1`

Needs:
 - XenSwdgn

Virtual PL011
-------------

`XenProd~arm64_virtual_pl011~1`

Description:
Xen shall provide an "Arm PL011 UART" compliant device to the domains.

Rationale:

Comments:

Covers:
 - `XenMkt~run_arm64_domains~1`
 - `XenMkt~provide_console_domains~1`

Needs:
 - XenSwdgn

| [1] https://github.com/torvalds/linux/blob/master/Documentation/arch/arm64/booting.rst
| [2] https://source.denx.de/u-boot/u-boot/-/blob/master/include/image.h#L315
| [3] https://docs.kernel.org/devicetree/usage-model.html
| [4] https://developer.arm.com/documentation/ihi0048/a/Introduction/Terminology/Interrupt-types?lang=en
