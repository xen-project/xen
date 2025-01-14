.. SPDX-License-Identifier: CC-BY-4.0

Generic Timer
=============

The following are the requirements related to ARM Generic Timer [1] interface
exposed by Xen to Arm64 domains.

Probe the Generic Timer device tree node from a domain
------------------------------------------------------

`XenSwdgn~arm64_generic_timer_probe_dt~1`

Description:
Xen shall generate a device tree node for the Generic Timer (in accordance to
ARM architected timer device tree binding [2]) in the domain device tree.

Rationale:

Comments:
Domains can detect the presence of the Generic Timer device tree node.

Covers:
 - `XenProd~arm64_emulated_timer~1`

Read system counter frequency
-----------------------------

`XenSwdgn~arm64_generic_timer_read_freq~1`

Description:
Xen shall expose the frequency of the system counter to the domains in
CNTFRQ_EL0 register.

Rationale:

Comments:

Covers:
 - `XenProd~arm64_emulated_timer~1`

Access CNTKCTL_EL1 system register from a domain
------------------------------------------------

`XenSwdgn~arm64_generic_timer_access_cntkctlel1~1`

Description:
Xen shall expose Counter-timer Kernel Control register (CNTKCTL_EL1) to the
domains.

Rationale:

Comments:

Covers:
 - `XenProd~arm64_emulated_timer~1`

Access virtual timer from a domain
----------------------------------

`XenSwdgn~arm64_generic_timer_access_virtual_timer~1`

Description:
Xen shall expose the virtual timer registers (CNTVCT_EL0, CNTV_CTL_EL0,
CNTV_CVAL_EL0, CNTV_TVAL_EL0) to the domains.

Rationale:

Comments:

Covers:
 - `XenProd~arm64_emulated_timer~1`

Access physical timer from a domain
-----------------------------------

`XenSwdgn~arm64_generic_timer_access_physical_timer~1`

Description:
Xen shall expose physical timer registers (CNTPCT_EL0, CNTP_CTL_EL0,
CNTP_CVAL_EL0, CNTP_TVAL_EL0) to the domains.

Rationale:

Comments:

Covers:
 - `XenProd~arm64_emulated_timer~1`

Trigger the virtual timer interrupt from a domain
-------------------------------------------------

`XenSwdgn~arm64_generic_timer_trigger_virtual_interrupt~1`

Description:
Xen shall generate virtual timer interrupts to domains when the virtual timer
condition is met.

Rationale:

Comments:

Covers:
 - `XenProd~arm64_emulated_timer~1`

Trigger the physical timer interrupt from a domain
--------------------------------------------------

`XenSwdgn~arm64_generic_timer_trigger_physical_interrupt~1`

Description:
Xen shall generate physical timer interrupts to domains when the physical timer
condition is met.

Rationale:

Comments:

Covers:
 - `XenProd~arm64_emulated_timer~1`

Assumption of Use on the Platform
=================================

Expose system timer frequency via register
------------------------------------------

`XenSwdgn~arm64_generic_timer_plat_program_cntfrq_el0~1`

Description:
CNTFRQ_EL0 register shall be programmed with the value of the system timer
frequency.

Rationale:
Xen reads the CNTFRQ_EL0 register to get the value of system timer frequency.

Comments:
While there is a provision to get this value by reading the "clock-frequency"
dt property [2], the use of this property is strongly discouraged.

Covers:
 - `XenProd~arm64_emulated_timer~1`

[1] Arm Architecture Reference Manual for A-profile architecture, Chapter 11
[2] https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/Documentation/devicetree/bindings/timer/arm,arch_timer.yaml
