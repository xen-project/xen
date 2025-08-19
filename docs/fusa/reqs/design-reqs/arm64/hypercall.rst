.. SPDX-License-Identifier: CC-BY-4.0

Hypercall
=========

Instruction
-----------

`XenSwdgn~arm64_hyp_instr~1`

Description:
Xen shall treat domain hvc instruction execution (with 0xEA1) as hypercall
requests.

Rationale:

Comments:
Hypercall is one of the communication mechanism between Xen and domains.
Domains use hypercalls for various requests to Xen.
The exception syndrome register should have the following values :-
ESR_EL2.ISS should be 0xEA1.
ESR_EL2.EC should be 0x16.

Covers:
 - `XenProd~version_hyp_first_param~1`
 - `XenProd~version_hyp_second_param~1`

Parameters
----------

`XenSwdgn~arm64_hyp_param~1`

Description:
Xen shall use x0 - x4 core registers to obtain the arguments for domain hypercall
requests.

Rationale:

Comments:
Xen shall read x0 for the first argument, x1 for the second argument and so on.

Covers:
 - `XenProd~version_hyp_first_param~1`
 - `XenProd~version_hyp_second_param~1`

Hypercall number
----------------

`XenSwdgn~arm64_hyp_num~1`

Description:
Xen shall read x16 to obtain the hypercall number.

Rationale:

Comments:

Covers:
 - `XenProd~version_hyp_first_param~1`
 - `XenProd~version_hyp_second_param~1`

Return value
------------

`XenSwdgn~arm64_ret_val~1`

Description:
Xen shall store the return value in x0.

Rationale:

Comments:

Covers:
 - `XenProd~hyp_err_ret_val~1`
