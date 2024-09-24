.. SPDX-License-Identifier: CC-BY-4.0

##################################
Requirements Introduction Document
##################################

This folder contains a set of requirements describing Xen and its implementation
in a form suitable for a safety certification process.

The status is experimental and it is maintained on a best effort basis. The
requirements may get slightly out of sync with the code. We are actively working
on a process to keep them updated, more details to follow.

The requirements writing style is inspired from the ANSI/IEEE guide to Software
Requirements Standard 830-1984.

The requirements are categorized as follows :-

1. Market requirements - They define the high level functionalities of the
hypervisor without going into concepts specific to Xen. Those should allow a
system architect to understand wether Xen is providing the functionalities it
needs for its system. This is the top level of the requirements.

2. Product requirements - They define the Xen specific concepts and interfaces
provided by Xen without going into implementation details. One or several of
those requirements are linked to each market requirement. An Architect can use
them understand how Xen fulfils a market need and design how Xen should be used
in his system.

3. Design requirements - They describe what the software implementation is doing
from a technical point of view. One or several design requirement together
define how product requirements are fulfilled technically and are linked to
them. An implementer can use them to know how to write or understand the Xen
code.

The requirements are linked using OpenFastTrace
(https://github.com/itsallcode/openfasttrace/blob/main/doc/user_guide.md).
OpenFastTrace parses through the requirements and generates a traceability
report.

Assumption of Use
=================

Xen is making several assumptions on the status of the platform or on some
functions being present and operational. For example, Xen might assume that
some registers are set.
Anybody who wants to use Xen must validate that the platform it is used on
(meaning the hardware and any software running before Xen like the firmware)
fulfils all the AoU described by Xen.

The following is the skeleton for a requirement.

Title of the requirement
========================

`unique_tag`

..

  Each requirement needs to have a unique tag associated. The format is
  req_type~name~revision.

  Thus, it consists of three components :-
  requirement type - This denotes the category of requirement. Thus, it shall
  be 'XenMkt', 'XenProd' or 'XenSwdgn' to denote market, product or design
  requirement.
  name - This denotes name of the requirement. In case of architecture specific
  requirements, this starts with the architecture type (eg x86_64, arm64)
  followed by component name (eg generic_timer) and action (eg read_xxx).
  revision number - This gets incremented each time the requirement is modified.


Description:
This shall describe the requirement in a definitive tone. In other words,
the requirement begins with 'Xen shall ...'. Further, the description is
expected to be unambiguous and consistent.

Rationale:
This describes a rationale explaining the reason of the presence of the
requirement when this can help the reader. This field can be left blank.

Comments:
This describes the use cases for the requirement when this can help the
reader. This field can be left blank as well.

Covers:
This denotes the unique_tag of the parent. This field is non existent for the
market requirement as it is the top level.

Needs:
This denotes the requirement type of its children. This field is non existent
for the design requirements as there are no subsequent requirements linked to
them.


The requirements are expected to the technically correct and follow the above
guidelines.
