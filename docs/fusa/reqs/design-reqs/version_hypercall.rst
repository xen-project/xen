.. SPDX-License-Identifier: CC-BY-4.0

Version
-------

`XenSwdgn~version~1`

Description:
Xen shall return its version when XENVER_version command is invoked.

Rationale:

Comments:

Covers:
 - `XenProd~version_hyp_version_cmd~1`

Error copying buffer
--------------------

`XenSwdgn~error_copy_buffer~1`

Description:
Xen shall return -EFAULT if it is not able to copy data to domain's buffer.

Rationale:
-EFAULT is one of the error code defined in
http://xenbits.xen.org/gitweb/?p=xen.git;a=blob;f=xen/include/public/errno.h.

Comments:

Covers:
 - `XenProd~hyp_err_ret_val~1`

Extraversion
------------

`XenSwdgn~extraversion~1`

Description:
Xen shall return its extraversion when XENVER_extraversion command is invoked.

Rationale:

Comments:

Covers:
 - `XenProd~version_hyp_extraversion_cmd~1`

Changeset
---------

`XenSwdgn~changeset~1`

Description:
Xen shall return its changeset when XENVER_changeset command is invoked.

Rationale:

Comments:

Covers:
 - `XenProd~version_hyp_changeset_cmd~1`
