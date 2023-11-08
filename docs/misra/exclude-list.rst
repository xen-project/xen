.. SPDX-License-Identifier: CC-BY-4.0

Exclude file list for xen scripts
=================================

Different Xen scripts can perform operations on the codebase to check its
compliance for a set of rules, however Xen contains some files that are taken
from other projects (e.g. linux) and they can't be updated to ease backporting
fixes from their source, for this reason the file docs/misra/exclude-list.json
is kept as a source of all these files that are external to the Xen project.

Every entry of the file can be linked to different checkers, so that this list
can be used by multiple scripts selecting only the required entries.

Here is an example of the exclude-list.json file::

|{
|    "version": "1.0",
|    "content": [
|        {
|            "rel_path": "relative/path/from/xen/file",
|            "comment": "This file is originated from ...",
|            "checkers": "xen-analysis"
|        },
|        {
|            "rel_path": "relative/path/from/xen/folder/*",
|            "comment": "This folder is a library",
|            "checkers": "xen-analysis some-checker"
|        },
|        {
|            "rel_path": "relative/path/from/xen/mem*.c",
|            "comment": "memcpy.c, memory.c and memcmp.c are from the outside"
|        }
|    ]
|}

Here is an explanation of the fields inside an object of the "content" array:
 - rel_path: it is the relative path from the Xen folder to the file/folder that
   needs to be excluded from the analysis report, it can contain a wildcard to
   match more than one file/folder at the time. This field is mandatory.
 - comment: an optional comment to explain why the file is removed from the
   analysis.
 - checkers: an optional list of checkers that will exclude this entries from
   their results. This field is optional and when not specified, it means every
   checker will use that entry.
   Current implemented values for this field are:

    - xen-analysis: the xen-analysis.py script exclude this entry for both MISRA
      and static analysis scan. (Implemented only for Cppcheck tool)

To ease the review and the modifications of the entries, they shall be listed in
alphabetical order referring to the rel_path field.
Excluded folder paths shall end with ``/*`` in order to match everything on that
folder.
