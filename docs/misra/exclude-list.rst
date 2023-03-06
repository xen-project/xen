.. SPDX-License-Identifier: CC-BY-4.0

Exclude file list for xen-analysis script
=========================================

The code analysis is performed on the Xen codebase for both MISRA
checkers and static analysis checkers, there are some files however that
needs to be removed from the findings report for various reasons (e.g.
they are imported from external sources, they generate too many false
positive results, etc.).

For this reason the file docs/misra/exclude-list.json is used to exclude every
entry listed in that file from the final report.
Currently only the cppcheck analysis will use this file.

Here is an example of the exclude-list.json file::

|{
|    "version": "1.0",
|    "content": [
|        {
|            "rel_path": "relative/path/from/xen/file",
|            "comment": "This file is originated from ..."
|        },
|        {
|            "rel_path": "relative/path/from/xen/folder/*",
|            "comment": "This folder is a library"
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

To ease the review and the modifications of the entries, they shall be listed in
alphabetical order referring to the rel_path field.
Excluded folder paths shall end with '/*' in order to match everything on that
folder.
