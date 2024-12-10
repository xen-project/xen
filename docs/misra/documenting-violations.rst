.. SPDX-License-Identifier: CC-BY-4.0

Documenting violations
======================

Static analysers are used on the Xen codebase for both static analysis and MISRA
compliance.
There might be the need to suppress some findings instead of fixing them and
many tools permit the usage of in-code comments that suppress findings so that
they are not shown in the final report.

Xen includes a tool capable of translating a specific comment used in its
codebase to the right proprietary in-code comment understandable by the selected
analyser that suppress its finding.

In the Xen codebase, these tags will be used to document and suppress findings:

 - SAF-X-safe: This tag means that the next line of code contains a finding, but
   the non compliance to the checker is analysed and demonstrated to be safe.
 - SAF-X-false-positive-<tool>: This tag means that the next line of code
   contains a finding, but the finding is a bug of the tool.

SAF stands for Static Analyser Finding, the X is a placeholder for a positive
number that starts from zero, the number after SAF- shall be incremental and
unique, base ten notation and without leading zeros.

Entries in the database shall never be removed, even if they are not used
anymore in the code (if a patch is removing or modifying the faulty line).
This is to make sure that numbers are not reused which could lead to conflicts
with old branches or misleading justifications.

An entry can be reused in multiple places in the code to suppress a finding if
and only if the justification holds for the same non-compliance to the coding
standard.

An orphan entry, that is an entry who was justifying a finding in the code, but
later that code was removed and there is no other use of that entry in the code,
can be reused as long as the justification for the finding holds. This is done
to avoid the allocation of a new entry with exactly the same justification, that
would lead to waste of space and maintenance issues of the database.

The files where to store all the justifications are in xen/docs/misra/ and are
named as safe.json and false-positive-<tool>.json, they have JSON format, each
one has a different justification schema which shares some fields.

Here is an example to add a new justification in safe.json::

|{
|    "version": "1.0",
|    "content": [
|        {
|            "id": "SAF-0-safe",
|            "analyser": {
|                "cppcheck": "misra-c2012-20.7",
|                "coverity": "misra_c_2012_rule_20_7_violation",
|                "eclair": "MC3A2.R20.7"
|            },
|            "name": "R20.7 C macro parameters not used as expression",
|            "text": "The macro parameters used in this [...]"
|        },
|        {
|            "id": "SAF-1-safe",
|            "analyser": {},
|            "name": "Sentinel",
|            "text": "Next ID to be used"
|        }
|    ]
|}

To document a finding in safe.json, just add another block {[...]} before the
sentinel block, using the id contained in the sentinel block and increment by
one the number contained in the id of the sentinel block.

Here is an explanation of the fields inside an object of the "content" array:
 - id: it is a unique string that is used to refer to the finding, many finding
   can be tagged with the same id, if the justification holds for any applied
   case.
   It tells the tool to substitute a Xen in-code comment having this structure:
   /* SAF-0-safe [...] \*/
 - analyser: it is an object containing pair of key-value strings, the key is
   the analyser, so it can be cppcheck, coverity or eclair, the value is the
   proprietary id corresponding on the finding, for example when coverity is
   used as analyser, the tool will translate the Xen in-code coment in this way:
   /* SAF-0-safe [...] \*/ -> /* coverity[misra_c_2012_rule_20_7_violation] \*/
   if the object doesn't have a key-value, then the corresponding in-code
   comment won't be translated.
 - name: a simple name for the finding
 - text: a proper justification to turn off the finding.


Here is an example to add a new justification in false-positive-<tool>.json::

|{
|    "version": "1.0",
|    "content": [
|        {
|            "id": "SAF-0-false-positive-<tool>",
|            "violation-id": "<proprietary-id>",
|            "tool-version": "<version>",
|            "name": "R20.7 [...]",
|            "text": "[...]"
|        },
|        {
|            "id": "SAF-1-false-positive-<tool>",
|            "violation-id": "",
|            "tool-version": "",
|            "name": "Sentinel",
|            "text": "Next ID to be used"
|        }
|    ]
|}

To document a finding in false-positive-<tool>.json, just add another block
{[...]} before the sentinel block, using the id contained in the sentinel block
and increment by one the number contained in the id of the sentinel block.

Here is an explanation of the fields inside an object of the "content" array:
 - id: it has the same meaning as in the "safe" justification schema.
   It tells the tool to substitute a Xen in-code comment having this structure:
   /* SAF-0-false-positive-<tool> [...] \*/
 - violation-id: its value is a string containing the proprietary id
   corresponding to the finding, for example when <tool> is coverity, the Xen
   tool will translate the Xen in-code coment in this way:
   /* SAF-0-false-positive-coverity [...] \*/ -> /* coverity[misra_c_2012_rule_20_7_violation] \*/
   if the object doesn't have a value, then the corresponding in-code comment
   won't be translated.
 - tool-version: the version of the tool affected by the false positive, if it
   is discovered in more than one version, this string can be a range
   (eg. 2.7 - 3.0)
 - name, text: they have the same meaning as in the "safe" justification schema.


Justification example
---------------------

Here an example of the usage of the in-code comment tags to suppress a finding
for the Rule 8.6:

Eclair reports it in its web report, file xen/include/xen/kernel.h, line 68:

| MC3A2.R8.6 for program 'xen/xen-syms', variable '_start' has no definition

Also coverity reports it, here is an extract of the finding:

| xen/include/xen/kernel.h:68:
| 1. misra_c_2012_rule_8_6_violation: Function "_start" is declared but never
 defined.

The analysers are complaining because we have this in xen/include/xen/kernel.h
at line 68::

| extern char _start[], _end[], start[];

Those are symbols exported by the linker, hence we will need to have a proper
deviation for this finding.

We will prepare our entry in the safe.json database::

|{
|    "version": "1.0",
|    "content": [
|        {
|        [...]
|        },
|        {
|            "id": "SAF-1-safe",
|            "analyser": {
|                "eclair": "MC3A2.R8.6",
|                "coverity": "misra_c_2012_rule_8_6_violation"
|            },
|            "name": "Rule 8.6: linker script defined symbols",
|            "text": "It is safe to declare this symbol because it is defined in the linker script."
|        },
|        {
|            "id": "SAF-2-safe",
|            "analyser": {},
|            "name": "Sentinel",
|            "text": "Next ID to be used"
|        }
|    ]
|}

And we will use the proper tag above the violation line::

| /* SAF-1-safe R8.6 linker defined symbols */
| extern char _start[], _end[], start[];

This entry will fix also the violation on _end and start, because they are on
the same line and the same "violation ID".

Also, the same tag can be used on other symbols from the linker that are
declared in the codebase, because the justification holds for them too.

A possible violation found by Cppcheck can be handled in the same way, from the
cppcheck text report it is possible to identify the violation id:

| include/public/arch-arm.h(226,0):misra-c2012-20.7:style:Expressions resulting from the expansion of macro parameters shall be enclosed in parentheses (Misra rule 20.7)

The violation id can be located also in the HTML report, opening index.html from
the browser, the violations can be filtered by id in the left side panel, under
the column "Defect ID". On the right there will be a list of files with the type
of violation and the violation line number, for the same violation above, there
will be an entry like the following and the violation id will be in the column
"Id":

| include/public/arch-arm.h
| [...]
| 226 misra-c2012-20.7  style Expressions resulting from the expansion of macro parameters shall be enclosed in parentheses (Misra rule 20.7)
| [...]

Given the violation id "misra-c2012-20.7", the procedure above can be followed
to justify this finding.

Another way to justify the above violation is to put the in-code comment tag
at the end of the affected line::

| extern char _start[], _end[], start[]; /* SAF-1-safe [...] */

This way of deviating violations needs however to be used only when placing the
tag above the line can't be done. This option suffers from some limitation on
cppcheck and coverity tool that don't support natively the suppression comment
at the end of the line.
