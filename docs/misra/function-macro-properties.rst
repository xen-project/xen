.. SPDX-License-Identifier: CC-BY-4.0

Properties list for Xen
=======================

Some functions and macros are found to have properties relevant to
the Xen codebase. For this reason, the file docs/properties.json
contains all the needed properties.

Here is an example of the properties.json file::

  {
     "version": "1.0",
     "content": [
        {
           "description": ""
           "type": "function",       // required
           "value:": "^printk*.$",   // required
           "properties":{
              "pointee_write": "1..2=never",
              "pointee_read": "",
              "taken": ""
              "attribute": ""
           }
        }
     ]
  }

Here is an explanation of the fields inside an object of the "content" array:

 - description: a brief description of why the properties apply
 - type: this is the kind of the element called: it may be either ``macro`` or ``function``
 - value: must be a regex, starting with ^ and ending with $ and matching function fully
   qualified name or macro name.
 - properties: a list of properties applied to said function.
   Possible values are:

    - pointee_write: indicate the write use for call arguments that correspond to
      parameters whose pointee types are non-const
    - pointee_read: indicate the read use for call arguments that correspond to
      parameters whose pointee types are non-const
    - taken: indicates that the specified address arguments may be stored in objects
      that persist after the function has ceased to exist (excluding the returned value);
      address arguments not listed are never taken
    - attribute: attributes a function may have. Possible values are pure, const and noeffect.

   pointee_read and pointee_write use a specific kind of argument, structured as pointee_arg=rw:

    - pointee_arg: argument index for callee. Index 0 refers to the return value,
      the indices of the arguments start from 1. It can be either a single value or a range.
    - rw: a value that's either always, maybe or never

       - always: for pointee_read: argument pointee is expected to be fully read in the function body,
         for pointee_write: argument pointee is fully initialized at function exit
       - maybe: for pointee_read: argument pointee may be expected to be read in the function body,
         for pointee_write: argument pointee may be written by function body
       - never: for pointee_read: argument pointee is not expected to be read in the function body,
         for pointee_write: argument pointee is never written by function body
