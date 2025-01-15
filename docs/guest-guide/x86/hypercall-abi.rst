.. SPDX-License-Identifier: CC-BY-4.0

Hypercall ABI
=============

Hypercalls are system calls to Xen.  Two modes of guest operation are
supported, and up to 5 individual parameters are supported.

Hypercalls may only be issued by kernel-level software [#kern]_.

Registers
---------

The registers used for hypercalls depends on the operating mode of the guest.

.. list-table::
   :header-rows: 1

   * - ABI
     - Hypercall Index
     - Parameters (1 - 5) [#params]_
     - Result

   * - 64bit
     - RAX
     - RDI RSI RDX R10 R8
     - RAX

   * - 32bit
     - EAX
     - EBX ECX EDX ESI EDI
     - EAX

32 and 64bit PV guests have an ABI fixed by their guest type.  The ABI for an
HVM guest depends on whether the vCPU is operating in a 64bit segment or not
[#mode]_.


Parameters
----------

Different hypercalls take a different number of parameters.  Each hypercall
potentially clobbers each of its parameter registers; a guest may not rely on
the parameter registers staying the same.  A debug build of Xen checks this by
deliberately poisoning the parameter registers before returning back to the
guest.


Mode transfer
-------------

The exact sequence of instructions required to issue a hypercall differs
between virtualisation mode and hardware vendor.

.. list-table::
   :header-rows: 1

   * - Guest
     - Transfer instruction

   * - 32bit PV
     - INT 0x82

   * - 64bit PV
     - SYSCALL

   * - Intel HVM
     - VMCALL

   * - AMD HVM
     - VMMCALL

To abstract away the details, Xen implements an interface known as the
Hypercall Page.  This allows a guest to make a hypercall without needing to
perform mode-specific or vendor-specific setup.


Hypercall Page
==============

The hypercall page is a page of guest RAM into which Xen will write suitable
transfer stubs.  It is intended as a convenience for guests, but use of the
hypercall page is not mandatory for making hypercalls to Xen.

.. note::

   There are cases where a hypercall page should not be used.  It contains
   ``ret`` instructions which are not compatible with certain speculative
   security techniques, and it does not contain ``endbr`` instructions which
   are necessary for certain Control-flow Integrity schemes.

Creating a hypercall page is an isolated operation from Xen's point of view.
It is the guests responsibility to ensure that the hypercall page, once
written by Xen, is mapped with executable permissions so it may be used.
Multiple hypercall pages may be created by the guest, if it wishes.

The stubs are arranged by hypercall index, and start on 32-byte boundaries.
To invoke a specific hypercall, ``call`` the relevant stub [#iret]_:

.. code-block:: none

   call hypercall_page + index * 32

There result is an ABI which is invariant of the exact operating mode or
hardware vendor.  This is intended to simplify guest kernel interfaces by
abstracting away the details of how it is currently running.


Creating Hypercall Pages
------------------------

Guests which are started using the PV boot protocol may set
``XEN_ELFNOTE_HYPERCALL_PAGE`` to have the nominated page written as a
hypercall page during construction.  This mechanism is common for PV guests,
and allows hypercalls to be issued with no additional setup.

Any guest can locate the Xen CPUID leaves and read the *hypercall transfer
page* information, which specifies an MSR that can be used to create
additional hypercall pages.  When a guest physical address is written to the
MSR, Xen writes a hypercall page into the nominated guest page.  This
mechanism is common for HVM guests which are typically started via legacy
means.


.. rubric:: Footnotes

.. [#kern] For HVM guests, ``HVMOP_guest_request_vm_event`` may be configured
   to be usable from userspace, but this behaviour is not default.

.. [#params] Xen's ABI used to declare support for 6 hypercall arguments,
   using ``r9`` and ``ebp``.  However, such an ABI clobbers the frame pointer
   in the 32bit code and does not interact nicely with guest-side debugging.
   ``V4V``, the predecessor to ``HYPERCALL_argo_op`` was a 6-argument
   hypercall, but the ABI was intentionally altered when Argo was upstreamed
   (Xen 4.13) to be the 5-argument hypercall it now is.

.. [#mode] While it is possible to use compatibility mode segments in a 64bit
   kernel, hypercalls issues from such a mode will be interpreted with the
   32bit ABI.  Such a setup is not expected in production scenarios.

.. [#iret] ``HYPERCALL_iret`` is special.  It is only implemented for PV
   guests and takes all its parameters on the stack.  This stub should be
   ``jmp``'d to, rather than ``call``'d.  HVM guests have this stub
   implemented as ``ud2a`` to prevent accidental use.
