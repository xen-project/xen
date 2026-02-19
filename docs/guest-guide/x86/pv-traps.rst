.. SPDX-License-Identifier: CC-BY-4.0

PV Traps and Entrypoints
========================

.. note::

   The details here are specific to 64bit builds of Xen.  Details for 32bit
   builds of Xen are different and not discussed further.

PV guests are subject to Xen's linkage setup for events (interrupts,
exceptions and system calls).  x86's IDT architecture and limitations are the
majority influence on the PV ABI.

All external interrupts are routed to PV guests via the :term:`Event Channel`
interface, and not discussed further here.

What remain are exceptions, and the instructions which cause control
transfers.  In the x86 architecture, the instructions relevant for PV guests
are:

 * ``INT3``, which generates ``#BP``.

 * ``INTO``, which generates ``#OF`` only if the overflow flag is set.  It is
   only usable in compatibility mode, and will ``#UD`` in 64bit mode.

 * ``CALL (far)`` referencing a gate in the GDT.

 * ``INT $N``, which invokes an arbitrary IDT gate.  These four instructions
   so far all check the gate DPL and will ``#GP`` otherwise.

 * ``INT1``, also known as ``ICEBP``, which generates ``#DB``.  This
   instruction does *not* check DPL, and can be used unconditionally by
   userspace.

 * ``SYSCALL``, which enters CPL0 as configured by the ``{C,L,}STAR`` MSRs.
   It is usable if enabled by ``MSR_EFER.SCE``, and will ``#UD`` otherwise.
   On Intel parts, ``SYSCALL`` is unusable outside of 64bit mode.

 * ``SYSENTER``, which enters CPL0 as configured by the ``SEP`` MSRs.  It is
   usable if enabled by ``MSR_SYSENTER_CS`` having a non-NUL selector, and
   will ``#GP`` otherwise.  On AMD parts, ``SYSENTER`` is unusable in Long
   mode.

The ``BOUND`` instruction is not included.  It is a hardware exception and
strictly a fault, with no trapping configuraton.


Xen's configuration
-------------------

Xen maintains a complete IDT, with most gates configured with DPL0.  This
causes most ``INT $N`` instructions to ``#GP``.  This allows Xen to emulate
the instruction, referring to the guest kernels vDPL choice.

 * Vectors 3 ``#BP`` and 4 ``#OF`` are DPL3, in order to allow the ``INT3``
   and ``INTO`` instructions to function in userspace.

 * Vector 0x80 is DPL3 because of it's common usage for syscall in UNIXes.
   This is a fastpath to avoid the emulation overhead.

 * Vector 0x82 is DPL1 when PV32 is enabled, allowing the guest kernel to make
   hypercalls to Xen.  All other cases (PV32 guest userspace, and both PV64
   modes) operate in CPL3 and this vector behaves like all others to ``INT
   $N`` instructions.

A range of the GDT is guest-owned, allowing for call gates.  During audit, Xen
forces all call gates to DPL0, causing their use to ``#GP`` allowing for
emulation.

Xen enables ``SYSCALL`` in all cases as it is mandatory in 64bit mode, and
enables ``SYSENTER`` when available in 64bit mode.

When Xen is using FRED delivery the hardware configuration is substantially
different, but the behaviour for guests remains as unchanged as possible.


PV Guest's configuration
------------------------

The PV ABI contains the "trap table", modelled closely on the IDT.  It is
manipulated by ``HYPERCALL_set_trap_table``, has 256 entries, each containing
a code segment selector, an address, and flags.  A guest is expected to
configure handlers for all exceptions; failure to do so is terminal and
similar to a Triple Fault.

Part of the GDT is guest owned with descriptors audited by Xen.  This range
can be manipulated with ``HYPERVISOR_set_gdt`` and
``HYPERVISOR_update_descriptor``.

Other entrypoints are configured via ``HYPERVISOR_callback_op``.  Of note here
are the callback types ``syscall``, ``syscall32`` (relevant for AMD parts) and
``sysenter`` (relevant for Intel parts).

.. warning::

   Prior to Xen 4.15, there was no check that the ``syscall`` or ``syscall32``
   callbacks had been registered before attempting to deliver via them.
   Guests are strongly advised to ensure the entrypoints are registered before
   running userspace.


Notes
-----

``INT3`` vs ``INT $3`` and ``INTO`` vs ``INT $4`` are hard to distinguish
architecturally as both forms have a DPL check and use the same IDT vectors.
Because Xen configures both as DPL3, the ``INT $`` forms do not fault for
emulation, and are treated as if they were exceptions.  This means the guest
can't block these instruction by trying to configure them with vDPL0.

The instructions which trap into Xen (``INT $0x80``, ``SYSCALL``,
``SYSENTER``) but can be disabled by guest configuration need turning back
into faults for the guest kernel to process.

 * When using IDT delivery, instruction lengths are not provided by hardware
   and Xen does not account for possible prefixes.  ``%rip`` only gets rewound
   by the length of the un-prefixed instruction.  This is observable, but not
   expected to be an issue in practice.

 * When Xen is using FRED delivery, the full instruction length is provided by
   hardware, and ``%rip`` is rewound fully.

While both PV32 and PV64 guests are permitted to write Call Gates into the
GDT, emulation is only wired up for PV32.  At the time of writing, the x86
maintainers feel no specific need to fix this omission.
