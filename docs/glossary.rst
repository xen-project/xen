.. SPDX-License-Identifier: CC-BY-4.0

Glossary
========

.. Terms should appear in alphabetical order

.. glossary::

   control domain
     A :term:`domain`, commonly dom0, with the permission and responsibility
     to create and manage other domains on the system.

   domain
     A domain is Xen's unit of resource ownership, and generally has at the
     minimum some RAM and virtual CPUs.

     The terms :term:`domain` and :term:`guest` are commonly used
     interchangeably, but they mean subtly different things.

     A guest is a single, end user, virtual machine.

     In some cases, e.g. during live migration, one guest will be comprised of
     two domains for a period of time, while it is in transit.

   domid
     The numeric identifier of a running :term:`domain`.  It is unique to a
     single instance of Xen, used as the identifier in various APIs, and is
     typically allocated sequentially from 0.

   guest
     The term 'guest' has two different meanings, depending on context, and
     should not be confused with :term:`domain`.

     When discussing a Xen system as a whole, a 'guest' refer to a virtual
     machine which is the "useful output" of running the system in the first
     place (e.g. an end-user VM).  Virtual machines providing system services,
     (e.g. the control and/or hardware domains), are not considered guests in
     this context.

     In the code, "guest context" and "guest state" is considered in terms of
     the CPU architecture, and contrasted against hypervisor context/state.
     In this case, it refers to all code running lower privilege privilege
     level the hypervisor.  As such, it covers all domains, including ones
     providing system services.

   hardware domain
     A :term:`domain`, commonly dom0, which shares responsibility with Xen
     about the system as a whole.

     By default it gets all devices, including all disks and network cards, so
     is responsible for multiplexing guest I/O.
